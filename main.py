"""Almoxarifado Central: FastAPI + SQLite. Run: python -m uvicorn main:app --reload"""
import csv
import hashlib
import hmac
import os
import io
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager, closing

from fastapi import FastAPI, Request, HTTPException, Depends, Body, Query
from fastapi.responses import FileResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
import db as dbmodule
from db import connect, transaction, initialize, hash_password, verify_password, ALL_PERMISSIONS

ROOT = Path(__file__).resolve().parent
SAFE = {'GET', 'HEAD', 'OPTIONS'}
ORDER_STATUSES = ('RASCUNHO','AGUARDANDO_APROVACAO','AGUARDANDO_MATERIAIS','AGUARDANDO_SEPARACAO','PRONTA','EM_MONTAGEM','PAUSADA','CONCLUIDA','CANCELADA')
PO_STATUSES = ('RASCUNHO','AGUARDANDO_APROVACAO','APROVADO','ENVIADO','PARCIAL','RECEBIDO','CANCELADO')

@asynccontextmanager
async def lifespan(app):
    initialize()
    yield

app = FastAPI(
    title='Almoxarifado Central', version='1.1.0-online', lifespan=lifespan,
    docs_url=None if os.environ.get('ALMOX_REQUIRE_VOLUME') == '1' else '/docs',
    redoc_url=None if os.environ.get('ALMOX_REQUIRE_VOLUME') == '1' else '/redoc',
    openapi_url=None if os.environ.get('ALMOX_REQUIRE_VOLUME') == '1' else '/openapi.json'
)

@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'same-origin'
    if request.url.scheme == 'https' or os.environ.get('ALMOX_REQUIRE_VOLUME') == '1':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response

app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')

@app.get('/', include_in_schema=False)
def index():
    return FileResponse(ROOT / 'static' / 'index.html')

@app.exception_handler(sqlite3.IntegrityError)
async def constraint_error(req, exc):
    return Response(json.dumps({'detail':'Registro duplicado, inválido ou vinculado a outro cadastro. Verifique os campos.'}), status_code=409, media_type='application/json')


def require(ok, message, status=400):
    if not ok:
        raise HTTPException(status, message)


def field(data, key, default=None):
    return data.get(key, default)


def valstr(data, key, *, required=False, maxlen=250, default=''):
    value = str(data.get(key, default) if data.get(key, default) is not None else '').strip()
    require(len(value) <= maxlen, f'{key}: texto longo demais')
    if required:
        require(bool(value), f'Preencha o campo {key}')
    return value


def qty(value, *, allow_zero=False):
    try:
        v = Decimal(str(value)) * 1000
        require(v == v.to_integral_value() and v.is_finite(), 'Quantidade: use até 3 casas decimais')
        n = int(v)
        require(n >= 0 if allow_zero else n > 0, 'Quantidade deve ser positiva' if not allow_zero else 'Quantidade não pode ser negativa')
        require(n <= 10**15, 'Quantidade acima do limite')
        return n
    except (InvalidOperation,TypeError,ValueError,OverflowError):
        raise HTTPException(400, 'Quantidade inválida')


def money(value):
    try:
        d = Decimal(str(value)) * 100
        require(d == d.to_integral_value() and d.is_finite(), 'Valor monetário deve ter no máximo duas casas decimais')
        n = int(d)
        require(0 <= n <= 10**15, 'Valor monetário inválido')
        return n
    except (InvalidOperation,TypeError,ValueError,OverflowError):
        raise HTTPException(400, 'Valor monetário inválido')


def number(v, name):
    try:
        n = int(v)
        require(n > 0, f'{name} inválido')
        return n
    except (TypeError, ValueError):
        raise HTTPException(400, f'{name} inválido')


def stable_csrf(token):
    key_path=dbmodule.DB_PATH.parent/'.csrf_key'
    key_path.parent.mkdir(parents=True,exist_ok=True)
    if not key_path.exists():
        try:
            fd=os.open(key_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'wb') as stream: stream.write(secrets.token_bytes(32))
        except FileExistsError: pass
    return hmac.new(key_path.read_bytes(),token.encode(),hashlib.sha256).hexdigest()


def record(c, sql, args=(), error='Registro não encontrado'):
    result = c.execute(sql, args).fetchone()
    require(result is not None, error, 404)
    return dict(result)


def jsonrows(c, sql, args=()):
    return [dict(r) for r in c.execute(sql,args).fetchall()]


def audit(c, actor, entity, entity_id, action, details=None):
    c.execute('INSERT INTO audit_events(actor_id,entity,entity_id,action,details) VALUES(?,?,?,?,?)',
              (actor,entity,entity_id,action,json.dumps(details or {},ensure_ascii=False,default=str)))


def user_from_request(req):
    token = req.cookies.get('almox_session')
    require(token, 'Faça login para continuar', 401)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with closing(connect()) as c:
        row = c.execute("""SELECT u.id,u.name,u.email,u.active,r.id AS role_id,r.name AS role,s.csrf_hash,s.expires_at
              FROM sessions s JOIN users u ON u.id=s.user_id JOIN roles r ON r.id=u.role_id
              WHERE s.token_hash=? AND s.expires_at > ? AND r.active=1""", (token_hash,datetime.now(timezone.utc).isoformat())).fetchone()
        require(row and row['active'], 'Sessão expirada. Entre novamente.', 401)
        user = dict(row)
        user['permissions'] = [p['permission'] for p in c.execute('SELECT permission FROM role_permissions WHERE role_id=?',(user['role_id'],))]
        if req.method not in SAFE:
            csrf = req.headers.get('x-csrf-token','')
            require(bool(csrf) and secrets.compare_digest(hashlib.sha256(csrf.encode()).hexdigest(),user['csrf_hash']), 'Token de segurança inválido', 403)
        return user


def permit(permission):
    def dependency(req: Request):
        user = user_from_request(req)
        if permission:
            require(permission in user['permissions'], 'Seu perfil não tem permissão para esta operação', 403)
        return user
    return dependency

AUTH = Depends(permit(None))

def paging(page, size):
    require(1 <= page <= 100000 and 1 <= size <= 150, 'Paginação inválida')
    return size, (page-1)*size


def movement(c, comp_id, kind, actor, amount, *, dp=0, dr=0, db=0, reason='', order_id=None, purchase_id=None, receipt_id=None, inventory_id=None, cost=None, reversal_of=None):
    require(amount>0, 'Quantidade de movimentação inválida')
    b = record(c,'SELECT * FROM stock_balances WHERE component_id=?',(comp_id,), 'Saldo do componente inexistente')
    np, nr, nb = b['physical']+dp, b['reserved']+dr, b['blocked']+db
    require(np>=0 and nr>=0 and nb>=0 and np>=nr+nb, 'Estoque insuficiente ou incompatível com reservas/bloqueios',409)
    c.execute('UPDATE stock_balances SET physical=?,reserved=?,blocked=? WHERE component_id=?',(np,nr,nb,comp_id))
    unit_cost = cost if cost is not None else record(c,'SELECT cost_cents FROM components WHERE id=?',(comp_id,))['cost_cents']
    result = c.execute("""INSERT INTO movements(component_id,kind,quantity,physical_delta,reserved_delta,blocked_delta,
       before_physical,after_physical,before_reserved,after_reserved,before_blocked,after_blocked,
       unit_cost_cents,reason,order_id,purchase_id,receipt_id,inventory_id,reversal_of,actor_id)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
       (comp_id,kind,amount,dp,dr,db,b['physical'],np,b['reserved'],nr,b['blocked'],nb,
        unit_cost,reason,order_id,purchase_id,receipt_id,inventory_id,reversal_of,actor))
    audit(c,actor,'movements',result.lastrowid,kind,{'component_id':comp_id,'amount_milli':amount,'dp':dp,'dr':dr,'db':db,'reason':reason})
    return result.lastrowid


def idem_existing(c, user, operation, key):
    if not key:
        return None
    require(5 <= len(key) <= 120, 'Chave de idempotência inválida')
    row = c.execute('SELECT result_json FROM idempotency WHERE actor_id=? AND operation=? AND idem_key=?',(user,operation,key)).fetchone()
    return json.loads(row['result_json']) if row else None


def idem_save(c, user, operation, key, result):
    if key:
        c.execute('INSERT INTO idempotency(actor_id,operation,idem_key,result_json) VALUES(?,?,?,?)',(user,operation,key,json.dumps(result)))

@app.post('/api/auth/login')
def login(req: Request, data: dict = Body(...)):
    email = valstr(data,'email',required=True,maxlen=254)
    password = str(data.get('password',''))
    require(password, 'Informe a senha')
    # Prevent repeated credential guessing without leaking whether an account exists.
    identity=hashlib.sha256((email.lower()+'|'+(req.client.host if req.client else 'unknown')).encode()).hexdigest()
    with transaction() as c:
        throttle=c.execute('SELECT * FROM login_attempts WHERE identity=?',(identity,)).fetchone()
        if throttle and throttle['blocked_until'] and throttle['blocked_until']>datetime.now(timezone.utc).isoformat():
            raise HTTPException(429,'Muitas tentativas. Tente novamente em 15 minutos.')
        row = c.execute('SELECT * FROM users WHERE email=? COLLATE NOCASE',(email,)).fetchone()
        # Equalize approximate computational effort for nonexistent accounts.
        if row:
            valid = verify_password(password,row['password_hash']) and row['active'] == 1
        else:
            valid = verify_password(password,hash_password('inexistente')) and False
        if not valid:
            count=(throttle['failures'] if throttle else 0)+1
            blocked=(datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat() if count>=5 else None
            c.execute('INSERT INTO login_attempts(identity,failures,blocked_until) VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET failures=excluded.failures,blocked_until=excluded.blocked_until,updated_at=CURRENT_TIMESTAMP',(identity,count,blocked))
            # Commit attempt counters before raising the public error.
            c.commit()
            raise HTTPException(401,'Credenciais inválidas ou conta desativada')
        c.execute('DELETE FROM login_attempts WHERE identity=?',(identity,))
        token = secrets.token_urlsafe(32)
        csrf = stable_csrf(token)
        expires = (datetime.now(timezone.utc)+timedelta(hours=10)).isoformat()
        c.execute('INSERT INTO sessions(token_hash,user_id,csrf_hash,expires_at) VALUES(?,?,?,?)',
                  (hashlib.sha256(token.encode()).hexdigest(),row['id'],hashlib.sha256(csrf.encode()).hexdigest(),expires))
        audit(c,row['id'],'auth',row['id'],'login')
    response = Response(json.dumps({'ok':True,'csrf':csrf}),media_type='application/json')
    response.set_cookie('almox_session',token,httponly=True,samesite='strict',secure=req.url.scheme=='https' or os.environ.get('ALMOX_REQUIRE_VOLUME')=='1',max_age=10*3600,path='/')
    return response

@app.post('/api/auth/logout')
def logout(req: Request, user=AUTH):
    token_hash = hashlib.sha256(req.cookies.get('almox_session','').encode()).hexdigest()
    with transaction() as c:
        c.execute('DELETE FROM sessions WHERE token_hash=?',(token_hash,))
        audit(c,user['id'],'auth',user['id'],'logout')
    res = Response(json.dumps({'ok':True}),media_type='application/json')
    res.delete_cookie('almox_session',path='/')
    return res

@app.get('/api/auth/me')
def me(req: Request, user=AUTH):
    # CSRF token is stored only as a hash: the client keeps the token returned at login.
    return {'id':user['id'],'name':user['name'],'email':user['email'],'role':user['role'], 'permissions':user['permissions']}

@app.get('/api/meta')
def meta(user=AUTH):
    with closing(connect()) as c:
        return {'categories':jsonrows(c,'SELECT * FROM categories ORDER BY name'),
                'locations':jsonrows(c,'SELECT * FROM locations ORDER BY code'),
                'suppliers':jsonrows(c,'SELECT * FROM suppliers ORDER BY name'),
                'roles':jsonrows(c,'SELECT id,name FROM roles WHERE active=1 ORDER BY name'),
                'permissions':ALL_PERMISSIONS}

@app.get('/api/users')
def users(user=Depends(permit('users.manage'))):
    with closing(connect()) as c:
        return jsonrows(c,'SELECT u.id,u.name,u.email,u.active,r.name AS role,r.id AS role_id,u.created_at FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.name')

@app.post('/api/users')
def create_user(data:dict=Body(...), user=Depends(permit('users.manage'))):
    password=valstr(data,'password',required=True,maxlen=500)
    require(len(password)>=10, 'A senha precisa de pelo menos 10 caracteres')
    with transaction() as c:
        rid=number(data.get('role_id'),'Perfil')
        record(c,'SELECT id FROM roles WHERE id=? AND active=1',(rid,))
        r=c.execute('INSERT INTO users(name,email,password_hash,role_id) VALUES(?,?,?,?)',(
            valstr(data,'name',required=True),valstr(data,'email',required=True,maxlen=254),hash_password(password),rid))
        audit(c,user['id'],'users',r.lastrowid,'create')
        return {'id':r.lastrowid}

@app.patch('/api/users/{uid}')
def update_user(uid:int,data:dict=Body(...),user=Depends(permit('users.manage'))):
    with transaction() as c:
        u=record(c,'SELECT * FROM users WHERE id=?',(uid,))
        active=int(bool(data.get('active',u['active'])))
        require(not(uid==user['id'] and not active),'Você não pode desativar sua própria conta')
        rid=number(data.get('role_id',u['role_id']),'Perfil')
        record(c,'SELECT id FROM roles WHERE id=? AND active=1',(rid,))
        if uid==user['id']:
            require(rid==u['role_id'],'Você não pode alterar seu próprio perfil')
        pw=data.get('password')
        if pw:
            require(len(str(pw))>=10,'A senha precisa de pelo menos 10 caracteres')
            pw_hash=hash_password(str(pw))
        else: pw_hash=u['password_hash']
        c.execute('UPDATE users SET name=?,email=?,role_id=?,active=?,password_hash=? WHERE id=?',(
            valstr(data,'name',required=True,default=u['name']),valstr(data,'email',required=True,default=u['email'],maxlen=254),rid,active,pw_hash,uid))
        if pw or not active or rid!=u['role_id']:
            c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
        audit(c,user['id'],'users',uid,'update',{'active':active,'role_id':rid,'password_changed':bool(pw)})
    return {'ok':True}

@app.get('/api/roles')
def roles(user=Depends(permit('roles.manage'))):
    with closing(connect()) as c:
        result=jsonrows(c,'SELECT * FROM roles ORDER BY id')
        for row in result:
            row['permissions']=[x['permission'] for x in c.execute('SELECT permission FROM role_permissions WHERE role_id=?',(row['id'],))]
        return result

@app.put('/api/roles/{rid}/permissions')
def set_permissions(rid:int,data:dict=Body(...),user=Depends(permit('roles.manage'))):
    perms=data.get('permissions',[])
    require(isinstance(perms,list) and all(p in ALL_PERMISSIONS for p in perms), 'Permissões inválidas')
    with transaction() as c:
        role=record(c,'SELECT * FROM roles WHERE id=?',(rid,))
        require(role['name']!='Administrador','Permissões do Administrador não podem ser reduzidas')
        c.execute('DELETE FROM role_permissions WHERE role_id=?',(rid,))
        c.executemany('INSERT INTO role_permissions(role_id,permission) VALUES(?,?)',[(rid,p) for p in set(perms)])
        audit(c,user['id'],'roles',rid,'update_permissions',{'permissions':perms})
    return {'ok':True}

REF_TABLES = {
 'categories':(['name'],['name','active']),
 'locations':(['code'],['code','sector','corridor','rack','shelf','drawer','active']),
 'suppliers':(['name'],['name','cnpj','contact','phone','email','address','commercial_terms','lead_days','notes','active'])
}

@app.get('/api/reference/{table}')
def reference_list(table:str,q:str='',page:int=1,size:int=100,user=Depends(permit('components.read'))):
    require(table in REF_TABLES,'Tipo de cadastro inválido',404)
    size,offset=paging(page,size)
    lookup='name' if table!='locations' else 'code'
    with closing(connect()) as c:
        return {'items':jsonrows(c,f'SELECT * FROM {table} WHERE {lookup} LIKE ? ORDER BY {lookup} LIMIT ? OFFSET ?',('%'+q+'%',size,offset)),
                'total':c.execute(f'SELECT COUNT(*) FROM {table} WHERE {lookup} LIKE ?',('%'+q+'%',)).fetchone()[0]}

@app.post('/api/reference/{table}')
def reference_create(table:str,data:dict=Body(...),user=AUTH):
    require(table in REF_TABLES,'Tipo de cadastro inválido',404)
    if table=='suppliers':
        require('purchases.write' in user['permissions'] or 'users.manage' in user['permissions'],'Sem permissão para cadastrar fornecedores',403)
    else:
        require('components.write' in user['permissions'],'Sem permissão para alterar esse cadastro',403)
    required, allowed=REF_TABLES[table]
    clean={k:(int(bool(data.get(k,1))) if k=='active' else number(data.get(k,0),'Prazo') if k=='lead_days' and data.get(k) not in (None,'',0,'0') else 0 if k=='lead_days' else valstr(data,k,required=k in required,maxlen=1500 if k in ('notes','address','commercial_terms') else 250)) for k in allowed if k in data or k in required}
    if table=='suppliers' and clean.get('cnpj')=='': clean['cnpj']=None
    with transaction() as c:
        fields=','.join(clean)
        marks=','.join('?' for _ in clean)
        r=c.execute(f'INSERT INTO {table}({fields}) VALUES({marks})',tuple(clean.values()))
        audit(c,user['id'],table,r.lastrowid,'create')
        return {'id':r.lastrowid}

@app.patch('/api/reference/{table}/{rid}')
def reference_update(table:str,rid:int,data:dict=Body(...),user=AUTH):
    require(table in REF_TABLES,'Tipo de cadastro inválido',404)
    if table=='suppliers':
        require('purchases.write' in user['permissions'] or 'users.manage' in user['permissions'],'Sem permissão para alterar fornecedores',403)
    else:
        require('components.write' in user['permissions'],'Sem permissão para alterar esse cadastro',403)
    allowed=REF_TABLES[table][1]
    with transaction() as c:
        orig=record(c,f'SELECT * FROM {table} WHERE id=?',(rid,))
        clean={}
        for k in allowed:
            if k not in data: continue
            if k=='active': clean[k]=int(bool(data[k]))
            elif k=='lead_days':
                try: clean[k]=int(data[k]); require(clean[k]>=0,'Prazo inválido')
                except (TypeError,ValueError): raise HTTPException(400,'Prazo inválido')
            else: clean[k]=valstr(data,k,required=k in REF_TABLES[table][0],maxlen=1500 if k in ('notes','address','commercial_terms') else 250)
        if 'cnpj' in clean and clean['cnpj']=='': clean['cnpj']=None
        if clean:
            c.execute(f'UPDATE {table} SET '+','.join(f'{k}=?' for k in clean)+' WHERE id=?',(*clean.values(),rid))
            audit(c,user['id'],table,rid,'update',clean)
    return {'ok':True}

COMPONENT_SQL="""SELECT c.*,g.name AS category,l.code AS location,b.physical,b.reserved,b.blocked,
(b.physical-b.reserved-b.blocked) AS available,
CASE WHEN b.physical-b.reserved-b.blocked <= c.stock_min THEN 1 ELSE 0 END AS low_stock
FROM components c LEFT JOIN categories g ON g.id=c.category_id
LEFT JOIN locations l ON l.id=c.location_id JOIN stock_balances b ON b.component_id=c.id"""

@app.get('/api/components')
def components(q:str='',category_id:Optional[int]=None,location_id:Optional[int]=None,active:Optional[int]=None,low:bool=False,page:int=1,size:int=30,user=Depends(permit('components.read'))):
    limit,offset=paging(page,size)
    where=['(c.name LIKE ? OR c.sku LIKE ?)']; args=['%'+q+'%','%'+q+'%']
    for k,v in [('category_id',category_id),('location_id',location_id),('active',active)]:
        if v is not None:
            where.append('c.'+k+'=?'); args.append(v)
    if low: where.append('(b.physical-b.reserved-b.blocked)<=c.stock_min')
    sql=' WHERE '+' AND '.join(where)
    with closing(connect()) as c:
        total=c.execute('SELECT COUNT(*) FROM components c JOIN stock_balances b ON b.component_id=c.id'+sql,args).fetchone()[0]
        items=jsonrows(c,COMPONENT_SQL+sql+' ORDER BY c.name LIMIT ? OFFSET ?',(*args,limit,offset))
        return {'items':items,'total':total,'page':page,'size':size}

@app.get('/api/components/{cid}')
def component_detail(cid:int,user=Depends(permit('components.read'))):
    with closing(connect()) as c:
        item=record(c,COMPONENT_SQL+' WHERE c.id=?',(cid,))
        item['suppliers']=jsonrows(c,'SELECT s.id,s.name FROM supplier_components sc JOIN suppliers s ON s.id=sc.supplier_id WHERE sc.component_id=?',(cid,))
        item['movements']=jsonrows(c,'SELECT m.*,u.name AS actor FROM movements m JOIN users u ON u.id=m.actor_id WHERE m.component_id=? ORDER BY m.id DESC LIMIT 50',(cid,))
        return item

@app.post('/api/components')
def component_create(data:dict=Body(...),user=Depends(permit('components.write'))):
    with transaction() as c:
        category_id=data.get('category_id') or None; location_id=data.get('location_id') or None
        if category_id: require(record(c,'SELECT active FROM categories WHERE id=?',(category_id,))['active'],'Categoria inativa')
        if location_id: require(record(c,'SELECT active FROM locations WHERE id=?',(location_id,))['active'],'Localização inativa')
        r=c.execute('''INSERT INTO components(sku,name,description,category_id,location_id,manufacturer,model,unit,stock_min,reorder_target,cost_cents)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(
            valstr(data,'sku',required=True,maxlen=70),valstr(data,'name',required=True),valstr(data,'description',maxlen=1500),category_id,location_id,
            valstr(data,'manufacturer'),valstr(data,'model'),valstr(data,'unit',default='UN',required=True,maxlen=15),
            qty(data.get('stock_min',0),allow_zero=True),qty(data.get('reorder_target',0),allow_zero=True),money(data.get('cost',0))))
        cid=r.lastrowid
        c.execute('INSERT INTO stock_balances(component_id) VALUES(?)',(cid,))
        for supplier_id in set(data.get('supplier_ids') or []):
            c.execute('INSERT INTO supplier_components(supplier_id,component_id) VALUES(?,?)',(supplier_id,cid))
        audit(c,user['id'],'components',cid,'create',{'sku':data.get('sku')})
        return {'id':cid}

@app.patch('/api/components/{cid}')
def component_update(cid:int,data:dict=Body(...),user=Depends(permit('components.write'))):
    fields={'sku','name','description','category_id','location_id','manufacturer','model','unit','stock_min','reorder_target','cost','active'}
    with transaction() as c:
        record(c,'SELECT id FROM components WHERE id=?',(cid,))
        update={}
        for k,v in data.items():
            if k not in fields: continue
            if k in ('stock_min','reorder_target'): update[k]=qty(v,allow_zero=True)
            elif k=='cost': update['cost_cents']=money(v)
            elif k=='active': update[k]=int(bool(v))
            elif k in ('category_id','location_id'):
                update[k]=v or None
                if update[k]:
                    table='categories' if k=='category_id' else 'locations'
                    require(record(c,f'SELECT active FROM {table} WHERE id=?',(v,))['active'],f'{table}: registro inativo')
            else: update[k]=valstr(data,k,required=k in ('sku','name','unit'),maxlen=1500 if k=='description' else 250)
        if update:
            c.execute('UPDATE components SET '+','.join(k+'=?' for k in update)+',updated_at=CURRENT_TIMESTAMP WHERE id=?',(*update.values(),cid))
        if 'supplier_ids' in data:
            c.execute('DELETE FROM supplier_components WHERE component_id=?',(cid,))
            for sid in set(data['supplier_ids']):
                c.execute('INSERT INTO supplier_components(supplier_id,component_id) VALUES(?,?)',(sid,cid))
        audit(c,user['id'],'components',cid,'update',update)
        return {'ok':True}

@app.get('/api/movements')
def movements(component_id:Optional[int]=None,kind:str='',start:str='',end:str='',page:int=1,size:int=50,user=Depends(permit('stock.read'))):
    limit,offset=paging(page,size)
    cond=['1=1']; args=[]
    if component_id: cond.append('m.component_id=?'); args.append(component_id)
    if kind: cond.append('m.kind=?'); args.append(kind)
    if start: cond.append('date(m.created_at)>=date(?)'); args.append(start)
    if end: cond.append('date(m.created_at)<=date(?)'); args.append(end)
    where=' WHERE '+' AND '.join(cond)
    join=' FROM movements m JOIN components c ON c.id=m.component_id JOIN users u ON u.id=m.actor_id'
    with closing(connect()) as c:
        return {'items':jsonrows(c,'SELECT m.*,c.sku,c.name AS component,u.name AS actor'+join+where+' ORDER BY m.id DESC LIMIT ? OFFSET ?',(*args,limit,offset)),
                'total':c.execute('SELECT count(*)'+join+where,args).fetchone()[0]}

@app.post('/api/movements/manual')
def manual_movement(req:Request,data:dict=Body(...),user=Depends(permit('stock.move'))):
    kind=valstr(data,'kind',required=True).upper()
    require(kind in ('ENTRADA_AVULSA','PERDA','BLOQUEIO','DESBLOQUEIO'),'Movimentação manual não permitida')
    reason=valstr(data,'reason',required=True,maxlen=1000)
    amount=qty(data.get('quantity'))
    cid=number(data.get('component_id'),'Componente')
    key=req.headers.get('idempotency-key')
    with transaction() as c:
        existing=idem_existing(c,user['id'],'manual',key)
        if existing is not None: return existing
        record(c,'SELECT id FROM components WHERE id=? AND active=1',(cid,))
        b=record(c,'SELECT * FROM stock_balances WHERE component_id=?',(cid,))
        if kind=='ENTRADA_AVULSA':
            require('orders.approve' in user['permissions'] or 'users.manage' in user['permissions'], 'Entrada avulsa exige aprovação gerencial',403)
            dp,db=amount,0
        elif kind=='PERDA': dp,db=-amount,0
        elif kind=='BLOQUEIO': dp,db=0,amount
        else: dp,db=0,-amount
        if kind=='PERDA' and data.get('from_blocked'):
            dp,db=-amount,-amount
        oid=int(data['order_id']) if data.get('order_id') else None
        if oid: record(c,'SELECT id FROM assembly_orders WHERE id=?',(oid,))
        mid=movement(c,cid,kind,user['id'],amount,dp=dp,db=db,reason=reason,order_id=oid)
        result={'id':mid}; idem_save(c,user['id'],'manual',key,result)
        return result

@app.get('/api/auth/csrf')
def rotate_csrf(req:Request,user=AUTH):
    # Stable per-session CSRF token allows multiple browser tabs and reloads.
    return {'csrf': stable_csrf(req.cookies['almox_session'])}

ORDER_SQL="""SELECT o.*,u.name AS created_by_name,
 (SELECT COUNT(*) FROM assembly_items i WHERE i.order_id=o.id) AS item_count,
 (SELECT COALESCE(SUM(r.quantity),0) FROM reservations r WHERE r.order_id=o.id) AS reserved_total
 FROM assembly_orders o JOIN users u ON u.id=o.created_by"""

def order_detail(c,oid):
    order=record(c,ORDER_SQL+' WHERE o.id=?',(oid,))
    order['items']=jsonrows(c,"""SELECT ai.id,ai.component_id,c.sku,c.name,c.unit,ai.planned,
         COALESCE(r.quantity,0) AS reserved,b.physical,b.blocked,b.reserved AS global_reserved,
         (b.physical-b.reserved-b.blocked) AS available,
         COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=ai.order_id AND m.component_id=ai.component_id AND m.kind='CONSUMO'),0) AS consumed,
         COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=ai.order_id AND m.component_id=ai.component_id AND m.kind='DEVOLUCAO_TRIAGEM'),0) AS returned,
         COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=ai.order_id AND m.component_id=ai.component_id AND m.kind='DEVOLUCAO_AVARIADA'),0) AS damaged_return,
         COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=ai.order_id AND m.component_id=ai.component_id AND m.kind='PERDA'),0) AS lost,
         COALESCE((SELECT SUM(pi.quantity-pi.received) FROM purchase_items pi JOIN purchase_orders po ON po.id=pi.purchase_id WHERE pi.component_id=ai.component_id AND po.status IN ('APROVADO','ENVIADO','PARCIAL')),0) AS inbound
         FROM assembly_items ai JOIN components c ON c.id=ai.component_id
         JOIN stock_balances b ON b.component_id=ai.component_id
         LEFT JOIN reservations r ON r.order_id=ai.order_id AND r.component_id=ai.component_id
         WHERE ai.order_id=? ORDER BY c.name""",(oid,))
    for i in order['items']:
        outstanding=max(0, i['planned']-i['consumed']+i['returned']+i['damaged_return'])
        i['outstanding']=outstanding
        i['missing']=max(0,outstanding-i['reserved']-i['available'])
    order['fully_reserved']=bool(order['items']) and all(i['reserved']>=i['outstanding'] for i in order['items'])
    return order

@app.get('/api/orders')
def orders(q:str='',status:str='',page:int=1,size:int=30,user=Depends(permit('orders.read'))):
    limit,offset=paging(page,size)
    cond=['(o.code LIKE ? OR o.name LIKE ?)']; args=['%'+q+'%','%'+q+'%']
    if status: cond.append('o.status=?');args.append(status)
    where=' WHERE '+' AND '.join(cond)
    with closing(connect()) as c:
        return {'items':jsonrows(c,ORDER_SQL+where+' ORDER BY o.id DESC LIMIT ? OFFSET ?',(*args,limit,offset)),
                'total':c.execute('SELECT COUNT(*) FROM assembly_orders o'+where,args).fetchone()[0]}

@app.post('/api/orders')
def order_create(data:dict=Body(...),user=Depends(permit('orders.write'))):
    with transaction() as c:
        code=valstr(data,'code',default='OM-'+datetime.now().strftime('%y%m%d')+'-'+secrets.token_hex(2).upper(),required=True,maxlen=40)
        r=c.execute('''INSERT INTO assembly_orders(code,name,equipment_type,planned_qty,requester,responsible,due_date,priority,notes,created_by)
         VALUES(?,?,?,?,?,?,?,?,?,?)''',(
         code,valstr(data,'name',required=True),valstr(data,'equipment_type'),number(data.get('planned_qty',1),'Quantidade planejada'),
         valstr(data,'requester'),valstr(data,'responsible'),data.get('due_date') or None,
         valstr(data,'priority',default='Normal'),valstr(data,'notes',maxlen=3000),user['id']))
        audit(c,user['id'],'orders',r.lastrowid,'create')
        return {'id':r.lastrowid}

@app.get('/api/orders/{oid}')
def order_get(oid:int,user=Depends(permit('orders.read'))):
    with closing(connect()) as c: return order_detail(c,oid)

@app.patch('/api/orders/{oid}')
def order_update(oid:int,data:dict=Body(...),user=Depends(permit('orders.write'))):
    allowed={'name','equipment_type','planned_qty','requester','responsible','due_date','priority','notes'}
    with transaction() as c:
        o=record(c,'SELECT * FROM assembly_orders WHERE id=?',(oid,))
        require(o['status']=='RASCUNHO','Só é possível editar a ordem em rascunho',409)
        clean={}
        for k in allowed:
            if k not in data: continue
            clean[k]=number(data[k],k) if k=='planned_qty' else data[k] or None if k=='due_date' else valstr(data,k,required=k=='name',maxlen=3000 if k=='notes' else 250)
        if clean:
            c.execute('UPDATE assembly_orders SET '+','.join(f'{k}=?' for k in clean)+',updated_at=CURRENT_TIMESTAMP WHERE id=?',(*clean.values(),oid))
            audit(c,user['id'],'orders',oid,'edit',clean)
    return {'ok':True}

@app.put('/api/orders/{oid}/items')
def order_item_upsert(oid:int,data:dict=Body(...),user=Depends(permit('orders.write'))):
    cid=number(data.get('component_id'),'Componente'); required=qty(data.get('quantity'))
    with transaction() as c:
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status']=='RASCUNHO','Itens só podem ser editados em rascunho',409)
        record(c,'SELECT id FROM components WHERE id=? AND active=1',(cid,))
        c.execute('''INSERT INTO assembly_items(order_id,component_id,planned) VALUES(?,?,?)
         ON CONFLICT(order_id,component_id) DO UPDATE SET planned=excluded.planned''',(oid,cid,required))
        audit(c,user['id'],'orders',oid,'item_upsert',{'component_id':cid,'qty':required})
    return {'ok':True}

@app.delete('/api/orders/{oid}/items/{cid}')
def order_item_delete(oid:int,cid:int,user=Depends(permit('orders.write'))):
    with transaction() as c:
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status']=='RASCUNHO','Itens só podem ser editados em rascunho',409)
        c.execute('DELETE FROM assembly_items WHERE order_id=? AND component_id=?',(oid,cid))
        audit(c,user['id'],'orders',oid,'item_remove',{'component_id':cid})
    return {'ok':True}

def unreserve_order(c,oid,actor):
    for r in jsonrows(c,'SELECT * FROM reservations WHERE order_id=? AND quantity>0',(oid,)):
        amount=r['quantity']
        movement(c,r['component_id'],'LIBERACAO',actor,amount,dr=-amount,reason='Liberação da reserva',order_id=oid)
        c.execute('UPDATE reservations SET quantity=0,updated_at=CURRENT_TIMESTAMP,modified_by=? WHERE id=?',(actor,r['id']))

@app.post('/api/orders/{oid}/action')
def order_action(oid:int,data:dict=Body(...),user=Depends(permit('orders.read'))):
    action=valstr(data,'action',required=True)
    p={'submit':'orders.write','approve':'orders.approve','start':'orders.consume','pause':'orders.consume','resume':'orders.consume','finish':'orders.consume','cancel':'orders.approve'}
    require(action in p,'Ação inválida')
    require(p[action] in user['permissions'],'Sem permissão para essa ação',403)
    with transaction() as c:
        o=record(c,'SELECT * FROM assembly_orders WHERE id=?',(oid,))
        status=o['status']
        if action=='submit':
            require(status=='RASCUNHO','Ordem não está em rascunho',409)
            require(c.execute('SELECT COUNT(*) FROM assembly_items WHERE order_id=?',(oid,)).fetchone()[0]>0,'Adicione componentes')
            new='AGUARDANDO_APROVACAO'
        elif action=='approve':
            require(status=='AGUARDANDO_APROVACAO','Ordem não aguarda aprovação',409)
            new='AGUARDANDO_MATERIAIS'
        elif action=='start':
            require(status=='PRONTA','Reserve todos os materiais pendentes antes de iniciar',409)
            new='EM_MONTAGEM'
        elif action=='pause':
            require(status=='EM_MONTAGEM','Ordem não está em montagem',409)
            new='PAUSADA'
        elif action=='resume':
            require(status=='PAUSADA','Ordem não está pausada',409)
            new='EM_MONTAGEM'
        elif action=='finish':
            require(status=='EM_MONTAGEM','Ordem não está em montagem',409)
            d=order_detail(c,oid)
            require(all(i['outstanding']==0 for i in d['items']),'Existem quantidades planejadas ainda não consumidas. Ajuste a ordem por procedimento autorizado.',409)
            unreserve_order(c,oid,user['id']);new='CONCLUIDA'
        else:
            require(status not in ('CANCELADA','CONCLUIDA'),'Esta ordem não pode ser cancelada',409)
            # Consumptions cannot be undone by canceling a partially executed order.
            require(not c.execute("SELECT 1 FROM movements WHERE order_id=? AND kind='CONSUMO' LIMIT 1",(oid,)).fetchone(),
                    'Ordem com consumo deve ser concluída ou reconciliada, não cancelada',409)
            require(valstr(data,'reason',required=True),'Justificativa obrigatória')
            unreserve_order(c,oid,user['id']);new='CANCELADA'
        c.execute('UPDATE assembly_orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(new,oid))
        audit(c,user['id'],'orders',oid,action,{'from':status,'to':new,'reason':data.get('reason','')})
        return {'status':new}

@app.post('/api/orders/{oid}/reserve')
def reserve(oid:int,data:dict=Body(default={}),user=Depends(permit('orders.reserve'))):
    partial=bool(data.get('partial',False))
    with transaction() as c:
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status'] in ('AGUARDANDO_MATERIAIS','AGUARDANDO_SEPARACAO','PRONTA','EM_MONTAGEM','PAUSADA'), 'Ordem não autorizada para reserva',409)
        d=order_detail(c,oid)
        require(d['items'],'Ordem sem itens')
        if not partial:
            require(all(i['available']>=max(0,i['outstanding']-i['reserved']) for i in d['items']),
                    'Disponibilidade insuficiente. Escolha reserva parcial ou aguarde recebimentos.',409)
        for i in d['items']:
            needed=max(0,i['outstanding']-i['reserved'])
            amount=min(needed,i['available'])
            if amount<=0: continue
            movement(c,i['component_id'],'RESERVA',user['id'],amount,dr=amount,order_id=oid,reason='Reserva para montagem')
            c.execute('''INSERT INTO reservations(order_id,component_id,quantity,modified_by) VALUES(?,?,?,?)
              ON CONFLICT(order_id,component_id) DO UPDATE SET quantity=reservations.quantity+excluded.quantity,
              modified_by=excluded.modified_by,updated_at=CURRENT_TIMESTAMP''',(oid,i['component_id'],amount,user['id']))
        d=order_detail(c,oid)
        new=o['status'] if o['status'] in ('EM_MONTAGEM','PAUSADA') else ('PRONTA' if d['fully_reserved'] else 'AGUARDANDO_MATERIAIS')
        c.execute('UPDATE assembly_orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(new,oid))
        audit(c,user['id'],'orders',oid,'reserve',{'partial':partial,'status':new})
        return {'status':new,'items':d['items']}

@app.post('/api/orders/{oid}/release')
def release_reservation(oid:int,data:dict=Body(...),user=Depends(permit('orders.reserve'))):
    cid=number(data.get('component_id'),'Componente'); amount=qty(data.get('quantity'))
    with transaction() as c:
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status'] not in ('CONCLUIDA','CANCELADA','EM_MONTAGEM'),'Não é possível liberar neste status',409)
        r=record(c,'SELECT * FROM reservations WHERE order_id=? AND component_id=?',(oid,cid))
        require(r['quantity']>=amount,'Liberação maior que a reserva',409)
        movement(c,cid,'LIBERACAO',user['id'],amount,dr=-amount,order_id=oid,reason='Liberação manual de reserva')
        c.execute('UPDATE reservations SET quantity=quantity-?,modified_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(amount,user['id'],r['id']))
        c.execute("UPDATE assembly_orders SET status='AGUARDANDO_MATERIAIS' WHERE id=?",(oid,))
        audit(c,user['id'],'orders',oid,'release',{'component_id':cid,'qty':amount})
    return {'ok':True}

@app.post('/api/orders/{oid}/consume')
def consume(oid:int,req:Request,data:dict=Body(...),user=Depends(permit('orders.consume'))):
    cid=number(data.get('component_id'),'Componente');amount=qty(data.get('quantity'))
    key=req.headers.get('idempotency-key')
    with transaction() as c:
        dup=idem_existing(c,user['id'],'consume',key)
        if dup is not None:return dup
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status']=='EM_MONTAGEM','Ordem deve estar em montagem',409)
        item=record(c,'SELECT * FROM assembly_items WHERE order_id=? AND component_id=?',(oid,cid))
        r=record(c,'SELECT * FROM reservations WHERE order_id=? AND component_id=?',(oid,cid),'É necessário reservar o componente')
        require(r['quantity']>=amount,'Consumo maior que a reserva. Solicite e reserve materiais adicionais.',409)
        balance=record(c,'SELECT * FROM stock_balances WHERE component_id=?',(cid,))
        require(balance['physical']>=amount,'Estoque insuficiente',409)
        mid=movement(c,cid,'CONSUMO',user['id'],amount,dp=-amount,dr=-amount,order_id=oid,reason='Consumo efetivo na montagem')
        c.execute('UPDATE reservations SET quantity=quantity-?,modified_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(amount,user['id'],r['id']))
        result={'id':mid};idem_save(c,user['id'],'consume',key,result)
        audit(c,user['id'],'orders',oid,'consumption',{'component_id':cid,'qty':amount})
        return result

@app.post('/api/orders/{oid}/return')
def return_material(oid:int,req:Request,data:dict=Body(...),user=Depends(permit('orders.consume'))):
    cid=number(data.get('component_id'),'Componente');amount=qty(data.get('quantity'))
    condition=valstr(data,'condition',required=True).lower()
    require(condition in ('aprovado','avariado'),'Condição deve ser aprovado ou avariado')
    key=req.headers.get('idempotency-key')
    with transaction() as c:
        dup=idem_existing(c,user['id'],'return',key)
        if dup is not None:return dup
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status'] in ('EM_MONTAGEM','PAUSADA'),'Ordem não permite devolução',409)
        record(c,'SELECT id FROM assembly_items WHERE order_id=? AND component_id=?',(oid,cid))
        consumed=c.execute("SELECT COALESCE(SUM(quantity),0) FROM movements WHERE order_id=? AND component_id=? AND kind='CONSUMO'",(oid,cid)).fetchone()[0]
        returned=c.execute("SELECT COALESCE(SUM(quantity),0) FROM movements WHERE order_id=? AND component_id=? AND kind='DEVOLUCAO_TRIAGEM'",(oid,cid)).fetchone()[0]
        require(consumed-returned>=amount,'Devolução maior que o material consumido',409)
        reason=valstr(data,'reason',required=True,maxlen=500)
        # Material returned by a montador is quarantined until checked by almoxarifado.
        past=c.execute("SELECT SUM(quantity*unit_cost_cents) AS weighted, SUM(quantity) AS total FROM movements WHERE order_id=? AND component_id=? AND kind='CONSUMO'",(oid,cid)).fetchone()
        original_cost=round(past['weighted']/past['total']) if past['total'] else None
        mid=movement(c,cid,'DEVOLUCAO_TRIAGEM',user['id'],amount,dp=amount,db=amount,order_id=oid,reason=reason,cost=original_cost)
        rr=c.execute('INSERT INTO material_returns(order_id,component_id,quantity,condition,reason,created_by) VALUES(?,?,?,?,?,?)',
                     (oid,cid,amount,condition,reason,user['id']))
        result={'id':rr.lastrowid,'movement_id':mid,'status':'PENDENTE'}
        idem_save(c,user['id'],'return',key,result)
        audit(c,user['id'],'returns',rr.lastrowid,'create',{'component_id':cid,'qty':amount,'condition':condition})
        return result

@app.get('/api/returns')
def returns_list(page:int=1,size:int=30,user=Depends(permit('stock.read'))):
    limit,offset=paging(page,size)
    with closing(connect()) as c:
        return {'items':jsonrows(c,"""SELECT r.*,c.name AS component,c.sku,o.code AS order_code,u.name AS actor,
              a.name AS resolver FROM material_returns r JOIN components c ON c.id=r.component_id
              JOIN assembly_orders o ON o.id=r.order_id JOIN users u ON u.id=r.created_by
              LEFT JOIN users a ON a.id=r.resolved_by ORDER BY r.id DESC LIMIT ? OFFSET ?""",(limit,offset)),
                'total':c.execute('SELECT COUNT(*) FROM material_returns').fetchone()[0]}

@app.post('/api/returns/{rid}/inspect')
def inspect_return(rid:int,data:dict=Body(...),user=Depends(permit('stock.move'))):
    decision=valstr(data,'decision',required=True).lower()
    require(decision in ('aprovar','reprovar'),'Decisão inválida')
    with transaction() as c:
        r=record(c,'SELECT * FROM material_returns WHERE id=?',(rid,))
        require(r['status']=='PENDENTE','Esta devolução já foi inspecionada',409)
        if decision=='aprovar':
            movement(c,r['component_id'],'LIBERACAO_DEVOLUCAO',user['id'],r['quantity'],db=-r['quantity'],order_id=r['order_id'],reason='Material devolvido aprovado para reutilização')
            status='APROVADA'
        else:
            # Rejected returns remain physically blocked pending explicit discard.
            status='REPROVADA'
        c.execute('UPDATE material_returns SET status=?,resolved_by=?,resolved_at=CURRENT_TIMESTAMP WHERE id=?',(status,user['id'],rid))
        audit(c,user['id'],'returns',rid,'inspect',{'decision':decision,'status':status})
        return {'status':status}

PO_SQL="""SELECT p.*,s.name AS supplier,u.name AS created_by_name,
 (SELECT COUNT(*) FROM purchase_items i WHERE i.purchase_id=p.id) AS item_count,
 (SELECT COALESCE(SUM(i.quantity*i.unit_cost_cents/1000),0) FROM purchase_items i WHERE i.purchase_id=p.id) AS total_cents
 FROM purchase_orders p JOIN suppliers s ON s.id=p.supplier_id JOIN users u ON u.id=p.created_by"""

def po_detail(c,pid):
    purchase=record(c,PO_SQL+' WHERE p.id=?',(pid,))
    purchase['items']=jsonrows(c,"""SELECT i.*,c.sku,c.name,c.unit,
       (i.quantity-i.received) AS pending FROM purchase_items i JOIN components c ON c.id=i.component_id
       WHERE i.purchase_id=? ORDER BY c.name""",(pid,))
    purchase['receipts']=jsonrows(c,'SELECT r.*,u.name AS actor FROM receipts r JOIN users u ON u.id=r.created_by WHERE r.purchase_id=? ORDER BY r.id DESC',(pid,))
    return purchase

@app.get('/api/purchases')
def purchase_list(q:str='',status:str='',page:int=1,size:int=30,user=Depends(permit('purchases.read'))):
    limit,offset=paging(page,size)
    where=' WHERE (p.code LIKE ? OR s.name LIKE ?)'; args=['%'+q+'%','%'+q+'%']
    if status:where+=' AND p.status=?';args.append(status)
    with closing(connect()) as c:
        return {'items':jsonrows(c,PO_SQL+where+' ORDER BY p.id DESC LIMIT ? OFFSET ?',(*args,limit,offset)),
                'total':c.execute('SELECT COUNT(*) FROM purchase_orders p JOIN suppliers s ON s.id=p.supplier_id'+where,args).fetchone()[0]}

@app.get('/api/purchases/{pid}')
def purchase_detail(pid:int,user=Depends(permit('purchases.read'))):
    with closing(connect()) as c:return po_detail(c,pid)

@app.post('/api/purchases')
def purchase_create(data:dict=Body(...),user=Depends(permit('purchases.write'))):
    sid=number(data.get('supplier_id'),'Fornecedor')
    with transaction() as c:
        require(record(c,'SELECT active FROM suppliers WHERE id=?',(sid,))['active'],'Fornecedor inativo')
        code=valstr(data,'code',required=True,maxlen=50,default='PC-'+datetime.now().strftime('%y%m%d')+'-'+secrets.token_hex(2).upper())
        r=c.execute('INSERT INTO purchase_orders(code,supplier_id,expected_date,notes,created_by) VALUES(?,?,?,?,?)',(
            code,sid,data.get('expected_date') or None,valstr(data,'notes',maxlen=3000),user['id']))
        audit(c,user['id'],'purchases',r.lastrowid,'create')
        return {'id':r.lastrowid}

@app.put('/api/purchases/{pid}/items')
def purchase_item_upsert(pid:int,data:dict=Body(...),user=Depends(permit('purchases.write'))):
    cid=number(data.get('component_id'),'Componente')
    amount=qty(data.get('quantity'));price=money(data.get('unit_cost',0))
    with transaction() as c:
        p=record(c,'SELECT * FROM purchase_orders WHERE id=?',(pid,))
        require(p['status']=='RASCUNHO','Pedido já enviado à aprovação',409)
        record(c,'SELECT id FROM components WHERE id=? AND active=1',(cid,))
        c.execute('''INSERT INTO purchase_items(purchase_id,component_id,quantity,unit_cost_cents) VALUES(?,?,?,?)
          ON CONFLICT(purchase_id,component_id) DO UPDATE SET quantity=excluded.quantity,unit_cost_cents=excluded.unit_cost_cents''',
          (pid,cid,amount,price))
        c.execute('UPDATE purchase_orders SET updated_at=CURRENT_TIMESTAMP WHERE id=?',(pid,))
        audit(c,user['id'],'purchases',pid,'item_upsert',{'component_id':cid,'qty':amount,'price_cents':price})
    return {'ok':True}

@app.delete('/api/purchases/{pid}/items/{cid}')
def purchase_item_delete(pid:int,cid:int,user=Depends(permit('purchases.write'))):
    with transaction() as c:
        require(record(c,'SELECT status FROM purchase_orders WHERE id=?',(pid,))['status']=='RASCUNHO','Pedido não está em rascunho',409)
        c.execute('DELETE FROM purchase_items WHERE purchase_id=? AND component_id=?',(pid,cid))
        audit(c,user['id'],'purchases',pid,'item_remove',{'component_id':cid})
    return {'ok':True}

@app.post('/api/purchases/{pid}/action')
def purchase_action(pid:int,data:dict=Body(...),user=Depends(permit('purchases.read'))):
    action=valstr(data,'action',required=True)
    required={'submit':'purchases.write','approve':'purchases.approve','send':'purchases.write','cancel':'purchases.approve'}
    require(action in required,'Ação inválida')
    require(required[action] in user['permissions'],'Sem permissão para essa ação',403)
    with transaction() as c:
        p=record(c,'SELECT * FROM purchase_orders WHERE id=?',(pid,))
        if action=='submit':
            require(p['status']=='RASCUNHO','Pedido não está em rascunho',409)
            require(c.execute('SELECT COUNT(*) FROM purchase_items WHERE purchase_id=?',(pid,)).fetchone()[0]>0,'Adicione itens')
            new='AGUARDANDO_APROVACAO'
        elif action=='approve':
            require(p['status']=='AGUARDANDO_APROVACAO','Pedido não aguarda aprovação',409)
            new='APROVADO'
        elif action=='send':
            require(p['status']=='APROVADO','Pedido ainda não foi aprovado',409)
            new='ENVIADO'
        else:
            require(p['status'] not in ('CANCELADO','RECEBIDO','PARCIAL'),'Pedido com recebimento não pode ser cancelado',409)
            require(valstr(data,'reason',required=True),'Informe a justificativa');new='CANCELADO'
        c.execute('UPDATE purchase_orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(new,pid))
        audit(c,user['id'],'purchases',pid,action,{'from':p['status'],'to':new,'reason':data.get('reason','')})
        return {'status':new}

@app.post('/api/purchases/{pid}/receive')
def purchase_receive(pid:int,req:Request,data:dict=Body(...),user=Depends(permit('purchases.receive'))):
    reference=valstr(data,'reference',required=True,maxlen=100)
    lines=data.get('items')
    require(isinstance(lines,list) and len(lines)>0,'Informe os itens recebidos')
    key=req.headers.get('idempotency-key')
    with transaction() as c:
        dup=idem_existing(c,user['id'],'receive',key)
        if dup is not None:return dup
        p=record(c,'SELECT * FROM purchase_orders WHERE id=?',(pid,))
        require(p['status'] in ('ENVIADO','PARCIAL'),'Pedido deve estar enviado ou parcialmente recebido',409)
        r=c.execute('INSERT INTO receipts(purchase_id,reference,note,created_by) VALUES(?,?,?,?)',
                    (pid,reference,valstr(data,'note',maxlen=1000),user['id']))
        seen=set()
        for x in lines:
            item_id=number(x.get('purchase_item_id'),'Item')
            require(item_id not in seen,'Itens duplicados no recebimento');seen.add(item_id)
            item=record(c,'SELECT * FROM purchase_items WHERE id=? AND purchase_id=?',(item_id,pid))
            accepted=qty(x.get('accepted',0),allow_zero=True)
            rejected=qty(x.get('rejected',0),allow_zero=True)
            require(accepted+rejected>0,'Informe quantidade recebida ou rejeitada')
            require(accepted+rejected<=item['quantity']-item['received'],'Entrega supera a quantidade pendente',409)
            c.execute('INSERT INTO receipt_items(receipt_id,purchase_item_id,accepted,rejected) VALUES(?,?,?,?)',
                      (r.lastrowid,item_id,accepted,rejected))
            if accepted:
                movement(c,item['component_id'],'ENTRADA_COMPRA',user['id'],accepted,dp=accepted,purchase_id=pid,
                         receipt_id=r.lastrowid,reason=f'Recebimento {reference}',cost=item['unit_cost_cents'])
                c.execute('UPDATE purchase_items SET received=received+? WHERE id=?',(accepted,item_id))
                # Latest actual landed purchase cost becomes component reference cost. Consumption snapshots its cost.
                c.execute('UPDATE components SET cost_cents=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',
                          (item['unit_cost_cents'],item['component_id']))
            if rejected:
                c.execute('UPDATE purchase_items SET rejected=rejected+? WHERE id=?',(rejected,item_id))
        all_done=c.execute('SELECT COUNT(*) FROM purchase_items WHERE purchase_id=? AND received<quantity',(pid,)).fetchone()[0]==0
        c.execute('UPDATE purchase_orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',('RECEBIDO' if all_done else 'PARCIAL',pid))
        audit(c,user['id'],'receipts',r.lastrowid,'confirmed',{'purchase_id':pid,'reference':reference})
        result={'id':r.lastrowid,'status':'RECEBIDO' if all_done else 'PARCIAL'}
        idem_save(c,user['id'],'receive',key,result)
        return result

@app.get('/api/receipts')
def receipts(page:int=1,size:int=50,user=Depends(permit('purchases.read'))):
    limit,offset=paging(page,size)
    with closing(connect()) as c:
        return {'items':jsonrows(c,'''SELECT r.*,p.code AS purchase,s.name AS supplier,u.name AS actor
           FROM receipts r JOIN purchase_orders p ON p.id=r.purchase_id
           JOIN suppliers s ON s.id=p.supplier_id JOIN users u ON u.id=r.created_by
           ORDER BY r.id DESC LIMIT ? OFFSET ?''',(limit,offset)),
           'total':c.execute('SELECT COUNT(*) FROM receipts').fetchone()[0]}

@app.get('/api/receipts/{rid}')
def receipt_detail(rid:int,user=Depends(permit('purchases.read'))):
    with closing(connect()) as c:
        d=record(c,'SELECT * FROM receipts WHERE id=?',(rid,))
        d['items']=jsonrows(c,'SELECT ri.*,c.name,c.sku FROM receipt_items ri JOIN purchase_items pi ON pi.id=ri.purchase_item_id JOIN components c ON c.id=pi.component_id WHERE ri.receipt_id=?',(rid,))
        return d

@app.get('/api/material-requests')
def material_request_list(user=Depends(permit('orders.read'))):
    with closing(connect()) as c:
        return jsonrows(c,"""SELECT r.*,o.code AS order_code,c.name AS component,c.sku,u.name AS requester
          FROM material_requests r JOIN assembly_orders o ON o.id=r.order_id
          JOIN components c ON c.id=r.component_id JOIN users u ON u.id=r.created_by
          ORDER BY r.id DESC LIMIT 150""")

@app.post('/api/orders/{oid}/material-requests')
def material_request_create(oid:int,data:dict=Body(...),user=Depends(permit('orders.consume'))):
    cid=number(data.get('component_id'),'Componente')
    amount=qty(data.get('quantity'))
    reason=valstr(data,'reason',required=True,maxlen=1000)
    with transaction() as c:
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status'] in ('AGUARDANDO_MATERIAIS','PRONTA','EM_MONTAGEM','PAUSADA'),'Ordem não aceita solicitação adicional',409)
        record(c,'SELECT id FROM components WHERE id=? AND active=1',(cid,))
        r=c.execute('INSERT INTO material_requests(order_id,component_id,quantity,reason,created_by) VALUES(?,?,?,?,?)',
                    (oid,cid,amount,reason,user['id']))
        audit(c,user['id'],'material_requests',r.lastrowid,'create',{'order':oid,'component':cid,'qty':amount})
        return {'id':r.lastrowid,'status':'PENDENTE'}

@app.post('/api/material-requests/{rid}/decide')
def material_request_decide(rid:int,data:dict=Body(...),user=Depends(permit('orders.approve'))):
    action=valstr(data,'action',required=True)
    require(action in ('aprovar','rejeitar'),'Decisão inválida')
    with transaction() as c:
        r=record(c,'SELECT * FROM material_requests WHERE id=?',(rid,))
        require(r['status']=='PENDENTE','Esta solicitação já foi decidida',409)
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(r['order_id'],))
        require(o['status'] not in ('CONCLUIDA','CANCELADA'),'Ordem encerrada',409)
        if action=='aprovar':
            c.execute("""INSERT INTO assembly_items(order_id,component_id,planned) VALUES(?,?,?)
              ON CONFLICT(order_id,component_id) DO UPDATE SET planned=assembly_items.planned+excluded.planned""",
              (r['order_id'],r['component_id'],r['quantity']))
            if o['status']=='PRONTA':c.execute("UPDATE assembly_orders SET status='AGUARDANDO_MATERIAIS' WHERE id=?",(r['order_id'],))
        status='APROVADA' if action=='aprovar' else 'REJEITADA'
        c.execute('UPDATE material_requests SET status=?,resolved_by=?,resolved_at=CURRENT_TIMESTAMP WHERE id=?',(status,user['id'],rid))
        audit(c,user['id'],'material_requests',rid,action,{'reason':r['reason']})
        return {'status':status}

@app.post('/api/orders/{oid}/change-material')
def order_change_material(oid:int,data:dict=Body(...),user=Depends(permit('orders.approve'))):
    cid=number(data.get('component_id'),'Componente'); new_plan=qty(data.get('quantity'))
    reason=valstr(data,'reason',required=True,maxlen=500)
    with transaction() as c:
        o=record(c,'SELECT status FROM assembly_orders WHERE id=?',(oid,))
        require(o['status'] not in ('RASCUNHO','AGUARDANDO_APROVACAO','CONCLUIDA','CANCELADA'),
                'Alterações autorizadas só após aprovação e antes do encerramento',409)
        record(c,'SELECT id FROM components WHERE id=? AND active=1',(cid,))
        old=c.execute('SELECT * FROM assembly_items WHERE order_id=? AND component_id=?',(oid,cid)).fetchone()
        if old:
            consumed=c.execute("SELECT COALESCE(SUM(quantity),0) FROM movements WHERE order_id=? AND component_id=? AND kind='CONSUMO'",(oid,cid)).fetchone()[0]
            reserved=c.execute('SELECT COALESCE(quantity,0) FROM reservations WHERE order_id=? AND component_id=?',(oid,cid)).fetchone()
            require(new_plan>=consumed+((reserved['quantity']) if reserved else 0),'Nova quantidade menor que o material comprometido',409)
            c.execute('UPDATE assembly_items SET planned=? WHERE id=?',(new_plan,old['id']))
        else:
            c.execute('INSERT INTO assembly_items(order_id,component_id,planned) VALUES(?,?,?)',(oid,cid,new_plan))
        if o['status']=='PRONTA':
            c.execute("UPDATE assembly_orders SET status='AGUARDANDO_MATERIAIS' WHERE id=?",(oid,))
        audit(c,user['id'],'orders',oid,'change_material',{'component_id':cid,'new_milli':new_plan,'old_milli':old['planned'] if old else None,'reason':reason})
    return {'ok':True}

INV_SQL="""SELECT v.*,u.name AS creator,a.name AS approver,l.code AS location,
  (SELECT COUNT(*) FROM inventory_items x WHERE x.inventory_id=v.id) AS item_count,
  (SELECT COUNT(*) FROM inventory_items x WHERE x.inventory_id=v.id AND x.counted IS NULL) AS uncounted
  FROM inventories v JOIN users u ON u.id=v.created_by LEFT JOIN users a ON a.id=v.approved_by
  LEFT JOIN locations l ON l.id=v.location_id"""

@app.get('/api/inventories')
def inventory_list(page:int=1,size:int=30,user=Depends(permit('inventory.read'))):
    limit,offset=paging(page,size)
    with closing(connect()) as c:
        return {'items':jsonrows(c,INV_SQL+' ORDER BY v.id DESC LIMIT ? OFFSET ?',(limit,offset)),
                'total':c.execute('SELECT COUNT(*) FROM inventories').fetchone()[0]}

@app.get('/api/inventories/{iid}')
def inventory_detail(iid:int,user=Depends(permit('inventory.read'))):
    with closing(connect()) as c:
        d=record(c,INV_SQL+' WHERE v.id=?',(iid,))
        d['items']=jsonrows(c,'SELECT i.*,c.sku,c.name,c.unit,(i.counted-i.expected) AS difference FROM inventory_items i JOIN components c ON c.id=i.component_id WHERE i.inventory_id=? ORDER BY c.name',(iid,))
        return d

@app.post('/api/inventories')
def inventory_create(data:dict=Body(default={}),user=Depends(permit('inventory.write'))):
    location_id=data.get('location_id') or None
    components=data.get('component_ids')
    with transaction() as c:
        if location_id:record(c,'SELECT id FROM locations WHERE id=?',(location_id,))
        code=valstr(data,'code',default='INV-'+datetime.now().strftime('%y%m%d')+'-'+secrets.token_hex(2).upper(),required=True)
        r=c.execute('INSERT INTO inventories(code,location_id,notes,created_by) VALUES(?,?,?,?)',
                    (code,location_id,valstr(data,'notes',maxlen=2000),user['id']))
        sql='SELECT c.id,b.physical FROM components c JOIN stock_balances b ON b.component_id=c.id WHERE c.active=1'
        args=[]
        if location_id: sql+=' AND c.location_id=?';args.append(location_id)
        if components is not None:
            require(isinstance(components,list) and len(components)>0,'Selecione componentes para inventariar')
            ids=[number(x,'Componente') for x in components]
            sql+=' AND c.id IN ('+','.join('?' for _ in ids)+')';args+=ids
        rows=c.execute(sql,args).fetchall()
        require(rows,'Nenhum componente para conferência')
        for row in rows:
            c.execute('INSERT INTO inventory_items(inventory_id,component_id,expected) VALUES(?,?,?)',
                      (r.lastrowid,row['id'],row['physical']))
        audit(c,user['id'],'inventories',r.lastrowid,'create',{'items':len(rows)})
        return {'id':r.lastrowid,'items':len(rows)}

@app.put('/api/inventories/{iid}/count')
def inventory_count(iid:int,data:dict=Body(...),user=Depends(permit('inventory.write'))):
    cid=number(data.get('component_id'),'Componente'); counted=qty(data.get('counted'),allow_zero=True)
    with transaction() as c:
        d=record(c,'SELECT status FROM inventories WHERE id=?',(iid,))
        require(d['status']=='ABERTO','Inventário já submetido',409)
        item=record(c,'SELECT id FROM inventory_items WHERE inventory_id=? AND component_id=?',(iid,cid))
        c.execute('UPDATE inventory_items SET counted=?,note=?,counted_by=?,counted_at=CURRENT_TIMESTAMP WHERE id=?',
                  (counted,valstr(data,'note',maxlen=1000),user['id'],item['id']))
        audit(c,user['id'],'inventories',iid,'count',{'component_id':cid,'counted':counted})
    return {'ok':True}

@app.post('/api/inventories/{iid}/action')
def inventory_action(iid:int,data:dict=Body(...),user=Depends(permit('inventory.read'))):
    action=valstr(data,'action',required=True)
    require(action in ('submit','approve','reopen'),'Ação inválida')
    permission='inventory.write' if action=='submit' else 'inventory.approve'
    require(permission in user['permissions'],'Sem permissão',403)
    with transaction() as c:
        inv=record(c,'SELECT * FROM inventories WHERE id=?',(iid,))
        items=jsonrows(c,'SELECT * FROM inventory_items WHERE inventory_id=?',(iid,))
        if action=='submit':
            require(inv['status']=='ABERTO','Inventário não está aberto',409)
            require(items and all(i['counted'] is not None for i in items),'Conte todos os componentes antes de submeter',409)
            require(all(i['expected']==i['counted'] or i['note'].strip() for i in items),'Justifique as divergências antes de submeter',409)
            new='AGUARDANDO_APROVACAO'
        elif action=='reopen':
            require(inv['status']=='AGUARDANDO_APROVACAO','Inventário não aguarda aprovação',409)
            new='ABERTO'
        else:
            require(inv['status']=='AGUARDANDO_APROVACAO','Inventário não aguarda aprovação',409)
            for item in items:
                b=record(c,'SELECT * FROM stock_balances WHERE component_id=?',(item['component_id'],))
                require(b['physical']==item['expected'],'Estoque foi movimentado após a abertura. Refaça a contagem do inventário.',409)
                delta=item['counted']-b['physical']
                if delta:
                    require(item['counted']>=b['reserved']+b['blocked'], 'Contagem abaixo das quantidades reservadas/bloqueadas',409)
                    movement(c,item['component_id'],'AJUSTE_INVENTARIO',user['id'],abs(delta),dp=delta,
                             reason=item['note'],inventory_id=iid)
            new='APROVADO'
            c.execute('UPDATE inventories SET approved_by=?,approved_at=CURRENT_TIMESTAMP WHERE id=?',(user['id'],iid))
        c.execute('UPDATE inventories SET status=? WHERE id=?',(new,iid))
        audit(c,user['id'],'inventories',iid,action,{'status':new})
        return {'status':new}

@app.get('/api/dashboard')
def dashboard(user=Depends(permit('stock.read'))):
    with closing(connect()) as c:
        components=record(c,"""SELECT COUNT(*) AS total,
         COALESCE(SUM(CASE WHEN b.physical-b.reserved-b.blocked<=c.stock_min THEN 1 ELSE 0 END),0) AS low,
         COALESCE(SUM(CASE WHEN b.physical-b.reserved-b.blocked=0 THEN 1 ELSE 0 END),0) AS empty,
         COALESCE(SUM(b.physical*c.cost_cents/1000),0) AS value_cents,
         COALESCE(SUM(b.reserved),0) AS reserved,
         COALESCE(SUM(b.blocked),0) AS blocked,
         COALESCE(SUM(b.physical),0) AS physical
         FROM components c JOIN stock_balances b ON b.component_id=c.id WHERE c.active=1""")
        stats={'components':components,
          'open_orders':c.execute("SELECT COUNT(*) FROM assembly_orders WHERE status NOT IN ('CONCLUIDA','CANCELADA')").fetchone()[0],
          'waiting_orders':c.execute("SELECT COUNT(*) FROM assembly_orders WHERE status='AGUARDANDO_MATERIAIS'").fetchone()[0],
          'active_orders':c.execute("SELECT COUNT(*) FROM assembly_orders WHERE status='EM_MONTAGEM'").fetchone()[0],
          'pending_purchases':c.execute("SELECT COUNT(*) FROM purchase_orders WHERE status IN ('AGUARDANDO_APROVACAO','APROVADO','ENVIADO','PARCIAL')").fetchone()[0],
          'open_inventories':c.execute("SELECT COUNT(*) FROM inventories WHERE status IN ('ABERTO','AGUARDANDO_APROVACAO')").fetchone()[0],
          'movements':jsonrows(c,'SELECT m.id,m.kind,m.quantity,m.created_at,c.name AS component,c.sku FROM movements m JOIN components c ON c.id=m.component_id ORDER BY m.id DESC LIMIT 10'),
          'low_stock':jsonrows(c,COMPONENT_SQL+' WHERE c.active=1 AND (b.physical-b.reserved-b.blocked)<=c.stock_min ORDER BY (b.physical-b.reserved-b.blocked)-c.stock_min LIMIT 10'),
          'consumption_trend':jsonrows(c,"""SELECT substr(created_at,1,7) AS month,ROUND(SUM(quantity*unit_cost_cents/1000.0)/100,2) AS cost
               FROM movements WHERE kind='CONSUMO' AND created_at>=datetime('now','-12 months') GROUP BY substr(created_at,1,7) ORDER BY month""")}
        return stats

@app.get('/api/reports/consumption')
def report_consumption(start:str='',end:str='',order_id:Optional[int]=None,component_id:Optional[int]=None,user=Depends(permit('reports.read'))):
    sql="""SELECT o.id AS order_id,o.code AS order_code,o.name AS order_name,c.id AS component_id,c.sku,c.name AS component,c.unit,
     ai.planned AS planned,
     COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=o.id AND m.component_id=c.id AND m.kind='CONSUMO' AND (?='' OR date(m.created_at)>=date(?)) AND (?='' OR date(m.created_at)<=date(?))),0) AS consumed,
     COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=o.id AND m.component_id=c.id AND m.kind='DEVOLUCAO_TRIAGEM' AND (?='' OR date(m.created_at)>=date(?)) AND (?='' OR date(m.created_at)<=date(?))),0) AS returned,
     COALESCE((SELECT SUM(m.quantity) FROM movements m WHERE m.order_id=o.id AND m.component_id=c.id AND m.kind='PERDA' AND (?='' OR date(m.created_at)>=date(?)) AND (?='' OR date(m.created_at)<=date(?))),0) AS lost,
     COALESCE((SELECT SUM(m.quantity*m.unit_cost_cents/1000.0) FROM movements m WHERE m.order_id=o.id AND m.component_id=c.id AND m.kind='CONSUMO' AND (?='' OR date(m.created_at)>=date(?)) AND (?='' OR date(m.created_at)<=date(?))),0) AS consumed_cost_cents,
     COALESCE((SELECT SUM(m.quantity*m.unit_cost_cents/1000.0) FROM movements m WHERE m.order_id=o.id AND m.component_id=c.id AND m.kind='DEVOLUCAO_TRIAGEM' AND (?='' OR date(m.created_at)>=date(?)) AND (?='' OR date(m.created_at)<=date(?))),0) AS returned_cost_cents
     FROM assembly_items ai JOIN assembly_orders o ON o.id=ai.order_id JOIN components c ON c.id=ai.component_id WHERE 1=1"""
    args=[start,start,end,end]*5
    if order_id:sql+=' AND o.id=?';args.append(order_id)
    if component_id:sql+=' AND c.id=?';args.append(component_id)
    sql+=' ORDER BY o.id DESC,c.name'
    with closing(connect()) as c: return jsonrows(c,sql,args)

@app.get('/api/reports/export')
def report_export(format:str='csv',start:str='',end:str='',order_id:Optional[int]=None,component_id:Optional[int]=None,user=Depends(permit('reports.read'))):
    require(format in ('csv','xlsx','pdf'),'Formato inválido')
    rows=report_consumption(start,end,order_id,component_id,user)
    headers=['Ordem','Montagem','Código','Componente','Planejado','Consumido','Devolvido','Perdas','Custo consumo (R$)','Custo líquido (R$)']
    data=[]
    for r in rows:
        data.append([r['order_code'],r['order_name'],r['sku'],r['component'],r['planned']/1000,
                     r['consumed']/1000,r['returned']/1000,r['lost']/1000,
                     round(r['consumed_cost_cents']/100,2),round((r['consumed_cost_cents']-r['returned_cost_cents'])/100,2)])
    if format=='csv':
        out=io.StringIO(); writer=csv.writer(out,delimiter=';');writer.writerow(headers);writer.writerows(data)
        payload='\ufeff'+out.getvalue()
        return Response(payload,media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="consumo.csv"'})
    if format=='xlsx':
        from openpyxl import Workbook
        wb=Workbook();ws=wb.active;ws.title='Consumo'
        ws.append(headers)
        for row in data:ws.append(row)
        ws.freeze_panes='A2';ws.auto_filter.ref=ws.dimensions
        for col in ws.columns:
            column=col[0].column_letter
            ws.column_dimensions[column].width=min(44,max(15,max(len(str(cell.value or '')) for cell in col)+2))
        out=io.BytesIO();wb.save(out);out.seek(0)
        return StreamingResponse(out,media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                 headers={'Content-Disposition':'attachment; filename="consumo.xlsx"'})
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.pdfgen.canvas import Canvas
    out=io.BytesIO();pdf=Canvas(out,pagesize=landscape(A4));w,h=landscape(A4)
    def header():
        pdf.setFont('Helvetica-Bold',14);pdf.drawString(30,h-34,'Almoxarifado Central - Consumo por montagem')
        pdf.setFont('Helvetica',9);pdf.drawString(30,h-50,f'Periodo: {start or "inicio"} a {end or "hoje"}')
        pdf.line(30,h-58,w-30,h-58)
    header(); y=h-78
    for row in data:
        if y<38: pdf.showPage();header();y=h-78
        line=f'{str(row[0])[:16]:16} | {str(row[2])[:14]:14} | {str(row[3])[:36]:36} | Prev: {row[4]} | Cons: {row[5]} | Liq: R$ {row[9]:.2f}'
        pdf.setFont('Courier',7.5);pdf.drawString(30,y,line);y-=14
    pdf.save();out.seek(0)
    return StreamingResponse(out,media_type='application/pdf',headers={'Content-Disposition':'attachment; filename="consumo.pdf"'})

@app.get('/api/audit')
def audit_list(q:str='',page:int=1,size:int=50,user=Depends(permit('audit.read'))):
    limit,offset=paging(page,size)
    sql=' FROM audit_events a LEFT JOIN users u ON u.id=a.actor_id WHERE (a.entity LIKE ? OR a.action LIKE ? OR u.name LIKE ?)'
    args=['%'+q+'%']*3
    with closing(connect()) as c:
        return {'items':jsonrows(c,'SELECT a.*,u.name AS actor'+sql+' ORDER BY a.id DESC LIMIT ? OFFSET ?',(*args,limit,offset)),
                'total':c.execute('SELECT COUNT(*)'+sql,args).fetchone()[0]}

@app.get('/api/health')
def health():return {'status':'ok'}
