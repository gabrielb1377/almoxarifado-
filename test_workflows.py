"""Integration tests against an isolated SQLite database; run pytest -q."""
import os
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
from fastapi.testclient import TestClient
import db
from main import app

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(db,'DB_PATH',tmp_path/'warehouse_test.db')
    monkeypatch.setenv('ALMOX_ADMIN_PASSWORD','StrongTestPassword!456')
    monkeypatch.setenv('ALMOX_ADMIN_EMAIL','admin@test.local')
    with TestClient(app) as client:
        assert client.get('/api/health').status_code==200
        res=client.post('/api/auth/login',json={'email':'admin@test.local','password':'StrongTestPassword!456'})
        assert res.status_code==200, res.text
        client.headers.update({'X-CSRF-Token':res.json()['csrf']})
        yield client


def post(c,url,data,status=200,key=None):
    headers={'Idempotency-Key':key} if key else {}
    r=c.post('/api'+url,json=data,headers=headers)
    assert r.status_code==status, (url,r.status_code,r.text)
    return r.json()


def put(c,url,data,status=200):
    r=c.put('/api'+url,json=data)
    assert r.status_code==status,(url,r.text)
    return r.json()


def get(c,url,status=200):
    r=c.get('/api'+url)
    assert r.status_code==status,(url,r.text)
    return r.json()


def setup(c):
    cat=post(c,'/reference/categories',{'name':'Eletrônica'})['id']
    loc=post(c,'/reference/locations',{'code':'A-01','sector':'Central'})['id']
    sup=post(c,'/reference/suppliers',{'name':'Distribuidora Exemplo','cnpj':'11222333000144'})['id']
    comp=post(c,'/components',{'sku':'CAB-001','name':'Cabo de energia','unit':'M','category_id':cat,'location_id':loc,'stock_min':5,'reorder_target':20,'cost':12.50})['id']
    return cat,loc,sup,comp


def test_purchases_receiving_idempotency_and_cost(client):
    c=client;_,_,sup,comp=setup(c)
    pid=post(c,'/purchases',{'supplier_id':sup})['id']
    put(c,f'/purchases/{pid}/items',{'component_id':comp,'quantity':10,'unit_cost':15.25})
    assert get(c,f'/purchases/{pid}')['status']=='RASCUNHO'
    for action in ('submit','approve','send'):
        post(c,f'/purchases/{pid}/action',{'action':action})
    item=get(c,f'/purchases/{pid}')['items'][0]['id']
    assert get(c,f'/components/{comp}')['physical']==0
    a=post(c,f'/purchases/{pid}/receive',{'reference':'NF-A','items':[{'purchase_item_id':item,'accepted':6,'rejected':1}]},key='recv-key-0001')
    assert a['status']=='PARCIAL'
    again=post(c,f'/purchases/{pid}/receive',{'reference':'NF-A','items':[{'purchase_item_id':item,'accepted':6,'rejected':1}]},key='recv-key-0001')
    assert a==again
    post(c,f'/purchases/{pid}/receive',{'reference':'NF-A','items':[{'purchase_item_id':item,'accepted':1}]},409,key='recv-key-0002')
    assert get(c,f'/components/{comp}')['physical']==6000
    assert get(c,f'/components/{comp}')['cost_cents']==1525
    b=post(c,f'/purchases/{pid}/receive',{'reference':'NF-B','items':[{'purchase_item_id':item,'accepted':4}]})
    assert b['status']=='RECEBIDO'
    assert get(c,f'/components/{comp}')['physical']==10000
    assert get(c,'/dashboard')['components']['value_cents']==15250


def test_orders_reservation_no_oversell_consumption_returns(client):
    c=client;_,_,sup,cid=setup(c)
    post(c,'/movements/manual',{'component_id':cid,'kind':'ENTRADA_AVULSA','quantity':10,'reason':'Saldo inicial autorizado'})
    o1=post(c,'/orders',{'name':'Montagem A'})['id']
    o2=post(c,'/orders',{'name':'Montagem B'})['id']
    for oid in (o1,o2):
        put(c,f'/orders/{oid}/items',{'component_id':cid,'quantity':7})
        post(c,f'/orders/{oid}/action',{'action':'submit'})
        post(c,f'/orders/{oid}/action',{'action':'approve'})
    assert post(c,f'/orders/{o1}/reserve',{'partial':False})['status']=='PRONTA'
    post(c,f'/orders/{o2}/reserve',{'partial':False},409)
    assert post(c,f'/orders/{o2}/reserve',{'partial':True})['status']=='AGUARDANDO_MATERIAIS'
    d=get(c,f'/components/{cid}')
    assert d['physical']==10000 and d['reserved']==10000 and d['available']==0
    post(c,f'/orders/{o1}/action',{'action':'start'})
    a=post(c,f'/orders/{o1}/consume',{'component_id':cid,'quantity':7},key='consume-test-1')
    assert a==post(c,f'/orders/{o1}/consume',{'component_id':cid,'quantity':7},key='consume-test-1')
    d=get(c,f'/components/{cid}');assert d['physical']==3000 and d['reserved']==3000
    returned=post(c,f'/orders/{o1}/return',{'component_id':cid,'quantity':2,'condition':'aprovado','reason':'Não utilizado'})
    assert get(c,f'/components/{cid}')['blocked']==2000
    post(c,f'/returns/{returned["id"]}/inspect',{'decision':'aprovar'})
    assert get(c,f'/components/{cid}')['blocked']==0
    # Return makes 2 units available and restores 2 outstanding units on order 1.
    post(c,f'/orders/{o1}/reserve',{'partial':False})
    assert get(c,f'/components/{cid}')['reserved']==5000
    post(c,f'/orders/{o1}/consume',{'component_id':cid,'quantity':2})
    post(c,f'/orders/{o1}/action',{'action':'finish'})
    d=get(c,f'/components/{cid}')
    assert d['physical']==3000 and d['reserved']==3000 and d['available']==0
    report=get(c,'/reports/consumption')
    r=next(x for x in report if x['order_id']==o1)
    assert r['consumed']==9000 and r['returned']==2000 and r['planned']==7000
    assert c.get('/api/reports/export?format=csv').status_code==200
    assert c.get('/api/reports/export?format=xlsx').content[:2]==b'PK'
    assert c.get('/api/reports/export?format=pdf').content[:4]==b'%PDF'


def test_inventory_does_not_adjust_until_approval_and_stale_rejected(client):
    c=client;_,_,_,cid=setup(c)
    post(c,'/movements/manual',{'component_id':cid,'kind':'ENTRADA_AVULSA','quantity':10,'reason':'Abertura'})
    iid=post(c,'/inventories',{'component_ids':[cid]})['id']
    put(c,f'/inventories/{iid}/count',{'component_id':cid,'counted':9,'note':'Unidade extraviada'})
    assert get(c,f'/components/{cid}')['physical']==10000
    post(c,f'/inventories/{iid}/action',{'action':'submit'})
    post(c,f'/inventories/{iid}/action',{'action':'approve'})
    assert get(c,f'/components/{cid}')['physical']==9000
    iid2=post(c,'/inventories',{'component_ids':[cid]})['id']
    put(c,f'/inventories/{iid2}/count',{'component_id':cid,'counted':8,'note':'Nova contagem'})
    post(c,f'/inventories/{iid2}/action',{'action':'submit'})
    post(c,'/movements/manual',{'component_id':cid,'kind':'PERDA','quantity':1,'reason':'Ocorrência'})
    post(c,f'/inventories/{iid2}/action',{'action':'approve'},409)
    assert get(c,f'/components/{cid}')['physical']==8000


def test_rbac_and_csrf(client):
    c=client; uid=post(c,'/users',{'name':'Montador Teste','email':'montador@test.local','password':'PasswordTest1234','role_id':4})['id']
    assert uid>0
    no_csrf=c.post('/api/components',json={'sku':'NO','name':'Sem CSRF'},headers={'X-CSRF-Token':''})
    assert no_csrf.status_code==403
    with TestClient(app) as other:
        res=other.post('/api/auth/login',json={'email':'montador@test.local','password':'PasswordTest1234'})
        assert res.status_code==200
        other.headers.update({'X-CSRF-Token':res.json()['csrf']})
        assert other.get('/api/users').status_code==403
        assert other.post('/api/components',json={'sku':'X','name':'Indevido'}).status_code==403
        assert other.get('/api/orders').status_code==200


def test_additional_material_request_and_return_inspection(client):
    c=client;_,_,_,cid=setup(c)
    post(c,'/movements/manual',{'component_id':cid,'kind':'ENTRADA_AVULSA','quantity':8,'reason':'Recebimento anterior'})
    o=post(c,'/orders',{'name':'Montagem extra'})['id']
    put(c,f'/orders/{o}/items',{'component_id':cid,'quantity':5})
    for action in ('submit','approve'):post(c,f'/orders/{o}/action',{'action':action})
    request=post(c,f'/orders/{o}/material-requests',{'component_id':cid,'quantity':2,'reason':'Cabo adicional para instalação'})
    assert get(c,f'/orders/{o}')['items'][0]['planned']==5000
    post(c,f'/material-requests/{request["id"]}/decide',{'action':'aprovar'})
    assert get(c,f'/orders/{o}')['items'][0]['planned']==7000
    post(c,f'/orders/{o}/reserve',{'partial':False})
    post(c,f'/orders/{o}/action',{'action':'start'})
    post(c,f'/orders/{o}/consume',{'component_id':cid,'quantity':7})
    ret=post(c,f'/orders/{o}/return',{'component_id':cid,'quantity':1,'condition':'avariado','reason':'Cabo danificado na bancada'})
    stock=get(c,f'/components/{cid}')
    assert stock['physical']==2000 and stock['blocked']==1000 and stock['available']==1000
    post(c,f'/returns/{ret["id"]}/inspect',{'decision':'reprovar'})
    stock=get(c,f'/components/{cid}')
    assert stock['blocked']==1000
    post(c,'/movements/manual',{'component_id':cid,'kind':'PERDA','quantity':1,'reason':'Descarte de material danificado','from_blocked':True,'order_id':o})
    stock=get(c,f'/components/{cid}')
    assert stock['physical']==1000 and stock['blocked']==0
    assert get(c,'/reports/consumption')[0]['lost']==1000


def test_lockout_invalid_credentials(client):
    from fastapi.testclient import TestClient
    with TestClient(app) as anonymous:
        for i in range(5):
            resp=anonymous.post('/api/auth/login',json={'email':'bad@test.local','password':'WrongPassword!123'})
            assert resp.status_code==401,resp.text
        assert anonymous.post('/api/auth/login',json={'email':'bad@test.local','password':'WrongPassword!123'}).status_code==429


def test_concurrent_reservations_one_winner(client):
    """Two writes competing for the last 8 units must never oversell stock."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    c=client;_,_,_,cid=setup(c)
    post(c,'/movements/manual',{'component_id':cid,'kind':'ENTRADA_AVULSA','quantity':8,'reason':'Abertura'})
    orders=[]
    for i in range(2):
        oid=post(c,'/orders',{'name':f'Montagem {i}'})['id']
        put(c,f'/orders/{oid}/items',{'component_id':cid,'quantity':8})
        post(c,f'/orders/{oid}/action',{'action':'submit'})
        post(c,f'/orders/{oid}/action',{'action':'approve'})
        orders.append(oid)
    barrier=Barrier(2)
    def run(oid):
        barrier.wait(timeout=5)
        return c.post(f'/api/orders/{oid}/reserve',json={'partial':False}).status_code
    with ThreadPoolExecutor(max_workers=2) as ex:
        results=list(ex.map(run,orders))
    assert sorted(results)==[200,409],results
    final=get(c,f'/components/{cid}')
    assert final['reserved']==8000 and final['physical']==8000 and final['available']==0
