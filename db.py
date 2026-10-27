"""SQLite schema and transactional primitives. All quantities use 0.001 units; prices use cents."""
import os
import sqlite3
import secrets
import hashlib
from pathlib import Path
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get('ALMOX_DB', str(ROOT / 'data' / 'almoxarifado.db')))

ALL_PERMISSIONS = [
    'components.read','components.write','stock.read','stock.move',
    'orders.read','orders.write','orders.approve','orders.reserve','orders.consume',
    'purchases.read','purchases.write','purchases.approve','purchases.receive',
    'inventory.read','inventory.write','inventory.approve','reports.read',
    'audit.read','users.manage','roles.manage'
]
ROLE_PERMISSIONS = {
    'Administrador': ALL_PERMISSIONS,
    'Gestor': ['components.read','stock.read','orders.read','orders.approve','purchases.read','purchases.approve','inventory.read','inventory.approve','reports.read','audit.read'],
    'Almoxarife': ['components.read','components.write','stock.read','stock.move','orders.read','orders.reserve','purchases.read','purchases.receive','inventory.read','inventory.write','reports.read'],
    'Montador': ['components.read','stock.read','orders.read','orders.consume'],
    'Comprador': ['components.read','stock.read','orders.read','purchases.read','purchases.write','purchases.receive','reports.read'],
    'Auditor': ['components.read','stock.read','orders.read','purchases.read','inventory.read','reports.read','audit.read']
}

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS roles (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS role_permissions (
 role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
 permission TEXT NOT NULL, PRIMARY KEY(role_id, permission)
);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL COLLATE NOCASE UNIQUE,
 password_hash TEXT NOT NULL, role_id INTEGER NOT NULL REFERENCES roles(id),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf_hash TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS categories (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS locations (
 id INTEGER PRIMARY KEY, code TEXT NOT NULL COLLATE NOCASE UNIQUE, sector TEXT NOT NULL DEFAULT '', corridor TEXT NOT NULL DEFAULT '',
 rack TEXT NOT NULL DEFAULT '', shelf TEXT NOT NULL DEFAULT '', drawer TEXT NOT NULL DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE TABLE IF NOT EXISTS suppliers (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, cnpj TEXT UNIQUE, contact TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '',
 email TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', commercial_terms TEXT NOT NULL DEFAULT '',
 lead_days INTEGER NOT NULL DEFAULT 0 CHECK(lead_days>=0), notes TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS components (
 id INTEGER PRIMARY KEY, sku TEXT NOT NULL COLLATE NOCASE UNIQUE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 category_id INTEGER REFERENCES categories(id), location_id INTEGER REFERENCES locations(id),
 manufacturer TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', unit TEXT NOT NULL DEFAULT 'UN',
 stock_min INTEGER NOT NULL DEFAULT 0 CHECK(stock_min>=0), reorder_target INTEGER NOT NULL DEFAULT 0 CHECK(reorder_target>=0),
 cost_cents INTEGER NOT NULL DEFAULT 0 CHECK(cost_cents>=0), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS supplier_components (
 supplier_id INTEGER NOT NULL REFERENCES suppliers(id), component_id INTEGER NOT NULL REFERENCES components(id),
 PRIMARY KEY(supplier_id, component_id)
);
CREATE TABLE IF NOT EXISTS stock_balances (
 component_id INTEGER PRIMARY KEY REFERENCES components(id),
 physical INTEGER NOT NULL DEFAULT 0 CHECK(physical>=0), reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved>=0),
 blocked INTEGER NOT NULL DEFAULT 0 CHECK(blocked>=0),
 CHECK (physical >= reserved + blocked)
);
CREATE TABLE IF NOT EXISTS assembly_orders (
 id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL, equipment_type TEXT NOT NULL DEFAULT '',
 planned_qty INTEGER NOT NULL DEFAULT 1 CHECK(planned_qty>0), requester TEXT NOT NULL DEFAULT '',
 responsible TEXT NOT NULL DEFAULT '', due_date TEXT, priority TEXT NOT NULL DEFAULT 'Normal',
 status TEXT NOT NULL DEFAULT 'RASCUNHO', notes TEXT NOT NULL DEFAULT '',
 created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assembly_items (
 id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES assembly_orders(id),
 component_id INTEGER NOT NULL REFERENCES components(id), planned INTEGER NOT NULL CHECK(planned>0),
 UNIQUE(order_id, component_id)
);
CREATE TABLE IF NOT EXISTS reservations (
 id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES assembly_orders(id),
 component_id INTEGER NOT NULL REFERENCES components(id), quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity>=0),
 modified_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(order_id, component_id)
);
CREATE TABLE IF NOT EXISTS purchase_orders (
 id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, supplier_id INTEGER NOT NULL REFERENCES suppliers(id),
 status TEXT NOT NULL DEFAULT 'RASCUNHO', expected_date TEXT, notes TEXT NOT NULL DEFAULT '',
 created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS purchase_items (
 id INTEGER PRIMARY KEY, purchase_id INTEGER NOT NULL REFERENCES purchase_orders(id),
 component_id INTEGER NOT NULL REFERENCES components(id), quantity INTEGER NOT NULL CHECK(quantity>0),
 received INTEGER NOT NULL DEFAULT 0 CHECK(received>=0), rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected>=0),
 unit_cost_cents INTEGER NOT NULL DEFAULT 0 CHECK(unit_cost_cents>=0), UNIQUE(purchase_id, component_id),
 CHECK(received<=quantity)
);
CREATE TABLE IF NOT EXISTS material_requests (
 id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES assembly_orders(id),
 component_id INTEGER NOT NULL REFERENCES components(id), quantity INTEGER NOT NULL CHECK(quantity>0),
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDENTE', created_by INTEGER NOT NULL REFERENCES users(id),
 resolved_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS material_returns (
 id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL REFERENCES assembly_orders(id),
 component_id INTEGER NOT NULL REFERENCES components(id), quantity INTEGER NOT NULL CHECK(quantity>0),
 condition TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDENTE',
 reason TEXT NOT NULL DEFAULT '', created_by INTEGER NOT NULL REFERENCES users(id),
 resolved_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
 identity TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0,
 blocked_until TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS receipts (
 id INTEGER PRIMARY KEY, purchase_id INTEGER NOT NULL REFERENCES purchase_orders(id),
 reference TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_by INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(purchase_id, reference)
);
CREATE TABLE IF NOT EXISTS receipt_items (
 id INTEGER PRIMARY KEY, receipt_id INTEGER NOT NULL REFERENCES receipts(id),
 purchase_item_id INTEGER NOT NULL REFERENCES purchase_items(id),
 accepted INTEGER NOT NULL DEFAULT 0 CHECK(accepted>=0), rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected>=0),
 CHECK(accepted+rejected>0), UNIQUE(receipt_id,purchase_item_id)
);
CREATE TABLE IF NOT EXISTS inventories (
 id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, location_id INTEGER REFERENCES locations(id),
 status TEXT NOT NULL DEFAULT 'ABERTO', notes TEXT NOT NULL DEFAULT '',
 created_by INTEGER NOT NULL REFERENCES users(id), approved_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, approved_at TEXT
);
CREATE TABLE IF NOT EXISTS inventory_items (
 id INTEGER PRIMARY KEY, inventory_id INTEGER NOT NULL REFERENCES inventories(id),
 component_id INTEGER NOT NULL REFERENCES components(id), expected INTEGER NOT NULL CHECK(expected>=0),
 counted INTEGER CHECK(counted>=0), note TEXT NOT NULL DEFAULT '',
 counted_by INTEGER REFERENCES users(id), counted_at TEXT, UNIQUE(inventory_id,component_id)
);
CREATE TABLE IF NOT EXISTS movements (
 id INTEGER PRIMARY KEY, component_id INTEGER NOT NULL REFERENCES components(id),
 kind TEXT NOT NULL, quantity INTEGER NOT NULL CHECK(quantity>0), physical_delta INTEGER NOT NULL DEFAULT 0,
 reserved_delta INTEGER NOT NULL DEFAULT 0, blocked_delta INTEGER NOT NULL DEFAULT 0,
 before_physical INTEGER NOT NULL, after_physical INTEGER NOT NULL,
 before_reserved INTEGER NOT NULL, after_reserved INTEGER NOT NULL,
 before_blocked INTEGER NOT NULL, after_blocked INTEGER NOT NULL,
 unit_cost_cents INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '',
 order_id INTEGER REFERENCES assembly_orders(id), purchase_id INTEGER REFERENCES purchase_orders(id),
 receipt_id INTEGER REFERENCES receipts(id), inventory_id INTEGER REFERENCES inventories(id),
 reversal_of INTEGER UNIQUE REFERENCES movements(id), actor_id INTEGER NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), entity TEXT NOT NULL,
 entity_id INTEGER, action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS idempotency (
 actor_id INTEGER NOT NULL REFERENCES users(id), operation TEXT NOT NULL, idem_key TEXT NOT NULL,
 result_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(actor_id,operation,idem_key)
);
CREATE INDEX IF NOT EXISTS idx_movements_component_date ON movements(component_id,created_at);
CREATE INDEX IF NOT EXISTS idx_movements_order ON movements(order_id);
CREATE INDEX IF NOT EXISTS idx_movements_kind_date ON movements(kind,created_at);
CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_components_name ON components(name);
CREATE INDEX IF NOT EXISTS idx_orders_status ON assembly_orders(status);
CREATE INDEX IF NOT EXISTS idx_po_status ON purchase_orders(status);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
"""

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=20, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA busy_timeout=20000')
    return c

@contextmanager
def transaction():
    c = connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        yield c
        c.commit()
    except:
        c.rollback()
        raise
    finally:
        c.close()

def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return f'pbkdf2_sha256$600000${salt.hex()}${digest.hex()}'

def verify_password(password, encoded):
    try:
        _, iterations, s, h = encoded.split('$')
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(s), int(iterations))
        return secrets.compare_digest(actual, bytes.fromhex(h))
    except (ValueError,TypeError):
        return False

def initialize():
    # Railway containers have ephemeral filesystems. Refuse cloud startup unless
    # a persistent volume is mounted over the SQLite/CSRF-key directory.
    if os.environ.get('ALMOX_REQUIRE_VOLUME') == '1':
        mount = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', '')
        if not mount:
            raise RuntimeError('Volume persistente obrigatorio: anexe um Railway Volume em /app/data.')
        if Path(mount).resolve() != DB_PATH.parent.resolve():
            raise RuntimeError('O volume persistente deve estar montado na pasta do banco de dados.')
        if not DB_PATH.parent.is_dir():
            raise RuntimeError('Diretorio do volume persistente nao encontrado.')
    c = connect()
    try:
        c.execute('PRAGMA journal_mode=WAL')
        c.executescript(SCHEMA)
        for role, perms in ROLE_PERMISSIONS.items():
            first=c.execute('SELECT id FROM roles WHERE name=?',(role,)).fetchone() is None
            c.execute('INSERT OR IGNORE INTO roles(name) VALUES(?)', (role,))
            rid = c.execute('SELECT id FROM roles WHERE name=?', (role,)).fetchone()['id']
            # Do not reset permissions customized later by the admin.
            if first:
                c.executemany('INSERT OR IGNORE INTO role_permissions(role_id,permission) VALUES(?,?)', [(rid,p) for p in perms])
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            cloud = os.environ.get('ALMOX_REQUIRE_VOLUME') == '1'
            configured_password = os.environ.get('ALMOX_ADMIN_PASSWORD')
            if cloud and (not configured_password or len(configured_password) < 12):
                raise RuntimeError('Defina ALMOX_ADMIN_PASSWORD com pelo menos 12 caracteres antes de publicar.')
            password = configured_password or secrets.token_urlsafe(15)
            email = os.environ.get('ALMOX_ADMIN_EMAIL', 'admin@local')
            if cloud and ('@' not in email or email.endswith('@local')):
                raise RuntimeError('Defina ALMOX_ADMIN_EMAIL com um e-mail real para o primeiro acesso.')
            rid = c.execute("SELECT id FROM roles WHERE name='Administrador'").fetchone()['id']
            c.execute('INSERT INTO users(name,email,password_hash,role_id) VALUES(?,?,?,?)', ('Administrador',email,hash_password(password),rid))
            print('\n' + '='*62 + '\n PRIMEIRO ACESSO AO ALMOXARIFADO')
            print(f' Email: {email}')
            if configured_password:
                print(' Senha: use ALMOX_ADMIN_PASSWORD configurada nas variaveis do servidor.')
            else:
                print(f' Senha: {password}')
                print(' GUARDE A SENHA: ela nao sera exibida novamente.')
            print('='*62 + '\n',flush=True)
    finally:
        c.close()

def dicts(rows):
    return [dict(x) for x in rows]
