#!/usr/bin/env python3
"""خادم مؤسسة الأمانة v6 — قاعدة بيانات SQL (SQLite) بدل ملفات JSON.
لا يحتاج أي مكتبات خارجية (Python 3.8+ فقط).

تشغيل مستقل (جهاز مكتب أو VPS):
  python server.py              ← شبكة المكتب (0.0.0.0:8765)
  python server.py --local      ← هذا الجهاز فقط (127.0.0.1)
  python server.py --port 9000  ← منفذ آخر

استضافة cPanel / Passenger: انظر passenger_wsgi.py (يستورد `application` من هنا).

متغيرات البيئة (اختيارية):
  AMANAH_DATA         مجلد قاعدة البيانات والنسخ الاحتياطية (الافتراضي: data بجوار الملف)
  AMANAH_PORT / PORT  المنفذ
  AMANAH_IDLE         خمول الجلسة بالثواني (900)
  AMANAH_BACKUP_EVERY أقل فاصل بين النسخ التلقائية بالثواني (600)
  AMANAH_BACKUP_KEEP  عدد النسخ المحفوظة (150)
  AMANAH_SECURE=1     إجبار علامة Secure على الكوكي (تلقائي عند HTTPS)
  AMANAH_TRUST_PROXY=1 الوثوق بعنوان IP القادم من وسيط (Cloudflare/nginx)

الترقية من v5: ضع state.json و users.json داخل مجلد data وشغّل الخادم — يُنقلان تلقائيًا ويُتحقق من تطابقهما.
"""
import argparse, hashlib, hmac, json, os, secrets, socket, sqlite3, sys, threading, time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('AMANAH_DATA', BASE / 'data'))
DB_PATH = DATA / 'amanah.db'
BACKUPS = DATA / 'backups'
LEGACY_STATE, LEGACY_USERS = DATA / 'state.json', DATA / 'users.json'

STATIC = {'/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js',
          '/auth.js': 'auth.js', '/style.css': 'style.css',
          '/logo.js': 'logo.js', '/logo.png': 'logo.png'}
MIME = {'.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8', '.png': 'image/png'}
ROLES = {'admin': 'مدير', 'accountant': 'محاسب', 'viewer': 'مشاهدة'}
PERMS = {'admin': {'write', 'backup', 'restore', 'users'}, 'accountant': {'write', 'backup'}, 'viewer': set()}

IDLE = int(os.environ.get('AMANAH_IDLE', 15 * 60))
BACKUP_EVERY = int(os.environ.get('AMANAH_BACKUP_EVERY', 600))
BACKUP_KEEP = int(os.environ.get('AMANAH_BACKUP_KEEP', 150))
ITER, MIN_PW, MAX_FAILS, LOCK_SECS = 200_000, 6, 5, 60
IP_MAX_FAILS, IP_LOCK_SECS = 20, 300          # حد عام لكل عنوان IP عبر كل أسماء المستخدمين
MAX_BODY = 30 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  salt TEXT NOT NULL, hash TEXT NOT NULL, iter INTEGER NOT NULL,
  created_at TEXT, last_login TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid TEXT NOT NULL, last REAL NOT NULL);
CREATE TABLE IF NOT EXISTS login_fails(ip TEXT NOT NULL, username TEXT NOT NULL, n INTEGER NOT NULL, until REAL NOT NULL,
  PRIMARY KEY(ip, username));
CREATE TABLE IF NOT EXISTS collections(name TEXT PRIMARY KEY, kind TEXT NOT NULL, pos INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(
  coll TEXT NOT NULL, k TEXT NOT NULL, pos INTEGER NOT NULL, data TEXT NOT NULL, h TEXT NOT NULL,
  PRIMARY KEY(coll, k)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS records_order ON records(coll, pos);
"""

_init_lock = threading.Lock()
_ready = False


class ApiError(Exception):
    def __init__(self, code, msg, **more):
        super().__init__(msg)
        self.code, self.body = code, {'error': msg, **more}


# ---------- قاعدة البيانات ----------
def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    c.row_factory = sqlite3.Row
    try:
        c.execute('PRAGMA journal_mode=WAL')
    except sqlite3.DatabaseError:
        pass
    c.execute('PRAGMA synchronous=NORMAL')
    return c


def meta_get(c, key, default=None):
    r = c.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return r['value'] if r and r['value'] is not None else default


def meta_set(c, key, value):
    c.execute('INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)', (key, None if value is None else str(value)))


def ensure_ready():
    global _ready
    if _ready:
        return
    with _init_lock:
        if _ready:
            return
        c = connect()
        try:
            c.executescript(SCHEMA)
            c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('rev', '0')")
            c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema', '1')")
            if LEGACY_STATE.exists() or LEGACY_USERS.exists():
                import_legacy(c, LEGACY_STATE, LEGACY_USERS)
        finally:
            c.close()
        _ready = True


def _hash_row(data):
    return hashlib.sha1(data.encode('utf-8')).hexdigest()


def flatten(state):
    """يحوّل state إلى صفوف: كل عنصر في كل مصفوفة/قاموس صف مستقل في جدول records."""
    colls, rows = [], {}
    for ci, (name, val) in enumerate(state.items()):
        name = str(name)
        if isinstance(val, list):
            kind, items, seen = 'array', [], set()
            for i, item in enumerate(val):
                rid = item.get('id') if isinstance(item, dict) else None
                k = str(rid) if isinstance(rid, (str, int)) and not isinstance(rid, bool) else f'#{i}'
                if k in seen:
                    k = f'#{i}'
                while k in seen:
                    k += '_'
                seen.add(k)
                items.append((k, item))
        elif isinstance(val, dict):
            kind, items = 'object', [(str(k), v) for k, v in val.items()]
        else:
            kind, items = 'value', [('_', val)]
        colls.append((name, kind, ci))
        for pos, (k, v) in enumerate(items):
            data = json.dumps(v, ensure_ascii=False, separators=(',', ':'))
            rows[(name, k)] = (pos, data, _hash_row(data))
    return colls, rows


def _read_state(c):
    base = {'rev': int(meta_get(c, 'rev', '0')), 'updatedAt': meta_get(c, 'updated_at'),
            'updatedBy': meta_get(c, 'updated_by'), 'state': None}
    if meta_get(c, 'has_state') != '1':
        return base
    kinds = {r['name']: r['kind'] for r in c.execute('SELECT name, kind FROM collections ORDER BY pos')}
    out = {n: ([] if k == 'array' else {} if k == 'object' else None) for n, k in kinds.items()}
    for r in c.execute('SELECT coll, k, data FROM records ORDER BY coll, pos'):
        v, kd = json.loads(r['data']), kinds.get(r['coll'])
        if kd == 'array':
            out[r['coll']].append(v)
        elif kd == 'object':
            out[r['coll']][r['k']] = v
        elif kd == 'value':
            out[r['coll']] = v
    base['state'] = out
    return base


def load_state(c):
    c.execute('BEGIN')
    try:
        return _read_state(c)
    finally:
        c.execute('COMMIT')


def _write_state(c, st, rev, by, at):
    """يكتب الفروق فقط (الصفوف التي تغيّرت). يُستدعى داخل معاملة مفتوحة."""
    colls, rows = flatten(st)
    old = {(r['coll'], r['k']): (r['pos'], r['h']) for r in c.execute('SELECT coll, k, pos, h FROM records')}
    for key in old.keys() - rows.keys():
        c.execute('DELETE FROM records WHERE coll=? AND k=?', key)
    for key, (pos, data, h) in rows.items():
        if old.get(key) != (pos, h):
            c.execute('INSERT OR REPLACE INTO records(coll, k, pos, data, h) VALUES(?,?,?,?,?)', (key[0], key[1], pos, data, h))
    c.execute('DELETE FROM collections')
    c.executemany('INSERT INTO collections(name, kind, pos) VALUES(?,?,?)', colls)
    meta_set(c, 'rev', rev)
    meta_set(c, 'updated_at', at)
    meta_set(c, 'updated_by', by)
    meta_set(c, 'has_state', '1')


def save_state(c, st, username, base_rev, restore):
    c.execute('BEGIN IMMEDIATE')
    try:
        cur = int(meta_get(c, 'rev', '0'))
        if not restore and base_rev != cur:
            by = meta_get(c, 'updated_by')
            c.execute('ROLLBACK')
            raise ApiError(409, 'تعدّلت البيانات من مستخدم آخر', rev=cur, by=by)
        rev = cur + 1
        _write_state(c, st, rev, username, now_iso())
        c.execute('COMMIT')
        return rev
    except ApiError:
        raise
    except BaseException:
        try:
            c.execute('ROLLBACK')
        except sqlite3.Error:
            pass
        raise


def import_legacy(c, state_path, users_path):
    """ينقل state.json و users.json من v5 إلى SQL ويتحقق أن المحتوى متطابق قبل الاعتماد.
    يعيد ملخصًا، أو None إذا كانت القاعدة تحتوي بيانات سابقة (لا يكتب فوقها)."""
    users = (json.loads(Path(users_path).read_text(encoding='utf-8')).get('users', [])) if Path(users_path).exists() else []
    legacy = json.loads(Path(state_path).read_text(encoding='utf-8')) if Path(state_path).exists() else None
    c.execute('BEGIN IMMEDIATE')
    try:
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] or meta_get(c, 'has_state') == '1':
            c.execute('ROLLBACK')
            return None
        for u in users:
            cred = u['cred']
            c.execute('INSERT INTO users(id, name, username, role, active, salt, hash, iter, created_at, last_login) VALUES(?,?,?,?,?,?,?,?,?,?)',
                      (u['id'], u['name'], u['username'], u['role'], 1 if u.get('active', True) else 0,
                       cred['salt'], cred['hash'], int(cred['iter']), u.get('createdAt'), u.get('lastLogin')))
        summary = {'users': len(users), 'rev': 0, 'collections': {}}
        if legacy and legacy.get('state') is not None:
            st = legacy['state']
            _write_state(c, st, int(legacy.get('rev', 0)), legacy.get('updatedBy'), legacy.get('updatedAt'))
            back = _read_state(c)
            if back['state'] != st or back['rev'] != int(legacy.get('rev', 0)):
                raise RuntimeError('فشل التحقق: البيانات بعد النقل لا تطابق الأصل')
            summary['rev'] = back['rev']
            summary['collections'] = {k: (len(v) if isinstance(v, (list, dict)) else 1) for k, v in st.items()}
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0] != len(users):
            raise RuntimeError('فشل التحقق: عدد المستخدمين غير مطابق')
        c.execute('COMMIT')
        return summary
    except BaseException:
        try:
            c.execute('ROLLBACK')
        except sqlite3.Error:
            pass
        raise


def make_backup(force=False):
    """نسخة احتياطية متسقة بواجهة SQLite الرسمية (آمنة أثناء الكتابة)."""
    if not DB_PATH.exists():
        return
    BACKUPS.mkdir(parents=True, exist_ok=True)
    files = sorted(BACKUPS.glob('amanah_*.db'))
    if not force and files and time.time() - files[-1].stat().st_mtime < BACKUP_EVERY:
        return
    name = f"amanah_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    tmp = BACKUPS / (name + '.tmp')
    src, dst = connect(), sqlite3.connect(str(tmp))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.replace(tmp, BACKUPS / name)
    for old in sorted(BACKUPS.glob('amanah_*.db'))[:-BACKUP_KEEP]:
        try:
            old.unlink()
        except OSError:
            pass


def now_iso():
    return datetime.now().isoformat()


# ---------- كلمات المرور والجلسات ----------
def hash_pw(pw, salt, iters=ITER):
    return hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, iters).hex()


def make_cred(pw):
    salt = secrets.token_bytes(16)
    return {'salt': salt.hex(), 'hash': hash_pw(pw, salt), 'iter': ITER}


def check_pw(u, pw):
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(u['salt']), u['iter']), u['hash'])


def public(u):
    return {'id': u['id'], 'name': u['name'], 'username': u['username'], 'role': u['role'],
            'active': bool(u['active']), 'lastLogin': u['last_login'], 'createdAt': u['created_at']}


def valid_username(s):
    return isinstance(s, str) and 3 <= len(s) <= 30 and not any(ch.isspace() for ch in s)


def active_admin_count(c):
    return c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]


def cookie_token(headers):
    for part in (headers.get('cookie') or '').split(';'):
        k, _, v = part.strip().partition('=')
        if k == 'amanah_sid':
            return v
    return None


def tok_hash(tok):
    return hashlib.sha256(tok.encode('utf-8')).hexdigest()


def cookie_header(value, secure, clear=False):
    s = f'amanah_sid={value}; Path=/; HttpOnly; SameSite=Strict'
    if clear:
        s = 'amanah_sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'
    return {'Set-Cookie': s + ('; Secure' if secure else '')}


def start_session(c, uid, secure):
    tok = secrets.token_urlsafe(32)
    c.execute('INSERT INTO sessions(token, uid, last) VALUES(?,?,?)', (tok_hash(tok), uid, time.time()))
    return cookie_header(tok, secure)


def session_user(c, headers, touch=True):
    tok = cookie_token(headers)
    if not tok:
        return None
    th, now = tok_hash(tok), time.time()
    r = c.execute('SELECT s.last AS s_last, u.* FROM sessions s JOIN users u ON u.id = s.uid WHERE s.token=?', (th,)).fetchone()
    if not r:
        return None
    if now - r['s_last'] > IDLE or not r['active']:
        c.execute('DELETE FROM sessions WHERE token=?', (th,))
        return None
    if touch:
        c.execute('UPDATE sessions SET last=? WHERE token=?', (now, th))
    return r


def need(c, headers, perm=None, touch=True):
    u = session_user(c, headers, touch)
    if not u:
        raise ApiError(401, 'سجّل الدخول أولًا')
    if perm and perm not in PERMS.get(u['role'], set()):
        raise ApiError(403, 'لا تملك الصلاحية لهذه العملية')
    return u


# ---------- واجهة API ----------
def api_route(c, method, path, d, headers, ip, secure):
    if path == '/api/health' and method == 'GET':
        c.execute('SELECT 1').fetchone()
        return 200, {'ok': True}, None
    if path == '/api/status' and method == 'GET':
        u = session_user(c, headers, touch=False)
        return 200, {'setup': c.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0, 'user': public(u) if u else None}, None
    if path == '/api/setup' and method == 'POST':
        return first_setup(c, d, secure)
    if path == '/api/login' and method == 'POST':
        return login(c, d, ip, secure)
    if path == '/api/logout' and method == 'POST':
        tok = cookie_token(headers)
        if tok:
            c.execute('DELETE FROM sessions WHERE token=?', (tok_hash(tok),))
        return 200, {'ok': True}, cookie_header('', secure, clear=True)
    if path == '/api/ping' and method == 'POST':
        need(c, headers)
        return 200, {'ok': True}, None
    if path == '/api/rev' and method == 'GET':
        need(c, headers, touch=False)
        return 200, {'rev': int(meta_get(c, 'rev', '0')), 'by': meta_get(c, 'updated_by'), 'at': meta_get(c, 'updated_at')}, None
    if path == '/api/state' and method == 'GET':
        need(c, headers)
        st = load_state(c)
        return 200, {'rev': st['rev'], 'state': st['state']}, None
    if path == '/api/state' and method == 'PUT':
        return put_state(c, d, headers)
    if path == '/api/password' and method == 'POST':
        return change_password(c, d, headers)
    if path == '/api/users' and method == 'GET':
        need(c, headers, 'users')
        return 200, {'users': [public(u) for u in c.execute('SELECT * FROM users ORDER BY created_at, username')]}, None
    if path == '/api/users' and method == 'POST':
        return add_user(c, d, headers)
    if path.startswith('/api/users/') and method in ('PATCH', 'DELETE'):
        return user_item(c, method, path.rsplit('/', 1)[1], d, headers)
    raise ApiError(404, 'غير موجود')


def first_setup(c, d, secure):
    name, username, pw = str(d.get('name', '')).strip(), str(d.get('username', '')).strip().lower(), str(d.get('password', ''))
    if not name:
        raise ApiError(400, 'أدخل الاسم')
    if not valid_username(username):
        raise ApiError(400, 'اسم المستخدم من 3 إلى 30 حرفًا بدون مسافات')
    if len(pw) < MIN_PW:
        raise ApiError(400, f'كلمة المرور لا تقل عن {MIN_PW} أحرف')
    cred, uid, now = make_cred(pw), 'USR-' + secrets.token_hex(5), now_iso()
    c.execute('BEGIN IMMEDIATE')
    try:
        if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]:
            c.execute('ROLLBACK')
            raise ApiError(409, 'تم إنشاء المدير مسبقًا')
        c.execute('INSERT INTO users(id, name, username, role, active, salt, hash, iter, created_at, last_login) VALUES(?,?,?,?,?,?,?,?,?,?)',
                  (uid, name, username, 'admin', 1, cred['salt'], cred['hash'], cred['iter'], now, now))
        c.execute('COMMIT')
    except ApiError:
        raise
    except BaseException:
        c.execute('ROLLBACK')
        raise
    u = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    return 200, {'user': public(u)}, start_session(c, uid, secure)


def _fail_row(c, ip, name):
    r = c.execute('SELECT n, until FROM login_fails WHERE ip=? AND username=?', (ip, name)).fetchone()
    return (r['n'], r['until']) if r else (0, 0.0)


def _bump_fail(c, ip, name, limit, lock, now):
    n, _ = _fail_row(c, ip, name)
    n, until = n + 1, 0.0
    if n >= limit:
        n, until = 0, now + lock
    c.execute('INSERT OR REPLACE INTO login_fails(ip, username, n, until) VALUES(?,?,?,?)', (ip, name, n, until))


def login(c, d, ip, secure):
    username, pw = str(d.get('username', '')).strip().lower(), str(d.get('password', ''))
    u = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    ukey, now = (username if u else '*'), time.time()
    u_until, ip_until = _fail_row(c, ip, ukey)[1], _fail_row(c, ip, '#ip')[1]
    if u_until > now or ip_until > now:
        if ip_until <= now:  # المحاولات أثناء القفل تُحتسب على الـ IP أيضًا
            _bump_fail(c, ip, '#ip', IP_MAX_FAILS, IP_LOCK_SECS, now)
        raise ApiError(429, f'محاولات كثيرة. انتظر {int(max(u_until, ip_until) - now) + 1} ثانية')
    ok = bool(u and u['active'] and check_pw(u, pw))
    if not (u and u['active']):
        hash_pw(pw, b'\0' * 16)  # موازنة الزمن
    if not ok:
        _bump_fail(c, ip, ukey, MAX_FAILS, LOCK_SECS, now)
        _bump_fail(c, ip, '#ip', IP_MAX_FAILS, IP_LOCK_SECS, now)
        raise ApiError(401, 'هذا الحساب موقوف. راجع المدير.' if (u and not u['active']) else 'اسم المستخدم أو كلمة المرور غير صحيحة')
    c.execute('DELETE FROM login_fails WHERE ip=? AND username=?', (ip, ukey))
    c.execute('DELETE FROM login_fails WHERE n=0 AND until<?', (now,))
    c.execute('DELETE FROM sessions WHERE last<?', (now - IDLE,))
    c.execute('UPDATE users SET last_login=? WHERE id=?', (now_iso(), u['id']))
    u = c.execute('SELECT * FROM users WHERE id=?', (u['id'],)).fetchone()
    return 200, {'user': public(u)}, start_session(c, u['id'], secure)


def put_state(c, d, headers):
    u = need(c, headers, 'write')
    st = d.get('state')
    if not isinstance(st, dict) or not isinstance(st.get('companies'), list) or not isinstance(st.get('employees'), list):
        raise ApiError(400, 'بيانات غير صالحة')
    restore = bool(d.get('restore'))
    if restore and 'restore' not in PERMS[u['role']]:
        raise ApiError(403, 'الاسترجاع للمدير فقط')
    if restore:
        make_backup(force=True)
    rev = save_state(c, st, u['username'], d.get('baseRev'), restore)
    make_backup()
    return 200, {'rev': rev}, None


def change_password(c, d, headers):
    u = need(c, headers)
    new = str(d.get('new', ''))
    if len(new) < MIN_PW:
        raise ApiError(400, f'كلمة المرور الجديدة لا تقل عن {MIN_PW} أحرف')
    if not check_pw(u, str(d.get('old', ''))):
        raise ApiError(400, 'كلمة المرور الحالية غير صحيحة')
    cred = make_cred(new)
    c.execute('UPDATE users SET salt=?, hash=?, iter=? WHERE id=?', (cred['salt'], cred['hash'], cred['iter'], u['id']))
    return 200, {'ok': True}, None


def add_user(c, d, headers):
    need(c, headers, 'users')
    name, username, pw, role = str(d.get('name', '')).strip(), str(d.get('username', '')).strip().lower(), str(d.get('password', '')), d.get('role')
    if not name:
        raise ApiError(400, 'أدخل الاسم')
    if not valid_username(username):
        raise ApiError(400, 'اسم المستخدم من 3 إلى 30 حرفًا بدون مسافات')
    if role not in ROLES:
        raise ApiError(400, 'دور غير صالح')
    if len(pw) < MIN_PW:
        raise ApiError(400, f'كلمة المرور لا تقل عن {MIN_PW} أحرف')
    cred = make_cred(pw)
    try:
        c.execute('INSERT INTO users(id, name, username, role, active, salt, hash, iter, created_at, last_login) VALUES(?,?,?,?,?,?,?,?,?,?)',
                  ('USR-' + secrets.token_hex(5), name, username, role, 1, cred['salt'], cred['hash'], cred['iter'], now_iso(), None))
    except sqlite3.IntegrityError:
        raise ApiError(409, 'اسم المستخدم مستخدم من قبل')
    return 200, {'ok': True}, None


def user_item(c, method, uid, d, headers):
    me = need(c, headers, 'users')
    u = c.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not u:
        raise ApiError(404, 'المستخدم غير موجود')
    if method == 'DELETE':
        if uid == me['id']:
            raise ApiError(400, 'لا يمكنك حذف حسابك')
        if u['role'] == 'admin' and active_admin_count(c) <= 1:
            raise ApiError(400, 'لا يمكن حذف آخر مدير')
        c.execute('DELETE FROM sessions WHERE uid=?', (uid,))
        c.execute('DELETE FROM users WHERE id=?', (uid,))
        return 200, {'ok': True}, None
    role, active = d.get('role', u['role']), bool(d.get('active', bool(u['active'])))
    if role not in ROLES:
        raise ApiError(400, 'دور غير صالح')
    if u['role'] == 'admin' and (role != 'admin' or not active) and active_admin_count(c) <= 1:
        raise ApiError(400, 'لا يمكن إيقاف أو تخفيض آخر مدير')
    if uid == me['id'] and not active:
        raise ApiError(400, 'لا يمكنك إيقاف حسابك')
    if d.get('password'):
        if len(str(d['password'])) < MIN_PW:
            raise ApiError(400, f'كلمة المرور لا تقل عن {MIN_PW} أحرف')
        cred = make_cred(str(d['password']))
        c.execute('UPDATE users SET salt=?, hash=?, iter=? WHERE id=?', (cred['salt'], cred['hash'], cred['iter'], uid))
    name = str(d.get('name', '')).strip() or u['name']
    c.execute('UPDATE users SET name=?, role=?, active=? WHERE id=?', (name, role, 1 if active else 0, uid))
    if not active:
        c.execute('DELETE FROM sessions WHERE uid=?', (uid,))
    return 200, {'ok': True}, None


# ---------- طبقة HTTP المشتركة (تخدم http.server و WSGI) ----------
def sec_headers(secure):
    h = {'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
         'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                                    "connect-src 'self'; frame-ancestors 'none'"}
    if secure:
        h['Strict-Transport-Security'] = 'max-age=31536000'
    return h


def json_resp(code, obj, secure, extra=None):
    h = {**sec_headers(secure), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', **(extra or {})}
    return code, h, json.dumps(obj, ensure_ascii=False).encode('utf-8')


def client_ip(headers, peer):
    if peer in ('127.0.0.1', '::1') or os.environ.get('AMANAH_TRUST_PROXY') == '1':
        v = headers.get('cf-connecting-ip') or (headers.get('x-forwarded-for') or '').split(',')[0].strip()
        if v:
            return v
    return peer


def handle(method, target, headers, body, peer):
    """(code, headers, bytes). headers: مفاتيح بحروف صغيرة."""
    secure = (headers.get('x-forwarded-proto') or '').split(',')[0].strip() == 'https' or os.environ.get('AMANAH_SECURE') == '1'
    try:
        path = urlparse(target).path
        if path.startswith('/api/'):
            if method != 'GET' and headers.get('x-requested-with') != 'amanah':
                raise ApiError(403, 'طلب مرفوض')
            d = {}
            if method in ('POST', 'PUT', 'PATCH') and body:
                try:
                    d = json.loads(body.decode('utf-8'))
                except (ValueError, UnicodeDecodeError):
                    raise ApiError(400, 'بيانات غير صالحة')
            if not isinstance(d, dict):
                raise ApiError(400, 'بيانات غير صالحة')
            ensure_ready()
            c = connect()
            try:
                code, obj, extra = api_route(c, method, path, d, headers, client_ip(headers, peer), secure)
            finally:
                c.close()
            return json_resp(code, obj, secure, extra)
        if method not in ('GET', 'HEAD'):
            raise ApiError(405, 'غير مسموح')
        name = STATIC.get(path)
        if not name:
            return 404, {**sec_headers(secure), 'Content-Type': 'text/plain; charset=utf-8'}, b'Not found'
        p = BASE / name
        return 200, {**sec_headers(secure), 'Content-Type': MIME[p.suffix], 'Cache-Control': 'no-cache'}, p.read_bytes()
    except ApiError as e:
        return json_resp(e.code, e.body, secure)
    except Exception as e:  # noqa
        sys.stderr.write(f'خطأ: {e!r}\n')
        return json_resp(500, {'error': 'خطأ في الخادم'}, secure)


# ---------- WSGI (cPanel / Passenger / gunicorn) ----------
def application(environ, start_response):
    method = environ.get('REQUEST_METHOD', 'GET').upper()
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
    except ValueError:
        n = 0
    if n > MAX_BODY:
        code, hdrs, payload = json_resp(413, {'error': 'الحجم كبير جدًا'}, False)
    else:
        body = environ['wsgi.input'].read(n) if n else b''
        headers = {k[5:].replace('_', '-').lower(): v for k, v in environ.items() if k.startswith('HTTP_')}
        headers.setdefault('x-forwarded-proto', environ.get('wsgi.url_scheme', 'http'))
        code, hdrs, payload = handle(method, environ.get('PATH_INFO', '/') or '/', headers, body, environ.get('REMOTE_ADDR', '0.0.0.0'))
    out = list(hdrs.items()) + [('Content-Length', str(len(payload)))]
    start_response(f'{code} {HTTPStatus(code).phrase}', out)
    return [b'' if method == 'HEAD' else payload]


# ---------- خادم مستقل ----------
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'AmanahGuard'

    def log_message(self, fmt, *args):
        if os.environ.get('AMANAH_VERBOSE'):
            sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))

    def _serve(self, method):
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if n > MAX_BODY:
                code, hdrs, payload = json_resp(413, {'error': 'الحجم كبير جدًا'}, False, {'Connection': 'close'})
                self.close_connection = True
            else:
                body = self.rfile.read(n) if n else b''
                headers = {k.lower(): v for k, v in self.headers.items()}
                code, hdrs, payload = handle(method, self.path, headers, body, self.client_address[0])
            self.send_response(code)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            if method != 'HEAD':
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self): self._serve('GET')
    def do_HEAD(self): self._serve('HEAD')
    def do_POST(self): self._serve('POST')
    def do_PUT(self): self._serve('PUT')
    def do_PATCH(self): self._serve('PATCH')
    def do_DELETE(self): self._serve('DELETE')


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default=None)
    ap.add_argument('--port', type=int, default=int(os.environ.get('AMANAH_PORT') or os.environ.get('PORT') or 8765))
    ap.add_argument('--local', action='store_true', help='هذا الجهاز فقط')
    a = ap.parse_args()
    host = a.host or ('127.0.0.1' if a.local else '0.0.0.0')
    ensure_ready()
    srv = ThreadingHTTPServer((host, a.port), Handler)
    srv.daemon_threads = True
    print('خادم مؤسسة الأمانة (SQL) يعمل. أغلق هذه النافذة لإيقافه.')
    print(f'من هذا الجهاز:   http://127.0.0.1:{a.port}/')
    if host == '0.0.0.0':
        ip = lan_ip()
        if ip:
            print(f'من أجهزة المكتب: http://{ip}:{a.port}/')
    print(f'قاعدة البيانات:  {DB_PATH}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
