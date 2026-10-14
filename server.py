#!/usr/bin/env python3
"""خادم مؤسسة الأمانة — يحفظ البيانات في ملف على هذا الجهاز ويشاركها بين أجهزة المكتب.
لا يحتاج أي مكتبات خارجية (Python 3.8+ فقط).

  python server.py              ← يعمل على شبكة المكتب (0.0.0.0:8765)
  python server.py --local      ← لهذا الجهاز فقط (127.0.0.1)
  python server.py --port 9000  ← منفذ آخر

ملفات البيانات في المجلد data/ (state.json, users.json, backups/) — انسخه دوريًا.
"""
import argparse, hashlib, hmac, json, os, secrets, shutil, socket, sys, threading, time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get('AMANAH_DATA', BASE / 'data'))
BACKUPS = DATA / 'backups'
STATE_FILE, USERS_FILE = DATA / 'state.json', DATA / 'users.json'

STATIC = {'/': 'index.html', '/index.html': 'index.html', '/app.js': 'app.js',
          '/auth.js': 'auth.js', '/style.css': 'style.css',
          '/logo.js': 'logo.js', '/logo.png': 'logo.png'}
MIME = {'.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
        '.css': 'text/css; charset=utf-8', '.png': 'image/png'}
ROLES = {'admin': 'مدير', 'accountant': 'محاسب', 'viewer': 'مشاهدة'}
PERMS = {'admin': {'write', 'backup', 'restore', 'users'}, 'accountant': {'write', 'backup'}, 'viewer': set()}

IDLE = int(os.environ.get('AMANAH_IDLE', 15 * 60))        # خمول الجلسة بالثواني
BACKUP_EVERY = int(os.environ.get('AMANAH_BACKUP_EVERY', 600))  # نسخة تلقائية كل 10 دقائق عند وجود تعديل
BACKUP_KEEP = 150
ITER, MIN_PW, MAX_FAILS, LOCK_SECS = 200_000, 6, 5, 60
MAX_BODY = 30 * 1024 * 1024

LOCK = threading.RLock()
SESSIONS = {}      # token -> {'uid':..., 'last':...}
FAILS = {}         # (ip, username) -> {'n':..., 'until':...}
_last_backup = [0.0]


# ---------- تخزين ----------
def read_json(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_users():
    return read_json(USERS_FILE, {'users': []})


def load_state():
    return read_json(STATE_FILE, {'rev': 0, 'updatedAt': None, 'updatedBy': None, 'state': None})


def make_backup(force=False):
    if not STATE_FILE.exists():
        return
    now = time.time()
    if not force and now - _last_backup[0] < BACKUP_EVERY:
        return
    BACKUPS.mkdir(parents=True, exist_ok=True)
    name = f"state_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    shutil.copy2(STATE_FILE, BACKUPS / name)
    if USERS_FILE.exists():
        shutil.copy2(USERS_FILE, BACKUPS / name.replace('state_', 'users_'))
    _last_backup[0] = now
    for prefix in ('state_', 'users_'):
        files = sorted(BACKUPS.glob(prefix + '*.json'))
        for old in files[:-BACKUP_KEEP]:
            try:
                old.unlink()
            except OSError:
                pass


# ---------- كلمات المرور ----------
def hash_pw(pw, salt, iters=ITER):
    return hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), salt, iters).hex()


def make_cred(pw):
    salt = secrets.token_bytes(16)
    return {'salt': salt.hex(), 'hash': hash_pw(pw, salt), 'iter': ITER}


def check_pw(user, pw):
    return hmac.compare_digest(hash_pw(pw, bytes.fromhex(user['cred']['salt']), user['cred']['iter']), user['cred']['hash'])


def public(u):
    return {k: u.get(k) for k in ('id', 'name', 'username', 'role', 'active', 'lastLogin', 'createdAt')}


def valid_username(s):
    return isinstance(s, str) and 3 <= len(s) <= 30 and not any(c.isspace() for c in s)


def active_admins(users):
    return [u for u in users if u['role'] == 'admin' and u['active']]


# ---------- المعالج ----------
class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'AmanahGuard'

    def log_message(self, fmt, *args):
        if os.environ.get('AMANAH_VERBOSE'):
            sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))

    # --- مساعدات ---
    def _headers(self, code, ctype, length, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(length))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                         "connect-src 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def send_json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        h = {'Cache-Control': 'no-store'}
        h.update(extra or {})
        self._headers(code, 'application/json; charset=utf-8', len(body), h)
        self.wfile.write(body)

    def err(self, code, msg, **more):
        self.send_json(code, {'error': msg, **more})

    def read_body(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > MAX_BODY:
            return None, 'الحجم كبير جدًا'
        raw = self.rfile.read(n) if n else b''
        if not raw:
            return {}, None
        try:
            data = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return None, 'بيانات غير صالحة'
        return data, None

    def cookie_token(self):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'amanah_sid':
                return v
        return None

    def session_user(self, touch=True):
        tok = self.cookie_token()
        with LOCK:
            s = SESSIONS.get(tok) if tok else None
            if not s:
                return None
            now = time.time()
            if now - s['last'] > IDLE:
                SESSIONS.pop(tok, None)
                return None
            u = next((x for x in load_users()['users'] if x['id'] == s['uid'] and x['active']), None)
            if not u:
                SESSIONS.pop(tok, None)
                return None
            if touch:
                s['last'] = now
            return u

    def need(self, perm=None, touch=True):
        u = self.session_user(touch)
        if not u:
            self.err(401, 'سجّل الدخول أولًا')
            return None
        if perm and perm not in PERMS.get(u['role'], set()):
            self.err(403, 'لا تملك الصلاحية لهذه العملية')
            return None
        return u

    def start_session(self, user):
        tok = secrets.token_urlsafe(32)
        with LOCK:
            SESSIONS[tok] = {'uid': user['id'], 'last': time.time()}
        return {'Set-Cookie': f'amanah_sid={tok}; Path=/; HttpOnly; SameSite=Strict'}

    # --- التوجيه ---
    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    def do_PUT(self):
        self.route('PUT')

    def do_PATCH(self):
        self.route('PATCH')

    def do_DELETE(self):
        self.route('DELETE')

    def route(self, method):
        try:
            path = urlparse(self.path).path
            if path.startswith('/api/'):
                if method != 'GET' and self.headers.get('X-Requested-With') != 'amanah':
                    return self.err(403, 'طلب مرفوض')
                return self.api(method, path)
            if method != 'GET':
                return self.err(405, 'غير مسموح')
            return self.static(path)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # noqa
            sys.stderr.write(f'خطأ: {e!r}\n')
            try:
                self.err(500, 'خطأ في الخادم')
            except Exception:
                pass

    def static(self, path):
        name = STATIC.get(path)
        if not name:
            body = b'Not found'
            return self._headers(404, 'text/plain; charset=utf-8', len(body)) or self.wfile.write(body)
        p = BASE / name
        body = p.read_bytes()
        self._headers(200, MIME[p.suffix], len(body), {'Cache-Control': 'no-cache'})
        self.wfile.write(body)

    # --- API ---
    def api(self, method, path):
        if method in ('POST', 'PUT', 'PATCH'):
            data, e = self.read_body()
            if e:
                return self.err(400, e)
        else:
            data = {}
        if not isinstance(data, dict):
            return self.err(400, 'بيانات غير صالحة')

        if path == '/api/status' and method == 'GET':
            u = self.session_user(touch=False)
            return self.send_json(200, {'setup': not load_users()['users'], 'user': public(u) if u else None})
        if path == '/api/setup' and method == 'POST':
            return self.first_setup(data)
        if path == '/api/login' and method == 'POST':
            return self.login(data)
        if path == '/api/logout' and method == 'POST':
            tok = self.cookie_token()
            with LOCK:
                SESSIONS.pop(tok, None)
            return self.send_json(200, {'ok': True}, {'Set-Cookie': 'amanah_sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict'})
        if path == '/api/ping' and method == 'POST':
            return self.send_json(200, {'ok': True}) if self.need() else None
        if path == '/api/rev' and method == 'GET':
            if not self.need(touch=False):
                return
            st = load_state()
            return self.send_json(200, {'rev': st['rev'], 'by': st.get('updatedBy'), 'at': st.get('updatedAt')})
        if path == '/api/state' and method == 'GET':
            if not self.need():
                return
            st = load_state()
            return self.send_json(200, {'rev': st['rev'], 'state': st['state']})
        if path == '/api/state' and method == 'PUT':
            return self.put_state(data)
        if path == '/api/password' and method == 'POST':
            return self.change_password(data)
        if path == '/api/users' and method == 'GET':
            if not self.need('users'):
                return
            return self.send_json(200, {'users': [public(u) for u in load_users()['users']]})
        if path == '/api/users' and method == 'POST':
            return self.add_user(data)
        if path.startswith('/api/users/') and method in ('PATCH', 'DELETE'):
            return self.user_item(method, path.rsplit('/', 1)[1], data)
        return self.err(404, 'غير موجود')

    def first_setup(self, d):
        with LOCK:
            db = load_users()
            if db['users']:
                return self.err(409, 'تم إنشاء المدير مسبقًا')
            name, username, pw = str(d.get('name', '')).strip(), str(d.get('username', '')).strip().lower(), str(d.get('password', ''))
            if not name:
                return self.err(400, 'أدخل الاسم')
            if not valid_username(username):
                return self.err(400, 'اسم المستخدم من 3 إلى 30 حرفًا بدون مسافات')
            if len(pw) < MIN_PW:
                return self.err(400, f'كلمة المرور لا تقل عن {MIN_PW} أحرف')
            u = {'id': 'USR-' + secrets.token_hex(5), 'name': name, 'username': username, 'role': 'admin', 'active': True,
                 'cred': make_cred(pw), 'createdAt': datetime.now().isoformat(), 'lastLogin': datetime.now().isoformat()}
            db['users'].append(u)
            write_json(USERS_FILE, db)
        self.send_json(200, {'user': public(u)}, self.start_session(u))

    def login(self, d):
        ip = self.client_address[0]
        username, pw = str(d.get('username', '')).strip().lower(), str(d.get('password', ''))
        with LOCK:
            db = load_users()
            u = next((x for x in db['users'] if x['username'] == username), None)
            key = (ip, username if u else '*')
            f = FAILS.get(key, {'n': 0, 'until': 0})
            now = time.time()
            if f['until'] > now:
                return self.err(429, f"محاولات كثيرة. انتظر {int(f['until'] - now) + 1} ثانية")
            ok = bool(u and u['active'] and check_pw(u, pw))
            if not (u and u['active']):
                hash_pw(pw, b'\0' * 16)  # موازنة الزمن
            if not ok:
                f['n'] += 1
                if f['n'] >= MAX_FAILS:
                    f = {'n': 0, 'until': now + LOCK_SECS}
                FAILS[key] = f
                msg = 'هذا الحساب موقوف. راجع المدير.' if (u and not u['active']) else 'اسم المستخدم أو كلمة المرور غير صحيحة'
                return self.err(401, msg)
            FAILS.pop(key, None)
            u['lastLogin'] = datetime.now().isoformat()
            write_json(USERS_FILE, db)
        self.send_json(200, {'user': public(u)}, self.start_session(u))

    def put_state(self, d):
        u = self.need('write')
        if not u:
            return
        st = d.get('state')
        if not isinstance(st, dict) or not isinstance(st.get('companies'), list) or not isinstance(st.get('employees'), list):
            return self.err(400, 'بيانات غير صالحة')
        restore = bool(d.get('restore'))
        if restore and 'restore' not in PERMS[u['role']]:
            return self.err(403, 'الاسترجاع للمدير فقط')
        with LOCK:
            cur = load_state()
            if not restore and d.get('baseRev') != cur['rev']:
                return self.err(409, 'تعدّلت البيانات من مستخدم آخر', rev=cur['rev'], by=cur.get('updatedBy'))
            if restore:
                make_backup(force=True)
            rev = cur['rev'] + 1
            write_json(STATE_FILE, {'rev': rev, 'updatedAt': datetime.now().isoformat(), 'updatedBy': u['username'], 'state': st})
            make_backup()
        self.send_json(200, {'rev': rev})

    def change_password(self, d):
        u = self.need()
        if not u:
            return
        new = str(d.get('new', ''))
        if len(new) < MIN_PW:
            return self.err(400, f'كلمة المرور الجديدة لا تقل عن {MIN_PW} أحرف')
        with LOCK:
            db = load_users()
            cur = next(x for x in db['users'] if x['id'] == u['id'])
            if not check_pw(cur, str(d.get('old', ''))):
                return self.err(400, 'كلمة المرور الحالية غير صحيحة')
            cur['cred'] = make_cred(new)
            write_json(USERS_FILE, db)
        self.send_json(200, {'ok': True})

    def add_user(self, d):
        if not self.need('users'):
            return
        name, username, pw, role = str(d.get('name', '')).strip(), str(d.get('username', '')).strip().lower(), str(d.get('password', '')), d.get('role')
        if not name:
            return self.err(400, 'أدخل الاسم')
        if not valid_username(username):
            return self.err(400, 'اسم المستخدم من 3 إلى 30 حرفًا بدون مسافات')
        if role not in ROLES:
            return self.err(400, 'دور غير صالح')
        if len(pw) < MIN_PW:
            return self.err(400, f'كلمة المرور لا تقل عن {MIN_PW} أحرف')
        with LOCK:
            db = load_users()
            if any(x['username'] == username for x in db['users']):
                return self.err(409, 'اسم المستخدم مستخدم من قبل')
            db['users'].append({'id': 'USR-' + secrets.token_hex(5), 'name': name, 'username': username, 'role': role, 'active': True,
                                'cred': make_cred(pw), 'createdAt': datetime.now().isoformat(), 'lastLogin': None})
            write_json(USERS_FILE, db)
        self.send_json(200, {'ok': True})

    def user_item(self, method, uid, d):
        me = self.need('users')
        if not me:
            return
        with LOCK:
            db = load_users()
            u = next((x for x in db['users'] if x['id'] == uid), None)
            if not u:
                return self.err(404, 'المستخدم غير موجود')
            if method == 'DELETE':
                if uid == me['id']:
                    return self.err(400, 'لا يمكنك حذف حسابك')
                if u['role'] == 'admin' and len(active_admins(db['users'])) <= 1:
                    return self.err(400, 'لا يمكن حذف آخر مدير')
                db['users'] = [x for x in db['users'] if x['id'] != uid]
            else:
                role = d.get('role', u['role'])
                active = d.get('active', u['active'])
                if role not in ROLES:
                    return self.err(400, 'دور غير صالح')
                if u['role'] == 'admin' and (role != 'admin' or not active) and len(active_admins(db['users'])) <= 1:
                    return self.err(400, 'لا يمكن إيقاف أو تخفيض آخر مدير')
                if uid == me['id'] and not active:
                    return self.err(400, 'لا يمكنك إيقاف حسابك')
                if d.get('password'):
                    if len(str(d['password'])) < MIN_PW:
                        return self.err(400, f'كلمة المرور لا تقل عن {MIN_PW} أحرف')
                    u['cred'] = make_cred(str(d['password']))
                if str(d.get('name', '')).strip():
                    u['name'] = str(d['name']).strip()
                u['role'], u['active'] = role, bool(active)
                if not u['active']:
                    with LOCK:
                        for t in [t for t, s in SESSIONS.items() if s['uid'] == uid]:
                            SESSIONS.pop(t, None)
            write_json(USERS_FILE, db)
        self.send_json(200, {'ok': True})


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
    ap.add_argument('--port', type=int, default=int(os.environ.get('AMANAH_PORT', 8765)))
    ap.add_argument('--local', action='store_true', help='هذا الجهاز فقط')
    a = ap.parse_args()
    host = a.host or ('127.0.0.1' if a.local else '0.0.0.0')
    DATA.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer((host, a.port), Handler)
    srv.daemon_threads = True
    print('خادم مؤسسة الأمانة يعمل. أغلق هذه النافذة لإيقافه.')
    print(f'من هذا الجهاز:   http://127.0.0.1:{a.port}/')
    if host == '0.0.0.0':
        ip = lan_ip()
        if ip:
            print(f'من أجهزة المكتب: http://{ip}:{a.port}/')
    print(f'مجلد البيانات:   {DATA}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
