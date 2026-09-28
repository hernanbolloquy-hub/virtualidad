#!/usr/bin/env python3
"""SAIE virtualidad: Python standard library + SQLite, no external packages."""
import base64, hashlib, hmac, json, os, secrets, sqlite3, smtplib, ssl, threading
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB = Path(os.getenv('SAIE_DB', str(ROOT / 'data' / 'saie.sqlite3')))
DB.parent.mkdir(parents=True, exist_ok=True)
PORT = int(os.getenv('PORT', '8080'))
COOKIE_SECURE = os.getenv('SAIE_HTTPS', '1') != '0'
ADMIN_USER = os.getenv('SAIE_ADMIN_USER', 'admin').strip().lower()
ADMIN_PASSWORD = os.getenv('SAIE_ADMIN_PASSWORD', '')
AREAS = {'Psicopedagogía', 'Psicología', 'Educación Especial', 'Trabajo Social'}
EQUIPOS = {'Equipo 1', 'Equipo 2', 'Equipo 3', 'Equipo 4'}
LOCK = threading.Lock()

def connect():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=20000')
    return db

def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 350000)
    return base64.b64encode(salt).decode() + ':' + base64.b64encode(key).decode()

def password_ok(password, stored):
    try:
        salt, key = stored.split(':')
        actual = password_hash(password, base64.b64decode(salt)).split(':')[1]
        return hmac.compare_digest(actual, key)
    except (ValueError, TypeError):
        return False

def init():
    if len(ADMIN_PASSWORD) < 12:
        raise SystemExit('Definí SAIE_ADMIN_PASSWORD con al menos 12 caracteres antes de iniciar.')
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','professional')),
          area TEXT, equipo TEXT, email TEXT, recipient TEXT, password_hash TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS tokens(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          expires TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          started TEXT NOT NULL, ended TEXT, resumen TEXT NOT NULL DEFAULT '', acta TEXT NOT NULL DEFAULT '');
        CREATE UNIQUE INDEX IF NOT EXISTS one_active_session ON sessions(user_id) WHERE ended IS NULL;
        ''')
        existing = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        if not existing:
            db.execute('INSERT INTO users(username,name,role,password_hash) VALUES(?,?,?,?)',
                       (ADMIN_USER, 'Administración SAIE', 'admin', password_hash(ADMIN_PASSWORD)))
        db.execute('DELETE FROM tokens WHERE expires < ?', (datetime.now(timezone.utc).isoformat(),))

def now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def rowdict(row): return dict(row) if row else None

def send_notice(user, session):
    host, sender, recipient = os.getenv('SAIE_SMTP_HOST'), os.getenv('SAIE_SMTP_FROM'), user['recipient']
    if not (host and sender and recipient): return 'Correo no configurado'
    msg = EmailMessage()
    msg['From'], msg['To'] = sender, recipient
    msg['Subject'] = 'SAIE: virtualidad finalizada - ' + user['name']
    msg.set_content(f"Profesional: {user['name']}\nÁrea: {user['area']}\nEquipo: {user['equipo']}\nInicio UTC: {session['started']}\nFin UTC: {session['ended']}\n\nResumen:\n{session['resumen']}\n\nActa:\n{session['acta']}")
    port = int(os.getenv('SAIE_SMTP_PORT', '587'))
    try:
        if port == 465:
            smtp = smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=15)
        with smtp:
            if port != 465: smtp.starttls(context=ssl.create_default_context())
            if os.getenv('SAIE_SMTP_USER'):
                smtp.login(os.environ['SAIE_SMTP_USER'], os.environ['SAIE_SMTP_PASSWORD'])
            smtp.send_message(msg)
        return 'Correo enviado'
    except Exception as exc:
        print('Error de correo:', type(exc).__name__, flush=True)
        return 'No se pudo enviar el correo; el registro quedó guardado'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print('%s %s' % (self.address_string(), fmt % args), flush=True)
    def respond(self, status, value, cookie=None):
        data = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        if cookie: self.send_header('Set-Cookie', cookie)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def fail(self, status, message): self.respond(status, {'error':message})
    def body(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1024 * 1024: raise ValueError('El texto supera 1 MB')
        return json.loads(self.rfile.read(length) or b'{}')
    def auth(self, db):
        from http.cookies import SimpleCookie
        cookies = SimpleCookie()
        try: cookies.load(self.headers.get('Cookie', ''))
        except Exception: return None
        item = cookies.get('saie_session')
        if not item: return None
        token_hash = hashlib.sha256(item.value.encode()).hexdigest()
        return db.execute('''SELECT users.* FROM users JOIN tokens ON tokens.user_id=users.id
           WHERE tokens.token_hash=? AND tokens.expires>? AND users.active=1''',
           (token_hash, now())).fetchone()
    def origin_ok(self):
        origin = self.headers.get('Origin')
        if not origin: return True
        host = self.headers.get('Host', '')
        parsed = urlparse(origin)
        return parsed.netloc == host and parsed.scheme in ('http','https')
    def cookie(self, token, clear=False):
        flags = '; HttpOnly; SameSite=Strict; Path=/' + ('; Secure' if COOKIE_SECURE else '')
        return 'saie_session=' + token + ('; Max-Age=0' if clear else '; Max-Age=43200') + flags
    def do_GET(self):
        if self.path == '/':
            data = (ROOT / 'static' / 'index.html').read_bytes()
            self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); return
        if self.path == '/static/app.js':
            data = (ROOT / 'static' / 'app.js').read_bytes()
            self.send_response(200); self.send_header('Content-Type','text/javascript; charset=utf-8')
            self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(data)))
            self.end_headers(); self.wfile.write(data); return
        with connect() as db:
            user = self.auth(db)
            if not user: return self.fail(401, 'Iniciá sesión')
            if self.path == '/api/me':
                return self.respond(200, {'user':dict(user) | {'password_hash':None}})
            if self.path == '/api/users':
                if user['role'] != 'admin': return self.fail(403,'Acceso restringido')
                return self.respond(200, {'users':[dict(x) for x in db.execute('SELECT id,username,name,role,area,equipo,email,recipient,active FROM users ORDER BY name')]})
            if self.path == '/api/sessions':
                query = '''SELECT s.*,u.name,u.area,u.equipo,u.recipient FROM sessions s JOIN users u ON u.id=s.user_id'''
                if user['role'] != 'admin': query += ' WHERE s.user_id=?'; args=(user['id'],)
                else: args=()
                query += ' ORDER BY s.started DESC'
                return self.respond(200, {'sessions':[dict(x) for x in db.execute(query,args)]})
        self.fail(404,'No encontrado')
    def do_POST(self):
        if not self.path.startswith('/api/'): return self.fail(404,'No encontrado')
        if not self.origin_ok(): return self.fail(403,'Origen no autorizado')
        try: data=self.body()
        except (ValueError, json.JSONDecodeError): return self.fail(400,'Datos inválidos')
        with connect() as db:
            user=self.auth(db)
            if self.path == '/api/login':
                username=str(data.get('username','')).strip().lower()
                found=db.execute('SELECT * FROM users WHERE username=? AND active=1',(username,)).fetchone()
                if not found or not password_ok(str(data.get('password','')),found['password_hash']):
                    return self.fail(401,'Usuario o contraseña incorrectos')
                token=secrets.token_urlsafe(32)
                db.execute('INSERT INTO tokens VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),found['id'],(datetime.now(timezone.utc)+timedelta(hours=12)).isoformat()))
                db.commit(); return self.respond(200,{'ok':True},self.cookie(token))
            if not user: return self.fail(401,'Iniciá sesión')
            if self.path == '/api/logout':
                from http.cookies import SimpleCookie
                cookie=SimpleCookie(); cookie.load(self.headers.get('Cookie',''))
                if 'saie_session' in cookie:
                    db.execute('DELETE FROM tokens WHERE token_hash=?',(hashlib.sha256(cookie['saie_session'].value.encode()).hexdigest(),))
                    db.commit()
                return self.respond(200,{'ok':True},self.cookie('',True))
            if self.path == '/api/users':
                if user['role']!='admin': return self.fail(403,'Acceso restringido')
                name=str(data.get('name','')).strip(); username=str(data.get('username','')).strip().lower()
                password=str(data.get('password','')); area=data.get('area'); equipo=data.get('equipo')
                if not name or not username or len(password)<12 or area not in AREAS or equipo not in EQUIPOS:
                    return self.fail(400,'Completá nombre, usuario, área, equipo y contraseña de 12 caracteres o más')
                try:
                    db.execute('INSERT INTO users(username,name,role,area,equipo,email,recipient,password_hash) VALUES(?,?,?,?,?,?,?,?)',
                       (username,name,'professional',area,equipo,str(data.get('email','')).strip(),str(data.get('recipient','')).strip(),password_hash(password)))
                    db.commit(); return self.respond(201,{'ok':True})
                except sqlite3.IntegrityError: return self.fail(409,'Ese usuario ya existe')
            if self.path == '/api/start':
                try:
                    db.execute('INSERT INTO sessions(user_id,started) VALUES(?,?)',(user['id'],now()))
                    db.commit(); return self.respond(201,{'ok':True})
                except sqlite3.IntegrityError: return self.fail(409,'Ya tenés una sesión activa')
            if self.path in ('/api/draft','/api/finish'):
                active=db.execute('SELECT * FROM sessions WHERE user_id=? AND ended IS NULL',(user['id'],)).fetchone()
                if not active: return self.fail(409,'No hay una sesión activa')
                resumen=str(data.get('resumen','')); acta=str(data.get('acta',''))
                if len(resumen)>10000 or len(acta)>500000:return self.fail(400,'Texto demasiado largo')
                if self.path=='/api/draft':
                    db.execute('UPDATE sessions SET resumen=?,acta=? WHERE id=? AND ended IS NULL',(resumen,acta,active['id']))
                    db.commit(); return self.respond(200,{'ok':True})
                ended=now()
                db.execute('UPDATE sessions SET resumen=?,acta=?,ended=? WHERE id=?',(resumen,acta,ended,active['id']))
                db.commit()
                notice=send_notice(user,{'started':active['started'],'ended':ended,'resumen':resumen,'acta':acta})
                return self.respond(200,{'ok':True,'notice':notice})
        self.fail(404,'No encontrado')

if __name__ == '__main__':
    init()
    print(f'SAIE escuchando en puerto {PORT}',flush=True)
    ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
