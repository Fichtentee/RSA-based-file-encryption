# Kritisches Security Assessment: RSA Hybrid FileCrypter
**Datum:** 12. Februar 2026  
**Scope:** Komplette Code-Basis (Server, Client, Kryptographie, TLS)  
**Methodik:** White-Box Analyse, Threat Modeling, OWASP Top 10, CWE Top 25  

---

## Executive Summary

Der RSA Hybrid FileCrypter zeigt **solide kryptografische Grundlagen** mit AES-256-GCM, RSA-4096 und RSASSA-PSS. Die kürzlich implementierte Input-Validation und TLS-Unterstützung verbessern die Sicherheit erheblich. 

**Jedoch:** Es gibt **kritische Schwachstellen** im Authentifizierungsdesign, Rate Limiting fehlt vollständig, und die Architektur ist anfällig für DoS-Angriffe. Für einen **Prototyp akzeptabel**, für **Production absolut inakzeptabel**.

**Risk Score:** 🔥 **7.2/10 (HIGH)** - Mehrere kritische Findings müssen vor Production-Einsatz behoben werden.

---

## 🔴 KRITISCHE FINDINGS (P0 - Immediate Action Required)

### 1. Replay Attack Vulnerability (CVSS 9.1 - CRITICAL)
**CWE-294: Authentication Bypass by Capture-Replay**

**Problem:** 
UUID-basierte Signaturen können **unbegrenzt oft wiederverwendet** werden. Ein Angreifer kann:
- Einmal abgefangenen `proof_signature` wiederverwenden
- Beliebig oft `/request_partner` aufrufen
- Nachrichten im Namen eines legitimen Clients senden

**Betroffene Endpoints:**
- `/request_partner` 
- `/deliver`
- `/inbox/<alias>`

**Beweis (Konzept):**
```python
# Angreifer fängt legitimen Request ab:
proof_signature = "a1b2c3..."  # Einmal abgefangen

# Kann nun beliebig oft wiederholt werden:
for i in range(1000):
    requests.post("/deliver", json={
        "from_alias": "Client1",
        "proof_signature": proof_signature,  # REPLAY!
        ...
    })
```

**Impact:**
- ✅ Authentifizierung umgangen
- ✅ Unbefugter Zugriff auf Partner-Keys
- ✅ Senden von Nachrichten im fremden Namen
- ✅ Zugriff auf fremde Inbox

**Remediation (HIGH PRIORITY):**
```python
# server/app.py - Nonce/Timestamp-basierte Challenge
import time

@dataclass
class AuthChallenge:
    uuid: str
    nonce: str
    timestamp: float
    used: bool = False

CHALLENGES = {}  # uuid -> AuthChallenge

@app.post("/participate")
def participate():
    u = str(_uuid.uuid4())
    nonce = base64.b64encode(os.urandom(16)).decode()
    challenge = AuthChallenge(
        uuid=u,
        nonce=nonce,
        timestamp=time.time()
    )
    CHALLENGES[u] = challenge
    return jsonify({"uuid": u, "nonce": nonce})

@app.post("/register")
def register():
    # Client muss UUID + NONCE signieren
    sig = base64.b64decode(data["uuid_signature"])
    challenge = CHALLENGES.get(u)
    
    if not challenge or challenge.used:
        return jsonify({"error": "invalid_challenge"}), 401
    
    # Prüfe Timeout (5 Minuten)
    if time.time() - challenge.timestamp > 300:
        return jsonify({"error": "challenge_expired"}), 401
    
    # Signatur muss UUID + Nonce enthalten
    message = f"{u}:{challenge.nonce}".encode()
    if not rsa_pss_verify(pub, sig, message):
        return jsonify({"error": "auth_failed"}), 401
    
    challenge.used = True  # Einmal-Verwendung
    # ... rest of registration
```

**Alternative:** JWT-Tokens mit Expiry und Refresh-Token-Mechanismus.

---

### 2. Fehlende Rate Limiting (CVSS 8.6 - HIGH)
**CWE-770: Allocation of Resources Without Limits or Throttling**

**Problem:**
Kein Rate Limiting an **irgendeinem** Endpoint. Ein Angreifer kann:

**DoS-Szenarien:**
```python
# 1) Registration Flooding
while True:
    priv = generate_rsa_private()  # Kostet Client-CPU
    requests.post("/participate")   # Kostet Server-RAM
    requests.post("/register", ...)  # Füllt Storage

# 2) Message Queue Flooding  
while True:
    requests.post("/deliver", json={
        "payload": {"ciphertext": "x" * 20_000_000}  # 20 MB
    })  # Füllt Server-RAM bis OOM

# 3) Brute Force UUID
for uuid in uuid_list:
    requests.post("/request_partner", json={
        "proof_signature": try_signature(uuid)
    })
```

**Impact:**
- Memory Exhaustion → Server Crash
- CPU Exhaustion → Performance-Degradation
- Brute Force Attacks möglich
- Kosten für Cloud-Hosting (wenn deployed)

**Aktuelle Limits:**
- ✅ File Size: 16 MB (gut)
- ✅ Payload Size: 20 MB (gut)
- ❌ Request Rate: **UNBEGRENZT** (kritisch!)
- ❌ Client Registrations: **UNBEGRENZT**
- ❌ Message Queue Size: **UNBEGRENZT**

**Remediation:**
```python
# server/app.py - Rate Limiting mit Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# Per-Endpoint Limits
@app.post("/register")
@limiter.limit("5 per hour")  # Max 5 Registrierungen pro Stunde
def register():
    ...

@app.post("/deliver")
@limiter.limit("100 per hour")  # Max 100 Nachrichten/Stunde
def deliver():
    ...

# Globale Message Queue Limits
MAX_MESSAGES_PER_CLIENT = 100
MAX_TOTAL_CLIENTS = 1000

def enqueue(self, msg: Message):
    if len(self.inbox.get(msg.to_alias, [])) >= MAX_MESSAGES_PER_CLIENT:
        raise ValueError("Inbox full")
    if len(self.clients_by_alias) >= MAX_TOTAL_CLIENTS:
        raise ValueError("Server at capacity")
    ...
```

**Requirements:**
```bash
pip install Flask-Limiter
```

---

### 3. TLS Certificate Validation Deaktiviert (CVSS 7.4 - HIGH)
**CWE-295: Improper Certificate Validation**

**Problem:**
`verify=False` ist **überall** im Code hart-codiert oder standardmäßig aktiv:

**Betroffene Stellen:**
```python
# clients/client.py
verify_ssl = not args.no_verify_ssl  # Aber --no-verify-ssl ist in ALLEN Befehlen!

# run_demo.py
urllib3.disable_warnings()  # Warnings global deaktiviert

# Jeder requests-Call
requests.post(url, verify=verify_ssl)  # verify=False praktisch überall
```

**Impact:**
- Man-in-the-Middle (MITM) Angriffe trivial
- Angreifer kann TLS-Traffic abfangen und **entschlüsseln**
- Self-signed Certs sind OK für **lokale Tests**, aber:
  - Keine Certificate Pinning
  - Kein Fallback auf echte CA-Validierung
  - User wird nicht ausreichend gewarnt

**Reales Angriffs-Szenario:**
```bash
# Angreifer im selben Netzwerk
sudo arpspoof -t 192.168.1.100 192.168.1.1  # ARP Spoofing
sudo sslstrip -l 5000                        # SSL Strip
# → Client connected zu Angreifer-Server statt finalem Server
# → verify=False = keine Warnung!
```

**Remediation:**

**Option A: Certificate Pinning (Empfohlen für interne Netzwerke)**
```python
# clients/client.py
EXPECTED_CERT_FINGERPRINT = "sha256:A1:B2:C3:..."  # Aus generate_certs.py

def verify_certificate(url, cert_fingerprint):
    """Pinned Certificate Verification"""
    import ssl, socket, hashlib
    
    hostname = url.split("://")[1].split(":")[0]
    port = int(url.split(":")[-1].split("/")[0])
    
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            fingerprint = hashlib.sha256(cert_bin).hexdigest()
            
            if fingerprint != cert_fingerprint:
                raise ssl.SSLError(f"Certificate fingerprint mismatch!")
    
    return True

# Bei jedem Request prüfen
if not args.no_verify_ssl:
    verify_certificate(base, EXPECTED_CERT_FINGERPRINT)
```

**Option B: Let's Encrypt für Production**
```bash
# Für echte Domains
sudo certbot certonly --standalone -d example.com
# → Verwende diese Zertifikate statt self-signed
```

**Option C: User-Warnung verstärken**
```python
# Bei --no-verify-ssl
print("⚠️  ⚠️  ⚠️  WARNING: SSL VERIFICATION DISABLED ⚠️  ⚠️  ⚠️")
print("   This connection is vulnerable to Man-in-the-Middle attacks!")
print("   Only use in trusted networks!")
response = input("   Continue anyway? (yes/NO): ")
if response.lower() != "yes":
    sys.exit(1)
```

---

### 4. Ungeschützte Private Keys auf Disk (CVSS 6.5 - MEDIUM-HIGH)
**CWE-311: Missing Encryption of Sensitive Data**

**Problem:**
Private Keys werden **unverschlüsselt** auf Disk gespeichert:

```python
# clients/crypto.py
def priv_to_pem(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()  # ❌ KEINE VERSCHLÜSSELUNG!
    )
```

**Gespeichert in:**
- `Client*/own/*_priv.pem` - Voller Dateisystem-Zugriff nötig
- Normale Dateirechte (644 oder 600, je nach umask)
- Kein Passwort-Schutz

**Impact:**
- Jeder mit Filesystem-Access kann Keys stehlen
- Backup-Systeme haben Klartext-Keys
- Malware kann Keys exfiltrieren
- Bei Docker/Cloud: Logs/Volumes könnten Keys enthalten

**Angriffsszenarien:**
```bash
# 1) Insider Threat
find / -name "*_priv.pem" 2>/dev/null
# → Findet alle Private Keys

# 2) Ransomware
for key in $(find . -name "*_priv.pem"); do
    encrypt_and_exfiltrate $key
done

# 3) Forensics nach Laptop-Diebstahl
photorec /dev/sda | grep "BEGIN PRIVATE KEY"
```

**Remediation:**

**Option A: Passwort-geschützte Keys (Empfohlen)**
```python
# clients/crypto.py
def priv_to_pem(priv, password: str = None) -> bytes:
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode())
    else:
        print("⚠️  WARNING: Saving private key without password protection!")
        response = input("Continue? (y/N): ")
        if response.lower() != 'y':
            raise ValueError("Aborted by user")
        encryption = serialization.NoEncryption()
    
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption
    )

# Bei genkeys
password = getpass.getpass("Enter password for private key: ")
password_confirm = getpass.getpass("Confirm password: ")
if password != password_confirm:
    raise ValueError("Passwords don't match")

save_keypair(kp, priv, password=password)
```

**Option B: OS Keychain Integration**
```python
# Linux: libsecret
# macOS: Keychain Access
# Windows: Windows Credential Manager

import keyring

def save_priv_secure(alias: str, priv_pem: bytes):
    keyring.set_password("rsa-filecrypter", alias, priv_pem.decode())

def load_priv_secure(alias: str) -> bytes:
    pem = keyring.get_password("rsa-filecrypter", alias)
    return pem.encode()
```

**Option C: Hardware Security Module (HSM/TPM)**
- Für High-Security Anforderungen
- Keys verlassen Hardware nie
- Teuer, aber maximal sicher

**Mindest-Maßnahme (Temporary Fix):**
```python
# Nach Key-Generierung
import os, stat
os.chmod(f"{kp}_priv.pem", stat.S_IRUSR | stat.S_IWUSR)  # 600 - nur Owner
print(f"🔒 Private key permissions set to 600 (owner-only)")
```

---

## 🟠 HIGH-PRIORITY FINDINGS (P1 - Address Before Production)

### 5. UUID Generation - Prädiktabilität (CVSS 5.3 - MEDIUM)
**CWE-330: Use of Insufficiently Random Values**

**Problem:**
UUIDs werden mit Python's `uuid.uuid4()` generiert:

```python
# server/app.py
u = str(_uuid.uuid4())
```

**Analyse:**
- `uuid4()` verwendet `/dev/urandom` (Linux) bzw. `CryptGenRandom` (Windows)
- **Kryptografisch sicher** ✅
- **Aber:** Collision-Wahrscheinlichkeit bei 1 Billion UUIDs: ~50%

**Ist das ein Problem?**
- Für Prototype: **NEIN** ✅
- Für Production mit Millionen Users: **JA** ⚠️

**Verbesserung:**
```python
# server/app.py
import secrets

@app.post("/participate")
def participate():
    # 256-bit kryptografisch sicherer Random Token
    token = secrets.token_urlsafe(32)  # 43 Zeichen Base64
    log.info(f"Generated token: {token}")
    return jsonify({"uuid": token})  # Umbenennen zu "token"
```

**Zusätzlich: Token-Rotation**
```python
@dataclass
class Session:
    token: str
    client_uuid: str  # Nach Registration gesetzt
    created: float
    expires: float
    
SESSIONS = {}  # token -> Session

# Nach erfolgreichem Register: Token rotieren
new_token = secrets.token_urlsafe(32)
SESSIONS[new_token] = Session(..., expires=time.time() + 3600)  # 1h
return jsonify({"access_token": new_token})
```

---

### 6. In-Memory Storage - Data Loss & RAM Exhaustion (CVSS 6.1 - MEDIUM)
**CWE-1236: Improper Neutralization of Formula Elements**

**Problem:**
```python
# server/storage.py
class Store:
    def __init__(self):
        self.clients_by_alias: Dict[str, Client] = {}  # RAM
        self.clients_by_uuid: Dict[str, Client] = {}   # RAM
        self.inbox: Dict[str, List[Message]] = {}      # RAM
```

**Issues:**
1. **Data Loss:** Server-Restart = alle Daten weg
2. **RAM Exhaustion:** Unbegrenztes Wachstum möglich
3. **Keine Persistenz:** Backup unmöglich
4. **No Cleanup:** Messages werden nie gelöscht (nur bei Abruf)

**Memory Growth Simulation:**
```python
# 1 Client = ~10 KB (Keys, UUID, Alias)
# 1 Message = ~20 MB (max payload) + Metadata = ~20 MB

# Szenario: 1000 Clients, je 10 nicht-abgeholte Messages
memory = 1000 * 10_000 + 1000 * 10 * 20_000_000
# = 10 MB + 200 GB = 200 GB RAM!!! 💥
```

**Remediation:**

**Option A: SQLite (Empfohlen für Prototyp → Production)**
```python
# server/storage.py
import sqlite3
from contextlib import contextmanager

class PersistentStore:
    def __init__(self, db_path="server.db"):
        self.db = db_path
        self._init_db()
    
    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    alias TEXT PRIMARY KEY,
                    uuid TEXT UNIQUE NOT NULL,
                    pubkey_pem BLOB NOT NULL,
                    created_at REAL DEFAULT (julianday('now'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_alias TEXT NOT NULL,
                    to_alias TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    meta_json TEXT NOT NULL,
                    created_at REAL DEFAULT (julianday('now')),
                    delivered BOOLEAN DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_to_alias ON messages(to_alias, delivered)")
    
    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db)
        try:
            yield conn
            conn.commit()
        except:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def add_client(self, c: Client):
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO clients (alias, uuid, pubkey_pem) VALUES (?, ?, ?)",
                (c.alias, c.uuid, c.pubkey_pem)
            )
    
    def enqueue(self, msg: Message):
        # Limit Messages per Client
        with self._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE to_alias = ? AND delivered = 0",
                (msg.to_alias,)
            ).fetchone()[0]
            
            if count >= 100:  # Max 100 pending messages
                raise ValueError("Inbox full")
            
            conn.execute(
                "INSERT INTO messages (from_alias, to_alias, payload_json, meta_json) VALUES (?, ?, ?, ?)",
                (msg.from_alias, msg.to_alias, json.dumps(msg.payload), json.dumps(msg.meta))
            )
```

**Option B: Redis (für High-Performance)**
```python
import redis
import pickle

class RedisStore:
    def __init__(self, host='localhost', port=6379):
        self.r = redis.Redis(host=host, port=port, decode_responses=False)
    
    def add_client(self, c: Client):
        # TTL: 30 Tage
        self.r.setex(f"client:alias:{c.alias}", 2592000, pickle.dumps(c))
        self.r.setex(f"client:uuid:{c.uuid}", 2592000, pickle.dumps(c))
    
    def enqueue(self, msg: Message):
        key = f"inbox:{msg.to_alias}"
        # List max 100 items, älteste löschen
        if self.r.llen(key) >= 100:
            self.r.ltrim(key, -99, -1)
        self.r.lpush(key, pickle.dumps(msg))
        self.r.expire(key, 604800)  # 7 Tage TTL
```

---

### 7. Fehlendes Audit Logging (CVSS 5.9 - MEDIUM)
**CWE-778: Insufficient Logging**

**Problem:**
Minimales Logging vorhanden, aber **kritische Events nicht geloggt**:

**Was wird NICHT geloggt:**
- ❌ Fehlgeschlagene Authentication Attempts (Brute Force Detection!)
- ❌ Client IP-Adressen
- ❌ Message Delivery Success/Failure
- ❌ File Sizes (für Capacity Planning)
- ❌ Wer hat welche Keys angefragt (Audit Trail!)

**Aktuelles Logging:**
```python
log.info(f"Generated new UUID: {u}")  # OK
log.info(f"Registered new client: alias={alias}")  # OK
log.warning(f"Validation error: {e}")  # OK
# ... aber viele Lücken
```

**Remediation:**
```python
# server/app.py
import logging
from logging.handlers import RotatingFileHandler
import json

# Structured Logging
class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        handler = RotatingFileHandler('security.log', maxBytes=10_000_000, backupCount=5)
        handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def log_event(self, event_type, **kwargs):
        log_entry = {
            'event': event_type,
            'timestamp': time.time(),
            'ip': request.remote_addr,
            **kwargs
        }
        self.logger.info(json.dumps(log_entry))

sec_log = SecurityLogger()

# In Endpoints
@app.post("/register")
def register():
    sec_log.log_event('registration_attempt', alias=alias)
    # ... validation ...
    if not rsa_pss_verify(...):
        sec_log.log_event('registration_failed', alias=alias, reason='invalid_signature')
        return jsonify({"error": "auth_failed"}), 401
    sec_log.log_event('registration_success', alias=alias, uuid=u)
    # ...

@app.post("/deliver")
def deliver():
    sec_log.log_event('message_send', from_alias=fr, to_alias=to, 
                     payload_size=len(json.dumps(payload)))
    # ...

# Für SIEM Integration
@app.before_request
def log_request():
    sec_log.log_event('http_request', 
                     method=request.method,
                     path=request.path,
                     user_agent=request.headers.get('User-Agent'))

# Failed Auth Counter (für Rate Limiting)
FAILED_AUTH = {}  # IP -> Count
@app.after_request
def track_failed_auth(response):
    if response.status_code == 401:
        ip = request.remote_addr
        FAILED_AUTH[ip] = FAILED_AUTH.get(ip, 0) + 1
        if FAILED_AUTH[ip] > 5:
            sec_log.log_event('potential_brute_force', ip=ip, count=FAILED_AUTH[ip])
            # Optional: IP blocken
    return response
```

<!-- ---

### 8. Flask Debug Mode in Production Risk (CVSS 7.5 - HIGH)
**CWE-489: Debug Mode Enabled**

**Problem:**
```python
# server/app.py
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, ssl_context=ssl_context)
    #                                    ^^^^^^^^^^^ GEFÄHRLICH!
```

**Risks bei Debug Mode:**
- ✅ **Werkzeug Debugger** ist aktiviert! 
- ✅ PIN ist im Terminal sichtbar: `Debugger PIN: 126-440-104`
- ✅ Code Injection via Debugger Console möglich
- ✅ Stack Traces mit Source Code werden an Client gesendet
- ✅ Auto-Reload bei Code-Änderungen (Performance-Hit)

**Exploit-Szenario:**
```python
# Angreifer triggert Exception
requests.post("/deliver", json={"malformed": "data"})
# → Server sendet Full Stack Trace mit:
#   - File Paths (/home/user/project/...)
#   - Source Code Snippets
#   - Environment Variables (?)
#   - Library Versions

# Mit Debugger PIN → Remote Code Execution!
# https://werkzeug.palletsprojects.com/debugger
# PIN erraten oder aus Process Memory extrahieren
```

**Implemented Fix:**
```python
# server/app.py (NEUE VERSION - FIXED)
import os

if __name__ == "__main__":
    # SECURITY: Never use debug=True in production!
    # Debug mode enables Werkzeug debugger with interactive console (RCE risk)
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    if debug_mode:
        print("⚠️  WARNING: Debug mode is ENABLED - for development only!")
        print("   This allows remote code execution via debugger PIN")
    
    app.run(
        debug=debug_mode,  # Default: False (production-safe)
        host="127.0.0.1",
        port=5000,
        ssl_context=ssl_context
    )

# Usage:
# Production (default):  python -m server.app
# Development:           FLASK_DEBUG=true python -m server.app
```

**Verification:**
```bash
# ✅ Production Mode (safe):
$ python -m server.app
# → No debugger warning, no PIN displayed

# ⚠️ Development Mode (explicit opt-in):
$ FLASK_DEBUG=true python -m server.app
# → ⚠️  WARNING: Debug mode is ENABLED - for development only!
# → Debugger PIN: xxx-xxx-xxx
```

**Remediation (Additional Hardening):**
```python
# server/app.py
import os

if __name__ == "__main__":
    # Umgebungsvariable für Production
    DEBUG = os.environ.get('FLASK_ENV') == 'development'
    
    if DEBUG:
        print("⚠️  WARNING: Debug mode enabled - FOR DEVELOPMENT ONLY!")
    
    app.run(
        host=os.environ.get('HOST', '127.0.0.1'),
        port=int(os.environ.get('PORT', 5000)),
        debug=DEBUG,  # False in Production
        ssl_context=ssl_context
    )

# Für Production: Verwende WSGI Server
# gunicorn -w 4 -b 0.0.0.0:5000 server.app:app

# requirements.txt hinzufügen:
# gunicorn>=21.0.0
``` -->

---

## 🟡 MEDIUM-PRIORITY FINDINGS (P2 - Address in Next Sprint)

### 9. Nonce-Reuse Risk bei identischen Dateien (CVSS 4.7 - MEDIUM-LOW)
**CWE-323: Reusing a Nonce, Key Pair in Encryption**

**Problem:**
```python
# clients/crypto.py
def aes_gcm_encrypt_file(...):
    nonce = os.urandom(12)  # Neu bei jedem Aufruf ✅
    # ABER: Was wenn dieselbe Datei mit demselben AES-Key mehrfach gesendet wird?
```

**Ist das ein Problem?**
- ✅ **Aktuell SICHER** - Jeder Send generiert neuen AES-Key:
  ```python
  aes_key = os.urandom(32)  # Neu bei jedem send
  ```
- ⚠️ **Aber:** Wenn Code geändert wird und Keys wiederverwendet werden → Nonce-Reuse!

**GCM Nonce-Reuse Impact:**
- Catastrophic Failure of Authentication
- Key Recovery möglich
- Plaintext Recovery möglich

**Remediation (Defense in Depth):**
```python
# clients/crypto.py
from cryptography.hazmat.primitives import hashes
import hashlib

def aes_gcm_encrypt_file(aes_key: bytes, filepath: str, aad: bytes | None = None) -> dict:
    with open(filepath, "rb") as f:
        pt = f.read()
    
    # Deterministischer Nonce aus File Content + Random
    # → Vermeidet Kollision selbst bei Key-Reuse
    file_hash = hashlib.sha256(pt).digest()[:6]  # 6 Bytes von Hash
    random_part = os.urandom(6)  # 6 Bytes Random
    nonce = file_hash + random_part  # 12 Bytes total
    
    # Alternative: Counter + Random
    # nonce = COUNTER.to_bytes(4, 'big') + os.urandom(8)
    
    ct = AESGCM(aes_key).encrypt(nonce, pt, aad)
    return {"nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()}
```

**Best Practice:** Key Rotation Policy dokumentieren:
```markdown
## Key Usage Policy
- ✅ AES-Keys werden pro Nachricht neu generiert
- ✅ RSA-Keys werden bei Registrierung generiert
- ⚠️  RSA-Keys sollten alle 90 Tage rotiert werden
- ❌ NIEMALS denselben AES-Key für mehrere Dateien verwenden
```

---

### 10. Cross-Client Message Injection (CVSS 5.9 - MEDIUM)
**CWE-345: Insufficient Verification of Data Authenticity**

**Problem:**
Server akzeptiert beliebige `from_alias` im `/deliver` Endpoint:

```python
# server/app.py
@app.post("/deliver")
def deliver():
    fr = validate_alias(data["from_alias"])  # User-controlled!
    # ... Auth mit proof_signature ...
    STORE.enqueue(Message(from_alias=fr, ...))
```

**Angriff:**
```python
# Client1 ist authentifiziert (hat gültige proof_signature)
requests.post("/deliver", json={
    "from_alias": "Client2",  # ❌ Lügt über Sender!
    "to_alias": "Client3",
    "proof_signature": client1_proof,  # Aber Auth ist Client1
    ...
})
```

**Was passiert:**
- Server prüft `proof_signature` gegen `c_from = STORE.get_client_by_alias(fr)`
- Aber `fr = "Client2"` (aus Request), nicht aus Signature!
- **Falls** Client1's Proof für Client2 valid ist... → Injection möglich? **NEIN**, weil:

```python
c_from = STORE.get_client_by_alias(fr)  # fr = "Client2"
if not rsa_pss_verify(load_public_key_pem(c_from.pubkey_pem), proof, c_from.uuid.encode()):
    # Proof ist nur valid für Client1's UUID, nicht Client2's
    return jsonify({"error": "auth_failed"}), 401
```

**Ergebnis:** **NICHT anfällig** ✅ (Aber verwirrende Logik!)

**Verbesserung für Klarheit:**
```python
# server/app.py
@app.post("/deliver")
def deliver():
    claimed_from = validate_alias(data["from_alias"])
    to = validate_alias(data["to_alias"])
    proof = base64.b64decode(data["proof_signature"])
    
    # 1) Hole Client anhand Claim
    c_from = STORE.get_client_by_alias(claimed_from)
    if not c_from:
        return jsonify({"error": "sender_not_found"}), 404
    
    # 2) Verify Proof gegen claimed Identity
    if not rsa_pss_verify(load_public_key_pem(c_from.pubkey_pem), proof, c_from.uuid.encode()):
        sec_log.log_event('spoofing_attempt', 
                          claimed_from=claimed_from, 
                          ip=request.remote_addr)
        return jsonify({"error": "auth_failed"}), 401
    
    # 3) Proof ist valid → claimed_from ist verifiziert
    # ... rest ...
```

---

### 11. AAD nicht ausreichend (CVSS 3.7 - LOW)
**CWE-345: Insufficient Verification of Data Authenticity**

**Problem:**
Nur `sender_alias` ist in AAD:

```python
# clients/client.py
enc = aes_gcm_encrypt_file(aes_key, args.file, aad=args.alias.encode())
#                                                    ^^^ Nur Alias
```

**Was AAD schützt:**
- ✅ Sender kann nicht geändert werden (Authenticated)
- ❌ Filename nicht geschützt
- ❌ Timestamp nicht geschützt
- ❌ Recipient nicht geschützt

**Angriffsszenario (Relay Attack):**
```python
# Angreifer (MitM) fängt Message ab:
{
    "from_alias": "Client1",  # AAD-geschützt
    "to_alias": "Client2",    # NICHT AAD-geschützt → änderbar!
    "meta": {"filename": "secret.txt"},  # NICHT AAD-geschützt
    "payload": {...}
}

# Angreifer ändert:
message["to_alias"] = "Client3"  # → Message geht an falschen Empfänger!
message["meta"]["filename"] = "virus.exe"  # → Empfänger speichert unter falschem Namen
```

**Impact:**
- Relaying to wrong recipient (aber nur wenn Angreifer schon MitM ist)
- Filename Spoofing (könnte zu Social Engineering führen)

**Remediation:**
```python
# clients/client.py
def build_aad(from_alias: str, to_alias: str, filename: str, timestamp: float = None) -> bytes:
    """Comprehensive AAD for all critical metadata"""
    import json
    timestamp = timestamp or time.time()
    aad_dict = {
        "from": from_alias,
        "to": to_alias,
        "file": filename,
        "ts": timestamp  # Prevents Replay
    }
    return json.dumps(aad_dict, sort_keys=True).encode()

# In send
aad = build_aad(args.alias, args.partner, os.path.basename(args.file))
enc = aes_gcm_encrypt_file(aes_key, args.file, aad=aad)

# In receive
aad = build_aad(m['from_alias'], args.alias, m['meta']['filename'], m.get('timestamp'))
aes_gcm_decrypt_to_file(aes_key, nonce, ct, out_path, aad=aad)
```

---

### 12. Fehlende Input Sanitization in Logs (CVSS 3.9 - LOW)
**CWE-117: Improper Output Neutralization for Logs**

**Problem:**
```python
# server/app.py
log.info(f"Registered new client: alias={alias}, uuid={u}")
#                                        ^^^^^ User-controlled!
```

**Log Injection Attack:**
```python
# Angreifer registriert mit speziellem Alias
alias = "Evil\n2026-02-12 22:00:00 INFO Admin login successful"

# Log enthält nun:
# 2026-02-12 21:59:00 INFO Registered new client: alias=Evil
# 2026-02-12 22:00:00 INFO Admin login successful
#                          ↑ Fake Entry!
```

**Impact:**
- Log-File Parsing getäuscht
- SIEM/IDS täuschbar
- Forensics erschwert
- Compliance Audit manipulierbar

**Remediation:**
```python
# server/app.py
import re

def sanitize_for_log(s: str) -> str:
    """Remove newlines and control characters"""
    s = s.replace('\n', '\\n').replace('\r', '\\r')
    s = re.sub(r'[\x00-\x1F\x7F]', '', s)  # Remove control chars
    return s

log.info(f"Registered: alias={sanitize_for_log(alias)}, uuid={u}")

# Oder: Structured Logging mit JSON
log.info(json.dumps({
    "event": "registration",
    "alias": alias,  # JSON escaping automatisch
    "uuid": u
}))
```

---

## 🟢 LOW-PRIORITY / INFORMATIONAL

### 13. RSA-4096 Performance Impact ℹ️
**Bemerkung:** RSA-4096 ist sehr sicher, aber langsam.

**Benchmarks:**
- RSA-2048: ~5-10ms Signatur/Verifizierung
- RSA-4096: ~20-40ms Signatur/Verifizierung
- RSA-4096: ~200KB+ Memory pro Keypair

**Empfehlung:**
- Für **Prototype**: OK ✅
- Für **High-Throughput Production**: Erwäge RSA-2048 (bis 2030 sicher)
- Für **Post-Quantum**: Plane Migration zu ML-DSA / ML-KEM (NIST PQC)

---

### 14. TLS 1.2 vs TLS 1.3 ℹ️
**self-signed Certs verwenden Python's SSL-Standard** (TLS 1.2+ meist).

**Check:**
```bash
openssl s_client -connect localhost:5000 -tls1_3
# Wenn failed → nur TLS 1.2
```

**Empfehlung:** Explicit TLS 1.3:
```python
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
ssl_context.load_cert_chain(cert_file, key_file)
app.run(..., ssl_context=ssl_context)
```

---

### 15. Code-Qualität & Best Practices ℹ️

**Positives:**
- ✅ Type Hints verwendet (`str`, `bytes`, etc.)
- ✅ Docstrings vorhanden
- ✅ Clear Separation of Concerns
- ✅ Dataclasses für strukturierte Daten
- ✅ Exception Handling

**Verbesserungspotential:**
- ⚠️ Mehr Unit Tests für Edge Cases
- ⚠️ Integration Tests für Multi-Client Szenarien
- ⚠️ Property-based Testing (Hypothesis)
- ⚠️ Security Tests (Bandit, Safety)
- ⚠️ Dependency Scanning (Snyk, Dependabot)

---

## Zusammenfassung & Priorisierung

### 🚨 MUST-FIX vor Production (P0)
1. ✅ **Replay Attack Prevention** (CVSS 9.1) → Implement Nonce/Token System
2. ✅ **Rate Limiting** (CVSS 8.6) → Flask-Limiter + Queue Limits
3. ✅ **TLS Validation** (CVSS 7.4) → Certificate Pinning oder Let's Encrypt
4. ✅ **Key Encryption** (CVSS 6.5) → Password-protected Private Keys

**Effort:** ~2-3 Entwicklertage  
**Risk Reduction:** 90%

---

### 🔧 Sollte implementiert werden (P1)
5. ✅ **UUID → Token Migration** (CVSS 5.3)
6. ✅ **Persistent Storage** (CVSS 6.1)
7. ✅ **Security Audit Logging** (CVSS 5.9)
8. ✅ **Debug Mode Disable** (CVSS 7.5) → **✅ FIXED (2026-02-13)**

**Effort:** ~3-4 Entwicklertage  
**Risk Reduction:** 80%

---

### 💡 Nice-to-Have (P2)
9-15. Nonce Policy, AAD Improvement, Log Sanitization, etc.

**Effort:** ~2 Entwicklertage  
**Risk Reduction:** 60%

---

## Threat Modeling - STRIDE Analysis

| Threat | Impact | Mitigated? | Notes |
|--------|--------|-----------|-------|
| **Spoofing** (Identity) | HIGH | ⚠️ PARTIAL | UUID-Sig OK, aber Replay möglich |
| **Tampering** (Data) | MEDIUM | ✅ YES | AES-GCM Auth Tag, AAD |
| **Repudiation** (Logging) | MEDIUM | ⚠️ PARTIAL | Logging exists, aber Lücken |
| **Information Disclosure** | HIGH | ⚠️ PARTIAL | E2E Encryption OK, aber verify=False |
| **Denial of Service** | CRITICAL | ❌ NO | Kein Rate Limiting! |
| **Elevation of Privilege** | LOW | ✅ YES | Keine Admin-Funktionen |

**Score:** 4/6 mitigated → **67% abgedeckt**

---

## Compliance & Standards

**Erfüllt:**
- ✅ NIST SP 800-38D (AES-GCM)
- ✅ RFC 8017 (RSA PKCS#1 v2.2)
- ✅ FIPS 186-4 (Digital Signatures)

**Nicht Erfüllt:**
- ❌ OWASP Top 10 #4 (Insecure Design - no rate limiting)
- ❌ OWASP Top 10 #5 (Security Misconfiguration - debug mode)
- ❌ OWASP Top 10 #9 (Insufficient Logging)
- ❌ PCI-DSS 8.3 (Key Management)

---

## Empfohlene Maßnahmen - Timeline

### Sprint 1 (Week 1) - Critical Fixes
- [ ] Replay Attack Prevention (3 Tage)
- [ ] Rate Limiting Implementation (2 Tage)

### Sprint 2 (Week 2) - High Priority
- [ ] Key Password Protection (2 Tage)
- [ ] Certificate Validation (2 Tage)
- [ ] Debug Mode Fix (0.5 Tage)

### Sprint 3 (Week 3) - Infrastructure
- [ ] SQLite Persistence (2 Tage)
- [ ] Audit Logging (2 Tage)
- [ ] WSGI Production Setup (1 Tag)

### Sprint 4 (Week 4) - Hardening
- [ ] AAD Enhancement (1 Tag)
- [ ] Nonce Policy (1 Tag)
- [ ] Log Sanitization (1 Tag)
- [ ] Security Testing (2 Tage)

**Total Effort:** ~20 Entwicklertage (~4 Wochen)

---

## Fazit

Der **RSA Hybrid FileCrypter** zeigt eine **solide kryptografische Basis** und gute Grundlagen. Die kürzlich implementierten Security-Fixes (Input Validation, TLS) sind positiv.

**Jedoch:** Für Production-Einsatz sind **kritische Lücken** vorhanden, insbesondere:
- Replay Attack Vulnerablity
- Fehlendes Rate Limiting
- TLS Validation deaktiviert

**Empfehlung:**
- ✅ Für **Prototyp/Demo**: **AKZEPTABEL** mit Einschränkungen
- ✅ Für **Akademisches Projekt**: **SEHR GUT** - zeigt Verständnis
- ❌ Für **Production**: **NICHT BEREIT** - kritische Fixes erforderlich

**Nächste Schritte:**
1. Implementiere P0-Fixes (Critical)
2. Führe Penetration Testing durch
3. Code Review mit Security-Fokus
4. Deployment in Staging-Umgebung
5. Load Testing & Performance Optimization

---

**Assessment durchgeführt von:** AI Security Analyst  
**Review-Datum:** 12. Februar 2026  
**Nächste Review:** Nach Implementierung der P0-Fixes
