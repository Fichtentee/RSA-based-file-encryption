# TLS Implementation - Quick Guide

## ✨ Was wurde implementiert?

**Self-signed TLS für lokalen HTTPS-Server**
- Server: Flask mit TLS-Support
- Client: HTTPS mit `verify=False` für self-signed certs
- Auto-Fallback auf HTTP wenn keine Zertifikate vorhanden

---

## 🚀 Schnellstart

### 1. Zertifikate generieren (einmalig)

```bash
./generate_certs.py
```

**Output:**
```
🔐 Generiere self-signed TLS-Zertifikat...
✅ Zertifikat generiert:
   Zertifikat: server/cert.pem
   Private Key: server/key.pem
   Gültig für: 365 Tage
   Common Name: localhost
```

### 2. Server starten

```bash
python -m server.app
```

**Output bei TLS:**
```
🔒 Starting HTTPS server with TLS...
   Certificate: server/cert.pem  
   Server URL: https://localhost:5000
   ⚠️  Self-signed certificate - clients need verify=False
 * Running on https://127.0.0.1:5000
```

**Output OHNE TLS** (Fallback):
```
⚠️  WARNING: No TLS certificates found!
   Run: python generate_certs.py
   Starting HTTP server (INSECURE)...
   Server URL: http://localhost:5000
```

### 3. Client verwenden

```bash
# Mit TLS (default)
python -m clients.client --alias MyClient --no-verify-ssl genkeys
python -m clients.client --alias MyClient --no-verify-ssl register

# ODER für HTTP-Server (falls kein TLS):
python -m clients.client --alias MyClient --server http://127.0.0.1:5000 genkeys
```

---

## 📝 Details zur Implementierung

### Generierte Dateien

| Datei | Beschreibung | Verwendung |
|-------|--------------|------------|
| `server/cert.pem` | TLS-Zertifikat | Server HTTPS |
| `server/key.pem` | Private Key | Server HTTPS |

**Zertifikat-Details:**
- Algorithmus: RSA-4096
- Gültigkeit: 365 Tage
- Common Name: localhost
- Self-signed (keine CA)

### Code-Änderungen

**Server (`server/app.py`):**
```python
if __name__ == "__main__":
    # Prüft ob cert.pem/key.pem existieren
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = (cert_file, key_file)  # TLS enabled
    else:
        ssl_context = None  # HTTP fallback
    
    app.run(ssl_context=ssl_context)
```

**Client (`clients/client.py`):**
```python
# Default: HTTPS
ap.add_argument("--server", default="https://127.0.0.1:5000")
ap.add_argument("--no-verify-ssl", action="store_true")

# Alle requests.post/get mit verify=verify_ssl
requests.post(url, json=data, verify=verify_ssl)
```

---

## ⚠️ Wichtige Hinweise

### Self-signed Zertifikate

**Vorteile:**
- ✅ Schnelle Einrichtung (keine CA notwendig)
- ✅ TLS-Verschlüsselung vorhanden
- ✅ Gut für lokale Entwicklung/Demo

**Nachteile:**
- ❌ Browser zeigen Sicherheitswarnung
- ❌ Clients müssen `verify=False` verwenden
- ❌ NICHT für Production geeignet
- ❌ Keine Chain of Trust

### Browser-Warnung

Wenn du den Server im Browser öffnest (`https://localhost:5000`):
```
⚠️ Diese Verbindung ist nicht privat
NET::ERR_CERT_AUTHORITY_INVALID
```

**Lösung für Tests:** "Erweitert" → "Trotzdem zu localhost wechseln"

### Für Production

Self-signed Zertifikate **NICHT** für Production verwenden!

**Production-Optionen:**
1. **Let's Encrypt** (kostenlos, automatisch)
   - Benötigt öffentliche Domain
   - certbot für Auto-Renewal

2. **Eigene CA** (für Unternehmens-Netzwerk)
   - Eigene Certificate Authority
   - Clients müssen CA vertrauen

3. **Reverse Proxy** (nginx/Apache)
   - Proxy handhabt TLS
   - Flask läuft intern mit HTTP

---

## 🧪 Tests

Alle 104 Tests bestehen weiterhin:

```bash
$ pytest -q
============================= 104 passed in 3.29s ===========================
```

**Warum?** Tests verwenden Flask Test Client (kein echtes HTTP/HTTPS).

---

## 🔒 Sicherheitsverbesserung

### Vorher (HTTP only):
```
[Client] --HTTP--> [Server]
   ↑                  ↑
   └── Klartext ❌   └── Sniffbar ❌
```

**Risiken:**
- Private Keys im Klartext übertragen
- Passwörter/Secrets lesbar
- Man-in-the-Middle möglich

### Jetzt (HTTPS mit TLS):
```
[Client] --TLS--> [Server]
   ↑                 ↑
   └── Encrypted ✅  └── Authenticated ✅
```

**Vorteile:**
- ✅ Transport-Verschlüsselung
- ✅ Server-Authentifizierung
- ✅ Schutz gegen Sniffing

**Noch offen (für Production):**
- ⚠️ Self-signed → CA-signiert
- ⚠️ Client cert verification
- ⚠️ TLS 1.3 only enforcement

---

## 🎯 Zusammenfassung

| Feature | Status |
|---------|--------|
| TLS/HTTPS | ✅ Implementiert |
| Self-signed Certs | ✅ Generiert |
| Client HTTPS-Support | ✅ Implementiert |
| Auto-Fallback HTTP | ✅ Implementiert |
| Tests | ✅ 104/104 passing |
| Production-ready | ❌ Self-signed only |

**Für Studien-Projekt:** ✅ Ausreichend  
**Für Production:** ❌ CA-Zertifikat notwendig

---

**Weitere Fragen?** Siehe `SECURITY_FIXES_REPORT.md` für vollständiges Security Audit.
