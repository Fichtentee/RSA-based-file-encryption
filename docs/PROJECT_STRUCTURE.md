# Projekt-Struktur: RSA Hybrid FileCrypter

## Aktuelle Struktur (Empfohlen)

```
rsa-hybrid-filecrypter/
│
├── 📁 docs/                              # 📚 Dokumentation
│   ├── CRITICAL_SECURITY_ASSESSMENT.md   # Security Assessment (detailliert)
│   ├── SECURITY_FIXES_REPORT.md          # Implementierte Security Fixes
│   ├── STRIDE_THREAT_ANALYSIS.md         # STRIDE Threat Model
│   ├── TLS_IMPLEMENTATION.md             # TLS Setup Guide
│   ├── DFD_Level_0.drawio                # Data Flow Diagram Level 0
│   ├── DFD_Level_1.drawio                # Data Flow Diagram Level 1
│   └── DFD_Level_2.drawio                # Data Flow Diagram Level 2
│
├── 📁 server/                            # 🖥️ Server-Komponenten
│   ├── __init__.py
│   ├── app.py                            # Flask REST API
│   ├── config.py                         # Konfiguration
│   ├── crypto.py                         # Kryptografie-Funktionen
│   ├── storage.py                        # In-Memory Storage
│   ├── validation.py                     # Input Validation
│   ├── schemas.py                        # JSON Schemas
│   ├── requirements.txt                  # Python Dependencies
│   ├── cert.pem                          # TLS Zertifikat (gitignored)
│   └── key.pem                           # TLS Private Key (gitignored)
│
├── 📁 clients/                           # 💻 Client-Komponenten
│   ├── __init__.py
│   ├── client.py                         # CLI Client
│   └── crypto.py                         # Client-seitige Kryptografie
│
├── 📁 tests/                             # 🧪 Test Suite
│   ├── conftest.py                       # Pytest Fixtures
│   ├── test_server.py                    # Server API Tests
│   ├── test_server_crypto.py             # Server Crypto Tests
│   ├── test_crypto.py                    # Client Crypto Tests
│   ├── test_storage.py                   # Storage Tests
│   ├── test_security.py                  # Security Tests
│   └── test_flow.py                      # End-to-End Flow Tests
│
├── 📁 scripts/                           # 🔧 Utility Scripts
│   ├── generate_certs.py                 # TLS Zertifikat-Generator
│   ├── run_demo.py                       # Automatisierte Demo
│   └── cleanup.py                        # Projekt aufräumen
│
├── 📁 files/                             # 📄 Beispiel-Dateien
│   ├── README.md                         # Info über Testdateien
│   ├── secret_message.txt
│   ├── meeting_notes.txt
│   └── credentials.txt
│
├── 📁 .tmp/                              # 🗑️ Temporäre Dateien (gitignored)
│   ├── Client1/                          # Test Client 1 Daten
│   ├── Client2/                          # Test Client 2 Daten
│   ├── TestClient/                       # Pytest Test Clients
│   ├── demo_test.txt                     # Demo Artefakte
│   └── *.txt                             # Sonstige Test-Outputs
│
├── 📁 htmlcov/                           # 📊 Coverage Reports (gitignored)
├── 📁 .pytest_cache/                     # Pytest Cache (gitignored)
│
├── 📄 README.md                          # Haupt-Dokumentation
├── 📄 pytest.ini                         # Pytest Konfiguration
├── 📄 .gitignore                         # Git Ignore Regeln
├── 📄 .coveragerc                        # Coverage Konfiguration
└── 📄 .coverage                          # Coverage Daten (gitignored)
```

---

## Verzeichnis-Beschreibungen

### 📚 `/docs/` - Dokumentation
Alle Markdown-Dokumente und Diagramme für das Projekt:
- Security Assessments
- Threat Models
- Implementation Guides
- Data Flow Diagramme

**Zweck:** Zentrale Anlaufstelle für alle Projekt-Dokumente.

---

### 🖥️ `/server/` - Server Code
Backend-Komponenten des FileCrypter-Systems:
- Flask REST API (`app.py`)
- Kryptografie-Bibliothek (`crypto.py`)
- Storage-Layer (`storage.py`)
- Input Validation (`validation.py`)
- TLS Zertifikate (`cert.pem`, `key.pem`)

**Zweck:** Vollständige Server-Implementation mit klarer Separation of Concerns.

---

### 💻 `/clients/` - Client Code
Client-seitige Komponenten:
- CLI Interface (`client.py`)
- Client Kryptografie (`crypto.py`)

**Zweck:** Wiederverwendbare Client-Bibliothek.

---

### 🧪 `/tests/` - Test Suite
Komplette Test-Abdeckung:
- Unit Tests (Server, Client, Crypto)
- Integration Tests (E2E Flows)
- Security Tests (Input Validation, Attack Vectors)

**Zweck:** Qualitätssicherung und Regression Prevention.

---

### 🔧 `/scripts/` - Utility Scripts
Hilfsskripte für Setup und Demo:
- `generate_certs.py` - TLS Zertifikate generieren
- `run_demo.py` - Automatisierte Demo
- `cleanup.py` - Projekt aufräumen

**Zweck:** Automatisierung von häufigen Aufgaben.

---

### 📄 `/files/` - Beispiel-Dateien
Test-Dateien für Verschlüsselung:
- Textdateien mit verschiedenen Inhalten
- Binärdateien (optional)
- README mit Beschreibung

**Zweck:** Referenz-Dateien für Tests und Demos.

---

### 🗑️ `/.tmp/` - Temporäre Dateien
**WICHTIG:** Dieses Verzeichnis ist gitignored!

Enthält:
- Client-Verzeichnisse (Client1, Client2, etc.)
- Test-Artefakte
- Demo-Outputs
- Temporäre Entschlüsselungen

**Zweck:** Vermeiden von Test-Artefakten im Root und Git-Repository.

---

## Cleanup-Regeln

### Gitignored (automatisch)
```
.tmp/
htmlcov/
.pytest_cache/
.coverage
*.pyc
__pycache__/
server/cert.pem
server/key.pem
Client*/
TestClient*/
*.txt (im Root)
.venv/
```

### Manuell zu entfernen
```
decrypted*.txt
demo_test.txt
passwd
plain.txt
```

---

## Migration

### Schritt 1: Verzeichnisse erstellen
```bash
mkdir -p docs scripts .tmp
```

### Schritt 2: Dateien verschieben
```bash
# Dokumentation
mv *.drawio CRITICAL_SECURITY_ASSESSMENT.md SECURITY_FIXES_REPORT.md \
   STRIDE_THREAT_ANALYSIS.md TLS_IMPLEMENTATION.md docs/

# Scripts
mv generate_certs.py run_demo.py scripts/

# Temporäre Dateien
mv Client1 Client2 TestClient TestClient2 .tmp/
mv decrypted*.txt demo_test.txt passwd plain.txt .tmp/ 2>/dev/null || true
```

### Schritt 3: .gitignore aktualisieren
```bash
# Siehe unten für neue .gitignore
```

### Schritt 4: Pfade in Code anpassen
- `run_demo.py`: Pfade zu scripts/
- `generate_certs.py`: Pfade zu scripts/
- Tests: Pfade zu .tmp/

---

## .gitignore (aktualisiert)

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# Virtual Environment
.venv/
venv/
ENV/
env/

# Testing
.pytest_cache/
.coverage
htmlcov/
*.cover

# Temporary Files & Test Artifacts
.tmp/
Client*/
TestClient*/
decrypted*.txt
demo_test.txt
plain.txt
passwd

# TLS Certificates (regenerierbar)
server/cert.pem
server/key.pem

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
```

---

## Best Practices

### ✅ DO:
- Alle Dokumentation in `/docs/`
- Scripts in `/scripts/`
- Test-Artefakte in `.tmp/`
- Vor Commits: `python scripts/cleanup.py`

### ❌ DON'T:
- Client-Verzeichnisse im Root
- Test-Output-Dateien committen
- Zertifikate committen
- Hardcoded Pfade ohne os.path.join()

---

## Automated Cleanup

Verwende `scripts/cleanup.py`:
```bash
python scripts/cleanup.py
# Oder: make clean (wenn Makefile vorhanden)
```

---

**Erstellt:** 12. Februar 2026  
**Version:** 2.0
