# RSA Hybrid FileCrypter (Prototype)

**Zweck:** Ende‑zu‑Ende‑Verschlüsselung von Dateien zwischen zwei Clients über einen unsicheren Kanal.  
**Kryptografie:** AES‑256‑GCM (Datei), RSA‑OAEP (Key‑Transport), RSASSA‑PSS (Identitätsnachweis).


Die Nutzdaten werden mit AES verschlüsselt, der jeweilige AES‑Key wird per RSA durch den Empfänger‑Public‑Key verschlüsselt. Die Client‑Authentizität wird über RSASSA‑PSS (SHA‑256) sichergestellt, indem der Client Server‑seitig ausgestellte UUIDs signiert. Der Server vermittelt Nachrichten, verarbeitet jedoch nie Klartext oder Private Keys. Nonces sind pro Verschlüsselung einzigartig, AAD bindet Sender‑Alias an die Ciphertexts. Damit wird Vertraulichkeit, Integrität und nicht-Abstreitbarkeit für transport und in-rest (Datenrückstände auf Server) erreicht.

## Verzeichnisstruktur

Jeder Client erhält automatisch eine eigene, strukturierte Verzeichnishierarchie:

```
.tmp/
├── Client1/
│   ├── own/                    # Eigene Keys + UUID
│   │   ├── Client1_priv.pem
│   │   ├── Client1_pub.pem
│   │   └── Client1_uuid.json
│   ├── partner_keys/           # Public Keys von Partnern
│   │   └── Client2_pub.pem
│   └── received/               # Empfangene & entschlüsselte Dateien
│       └── from_Client2_*.txt
├── Client2/
│   ├── own/
│   ├── partner_keys/
│   └── received/
└── ...
```

<!-- **Vorteile:**
- 🗂️ Klare Trennung zwischen eigenen Keys, Partner-Keys und empfangenen Dateien
- 📁 Mehrere Clients können parallel existieren
- 🧹 Einfaches Aufräumen durch Löschen der Client-Ordnern -->

## Demo:

### 🚀 Option 1: Automatische Demo

Das Skript `run_demo.py` führt den kompletten Testablauf automatisch aus und funktioniert **plattformunabhängig** unter Windows, macOS und Linux (muss ausführbar gemacht werden):

```bash
# 1. TLS-Zertifikate generieren (nur beim ersten Mal nötig)
./generate_certs.py

# 2. Demo ausführen
./run_demo.py
```

**Ablauf der Demo:**
1. ✓ Server starten (mit HTTPS/TLS)
2. ✓ Client1 & Client2 Keys generieren und registrieren
3. ✓ Schlüsselaustausch durchführen
4. ✓ Test-Datei verschlüsselt übertragen
5. ✓ Datei empfangen und entschlüsseln


---

### 🔧 Option 2: Manuelle Ausführung

> **💡 Hinweis:** Die automatische Demo (Option 1) ist empfohlen und einfacher!  
> Die manuelle Ausführung erfordert 3 separate Terminal-Fenster.

Einzelne Schritte für die manuelle Ausführung:

#### Vorbereitung: TLS-Zertifikate generieren
```bash
# Nur beim ersten Mal nötig
./generate_certs.py
```

<!-- **Wichtig:** 
- Der Server läuft mit HTTPS und self-signed Zertifikaten
- Bei allen Client-Befehlen muss `--no-verify-ssl` verwendet werden
- Der Server muss in einem **separaten Terminal-Fenster** laufen (nicht im Hintergrund mit `&`) -->

#### Konsolenfenster 1 – Server starten:
```bash
# Im Projektverzeichnis
python -m server.app
# Server läuft jetzt auf https://127.0.0.1:5000
# Dieses Fenster offen lassen!
```

#### Konsolenfenster 2 – Client1 starten:
```bash
python -m clients.client --alias Client1 --no-verify-ssl genkeys
python -m clients.client --alias Client1 --no-verify-ssl register
```

#### Konsolenfenster 3 – Client2 starten:
```bash
python -m clients.client --alias Client2 --no-verify-ssl genkeys
python -m clients.client --alias Client2 --no-verify-ssl register
```

#### in Konsolenfenster 2: Partner-Key als Client1 von Client2 anfordern
```bash
python -m clients.client --alias Client1 --no-verify-ssl request --partner Client2
```

#### in Konsolenfenster 2: Datei senden
##### Verfügbare Testdateien:
Im Verzeichnis `files/` befinden sich vorgefertigte Testdateien:
- **secret_message.txt** - Geheime Projektnachricht
- **meeting_notes.txt** - Vertrauliche Meeting-Notizen
- **credentials.txt** - Sensible Zugangsdaten
- **contract_draft.pdf** - PDF-Vertrag (zeigt, dass alle Dateitypen funktionieren!)


```bash
# Option 1: Quicktest mit echo
echo "TOP SECRET – hello Client2" > test.txt
python -m clients.client --alias Client1 --no-verify-ssl send --partner Client2 --file ./test.txt

# Option 2: Senden existierender Textdatei
python -m clients.client --alias Client1 --no-verify-ssl send --partner Client2 --file ./files/credentials.txt

# Option 3: Senden existierender Datei (z. B. PDF)
python -m clients.client --alias Client1 --no-verify-ssl send --partner Client2 --file ./files/contract_draft.pdf
```

#### in Konsolenfenster 3: Empfang & Entschlüsselung der Datei
```bash
python -m clients.client --alias Client2 --no-verify-ssl receive
# Dateien werden automatisch in Client2/received/ gespeichert
```

---

## Aufräumen

Um alle Client-Daten zu löschen und neu zu starten zu können:

Clients manuell im Dateimanager löschen oder per command

```bash
# Alle Clients entfernen
rm -rf Client*/
```

---

## Ausblick nach akzeptiertem Prototyp

- **Chunk‑Streaming**: für größere Dateien (>16 MB) als Ausblick sinnvoll. Aktuell wird alles auf einmal im RAM verarbeitet, durch Originaltext, Ciphertext, Base64-String und JSON wird ungefähr die dreifache Menge an RAM benötigt, wie die Datei selbst groß ist. Zudem besteht das default Flask Limit von 16 MB. Daher wird empfohlen den filecrypter nur für max. 10 MB große Dateien zu verwenden.
- **Persistenz**: `server/storage.py` auf z. B. SQLite umstellen, sonst gehen Daten (Client alias und die Zuordnung zum öffentlichem Schlüssel) nach einem Neustart verloren.
<!-- Nice to have: - **/whoami**‑Endpoint: gibt `alias` entsprechende `uuid` zurück (hilft Clients ggf. bei einer Selbstüberprüfung). -->
<!-- Umgesetzt: - **AAD**: Absender-Name (Client1)schützt vor „gefälschten Absender“-Angriffen,
Dateiname verhindert, dass Angreifer z. B. test.txt zu passwort.txt manipulieren,
Sequence Numbers / IDs verhindert Replay-AngriffeProtokollheaderschützt Routing-Informationen -->

---


<!-- # Todo:

- DFD Code anpassen
- Security fixes in report refacotoring aufnehmen
- TLS implementation nennen als Entwicklung für Production use, hier nur Hybridansatz für Files
- neues security assessment nutzen um Fehler zu bewerten und zu beheben sowie im refactoring zu nennen -->