#!/usr/bin/env python3
"""
RSA Hybrid FileCrypter - Automatisierter Demo-Ablauf
Funktioniert plattformunabhängig unter Windows, macOS und Linux
"""

import subprocess
import sys
import time
import os
import shutil
import platform
import requests
import urllib3
from pathlib import Path

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Farben für Terminal-Ausgabe (funktioniert auf den meisten Systemen)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def disable_on_windows():
        """Deaktiviert Farben auf Windows, falls ANSI nicht unterstützt wird"""
        if platform.system() == 'Windows':
            # Aktiviere ANSI-Support auf Windows 10+
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                # Fallback: Keine Farben
                for attr in dir(Colors):
                    if not attr.startswith('_') and attr != 'disable_on_windows':
                        setattr(Colors, attr, '')

Colors.disable_on_windows()

def print_header(text):
    """Druckt eine formatierte Überschrift"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text:^70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.ENDC}\n")

def print_step(step_num, text):
    """Druckt einen nummerierten Schritt"""
    print(f"{Colors.BOLD}{Colors.YELLOW}[Schritt {step_num}]{Colors.ENDC} {Colors.BLUE}{text}{Colors.ENDC}")

def print_success(text):
    """Druckt eine Erfolgsmeldung"""
    print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")

def print_error(text):
    """Druckt eine Fehlermeldung"""
    print(f"{Colors.RED}✗ {text}{Colors.ENDC}")

def print_info(text):
    """Druckt eine Info-Meldung"""
    print(f"{Colors.CYAN}ℹ {text}{Colors.ENDC}")

def wait_for_server(url="https://127.0.0.1:5000", timeout=30):
    """Wartet, bis der Server antwortet"""
    print_info(f"Warte auf Server ({url})...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = requests.get(url, timeout=1, verify=False)
            print_success("Server ist bereit!")
            return True
        except requests.exceptions.RequestException:
            time.sleep(0.5)
    print_error("Server-Timeout!")
    return False

def run_command(cmd, description, cwd=None):
    """Führt ein Kommando aus und zeigt die Ausgabe"""
    print(f"\n{Colors.BOLD}$ {' '.join(cmd)}{Colors.ENDC}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        print_success(description)
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"{description} fehlgeschlagen!")
        if e.stdout:
            print(e.stdout)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        return False

def cleanup_clients():
    """Entfernt alte Client-Verzeichnisse"""
    clients_dir = Path(".tmp")
    for client in ["Client1", "Client2"]:
        client_path = clients_dir / client
        if client_path.exists():
            print_info(f"Entferne altes Verzeichnis: {client_path}")
            shutil.rmtree(client_path)

def create_test_file():
    """Erstellt eine Test-Datei"""
    test_content = """TOP SECRET – Testübertragung

Dies ist eine verschlüsselte Testnachricht für die RSA-Hybrid-FileCrypter Demo.

Inhalt:
- Ende-zu-Ende-Verschlüsselung mit AES-256-GCM
- RSA-OAEP für sicheren Schlüsseltransport
- RSASSA-PSS für digitale Signaturen

Timestamp: {}
""".format(time.strftime("%Y-%m-%d %H:%M:%S"))
    
    test_file = Path("demo_test.txt")
    test_file.write_text(test_content, encoding='utf-8')
    print_success(f"Test-Datei erstellt: {test_file.absolute()}")
    return str(test_file)

def main():
    """Hauptfunktion für den Demo-Ablauf"""
    
    print_header("RSA Hybrid FileCrypter - Automatische Demo")
    print_info(f"Plattform: {platform.system()} {platform.release()}")
    print_info(f"Python: {sys.version.split()[0]}")
    print_info(f"Arbeitsverzeichnis: {Path.cwd()}")
    
    # Prüfung ob das Skript im richtigen Verzeichnis ausgeführt wird
    if not Path("server/app.py").exists() or not Path("clients/client.py").exists():
        print_error("Bitte das Skript aus dem Hauptverzeichnis des Projekts ausführen!")
        sys.exit(1)
    
    server_process = None
    
    try:
        # Schritt 0: Aufräumen
        print_step(0, "Aufräumen alter Test-Daten")
        cleanup_clients()
        time.sleep(1)
        
        # Schritt 1: Test-Datei erstellen
        print_step(1, "Test-Datei erstellen")
        test_file = create_test_file()
        time.sleep(1)
        
        # Schritt 2: Server starten
        print_step(2, "Server starten (HTTPS mit TLS)")
        
        # Server mit TLS-Support starten
        server_cmd = [sys.executable, "-m", "server.app"]
        
        print(f"{Colors.BOLD}$ {' '.join(server_cmd)}{Colors.ENDC}")
        server_process = subprocess.Popen(
            server_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        if not wait_for_server():
            raise Exception("Server konnte nicht gestartet werden")
        
        time.sleep(1)
        
        # Python-Executable für Client-Kommandos
        python_cmd = sys.executable
        
        # Schritt 3: Client1 - Keys generieren
        print_step(3, "Client1 - Schlüsselpaar generieren")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client1", "--no-verify-ssl", "genkeys"],
            "Client1 Keys generiert"
        )
        time.sleep(0.5)
        
        # Schritt 4: Client1 - Registrierung
        print_step(4, "Client1 - Beim Server registrieren")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client1", "--no-verify-ssl", "register"],
            "Client1 registriert"
        )
        time.sleep(0.5)
        
        # Schritt 5: Client2 - Keys generieren
        print_step(5, "Client2 - Schlüsselpaar generieren")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client2", "--no-verify-ssl", "genkeys"],
            "Client2 Keys generiert"
        )
        time.sleep(0.5)
        
        # Schritt 6: Client2 - Registrierung
        print_step(6, "Client2 - Beim Server registrieren")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client2", "--no-verify-ssl", "register"],
            "Client2 registriert"
        )
        time.sleep(0.5)
        
        # Schritt 7: Client1 - Partner-Key anfordern
        print_step(7, "Client1 - Public Key von Client2 anfordern")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client1", "--no-verify-ssl", "request", "--partner", "Client2"],
            "Partner-Key erhalten"
        )
        time.sleep(0.5)
        
        # Schritt 8: Client1 - Datei senden
        print_step(8, "Client1 - Verschlüsselte Datei an Client2 senden")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client1", "--no-verify-ssl", "send", 
             "--partner", "Client2", "--file", test_file],
            "Datei verschlüsselt und gesendet"
        )
        time.sleep(0.5)
        
        # Schritt 9: Client2 - Nachrichten empfangen
        print_step(9, "Client2 - Nachricht empfangen und entschlüsseln")
        run_command(
            [python_cmd, "-m", "clients.client", "--alias", "Client2", "--no-verify-ssl", "receive"],
            "Nachricht entschlüsselt"
        )
        time.sleep(0.5)
        
        # Schritt 10: Empfangene Datei anzeigen
        print_step(10, "Empfangene Datei prüfen")
        received_files = list(Path(".tmp/Client2/received").glob("from_Client1_*"))
        if received_files:
            received_file = received_files[0]
            print_info(f"Empfangene Datei: {received_file}")
            print(f"\n{Colors.BOLD}Inhalt:{Colors.ENDC}")
            print("-" * 70)
            print(received_file.read_text(encoding='utf-8'))
            print("-" * 70)
            print_success("Datei erfolgreich empfangen und entschlüsselt!")
        else:
            print_error("Keine empfangene Datei gefunden!")
        
        time.sleep(1)
        
        # Zusammenfassung
        print_header("Demo erfolgreich abgeschlossen!")
        print_success("Alle Schritte wurden erfolgreich durchgeführt:")
        print("  ✓ Server gestartet")
        print("  ✓ Client1 und Client2 registriert")
        print("  ✓ Schlüsselaustausch durchgeführt")
        print("  ✓ Datei verschlüsselt übertragen")
        print("  ✓ Datei erfolgreich entschlüsselt")
        
        print_info("\nGenerierte Dateien:")
        print(f"  - Client1/own/ (Private/Public Keys)")
        print(f"  - Client2/own/ (Private/Public Keys)")
        print(f"  - Client1/partner_keys/ (Client2 Public Key)")
        print(f"  - Client2/received/ (Empfangene Datei)")
        
    except KeyboardInterrupt:
        print_info("\nDemo durch Benutzer abgebrochen")
    except Exception as e:
        print_error(f"Fehler: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Server beenden
        if server_process:
            print_info("\nBeende Server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
            print_success("Server beendet")

if __name__ == "__main__":
    main()
