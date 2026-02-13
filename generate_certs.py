#!/usr/bin/env python3
"""
Generiert self-signed TLS-Zertifikate für lokalen HTTPS-Server.
Nur für Entwicklung/Demo-Zwecke! Nicht für Production verwenden.
"""
import subprocess
import os
import sys

CERT_FILE = "server/cert.pem"
KEY_FILE = "server/key.pem"

def generate_self_signed_cert():
    """Generiert self-signed Zertifikat mit OpenSSL."""
    
    print("🔐 Generiere self-signed TLS-Zertifikat...")
    
    # Prüfe ob OpenSSL verfügbar ist
    try:
        subprocess.run(["openssl", "version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Error: OpenSSL nicht gefunden!")
        print("   Installation: sudo apt install openssl (Linux) oder brew install openssl (macOS)")
        sys.exit(1)
    
    # Prüfe ob Zertifikate bereits existieren
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print(f"⚠️  Zertifikate existieren bereits:")
        print(f"   {CERT_FILE}")
        print(f"   {KEY_FILE}")
        
        response = input("   Überschreiben? (y/N): ").strip().lower()
        if response != 'y':
            print("✋ Abgebrochen. Verwende bestehende Zertifikate.")
            return
    
    # Generiere Zertifikat
    cmd = [
        "openssl", "req", "-x509",
        "-newkey", "rsa:4096",
        "-nodes",  # Kein Passwort für Private Key
        "-keyout", KEY_FILE,
        "-out", CERT_FILE,
        "-days", "365",
        "-subj", "/CN=localhost/O=RSA-Hybrid-FileCrypter/C=DE"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"✅ Zertifikat generiert:")
        print(f"   Zertifikat: {CERT_FILE}")
        print(f"   Private Key: {KEY_FILE}")
        print(f"   Gültig für: 365 Tage")
        print(f"   Common Name: localhost")
        print()
        print("⚠️  WARNUNG: Self-signed Zertifikat!")
        print("   - Browser zeigen Sicherheitswarnung")
        print("   - Nur für lokale Entwicklung/Demo")
        print("   - Clients verwenden verify=False")
        print()
        print("🚀 Server starten mit: python -m server.app")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error beim Generieren: {e}")
        print(f"   stdout: {e.stdout}")
        print(f"   stderr: {e.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    generate_self_signed_cert()
