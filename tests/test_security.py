# tests/test_security.py
"""
Security Tests - Testet gegen bekannte Angriffsvektoren.

Diese Tests validieren die Sicherheitsmaßnahmen gegen:
- Path Traversal
- Input Validation Bypasses
- Memory Exhaustion (DoS)
- File Size Limits
"""
import pytest
import os
import base64
from server.validation import (
    validate_alias,
    validate_filename,
    validate_uuid,
    validate_payload_size,
    ValidationError,
    MAX_FILE_SIZE_BYTES
)
from clients.crypto import (
    generate_rsa_private,
    pub_to_pem,
    sign_pss,
    aes_gcm_encrypt_file,
    aes_gcm_decrypt_to_file,
    MAX_FILE_SIZE
)


class TestAliasValidation:
    """Tests für Alias Input Validation gegen Exploits"""
    
    def test_valid_alias(self):
        """Testet dass gültige Aliase akzeptiert werden"""
        valid_aliases = ["Client1", "user_123", "test-client", "ABC", "a1b2c3"]
        for alias in valid_aliases:
            assert validate_alias(alias) == alias
    
    def test_path_traversal_attack_blocked(self):
        """SECURITY: Blockt Path Traversal Angriff"""
        malicious_aliases = [
            "../../etc/passwd",
            "../../../tmp/evil",
            "..\\..\\windows\\system32",
            "user/../admin",
            "client1/../../root"
        ]
        for alias in malicious_aliases:
            with pytest.raises(ValidationError, match="path traversal|invalid characters"):
                validate_alias(alias)
    
    def test_special_characters_blocked(self):
        """SECURITY: Blockt Sonderzeichen die gefährlich sein könnten"""
        malicious_aliases = [
            "user<script>",
            "admin'; DROP TABLE--",
            "client\x00null",
            "user\ninjection",
            "test@host.com"
        ]
        for alias in malicious_aliases:
            with pytest.raises(ValidationError):
                validate_alias(alias)
    
    def test_length_limits_enforced(self):
        """SECURITY: Verhindert DoS durch extrem lange Aliase"""
        # Zu kurz
        with pytest.raises(ValidationError, match="between"):
            validate_alias("ab")
        
        # Zu lang (Memory Exhaustion Prevention)
        with pytest.raises(ValidationError, match="between"):
            validate_alias("A" * 1000)
    
    def test_empty_alias_blocked(self):
        """SECURITY: Leere Aliase nicht erlaubt"""
        with pytest.raises(ValidationError, match="required"):
            validate_alias("")
        
        # Whitespace wird als ungültige Zeichen erkannt
        with pytest.raises(ValidationError, match="invalid characters|required"):
            validate_alias("   ")  # Nur Whitespace


class TestFilenameValidation:
    """Tests für Filename Sanitization gegen Path Traversal"""
    
    def test_valid_filename(self):
        """Testet dass gültige Dateinamen akzeptiert werden"""
        assert validate_filename("document.pdf") == "document.pdf"
        assert validate_filename("test_file.txt") == "test_file.txt"
    
    def test_path_traversal_sanitized(self):
        """SECURITY: Path Traversal wird entfernt"""
        dangerous_files = [
            "../../etc/passwd",
            "../../../.ssh/authorized_keys",
            "..\\..\\windows\\win.ini",
            "dir/../../../etc/shadow"
        ]
        for filename in dangerous_files:
            result = validate_filename(filename)
            # Sollte nur den Basename ohne Traversal behalten
            assert ".." not in result
            assert "/" not in result
            assert "\\" not in result
    
    def test_absolute_paths_converted_to_basename(self):
        """SECURITY: Absolute Pfade werden zu Basename reduziert"""
        assert validate_filename("/etc/passwd") == "passwd"
        assert validate_filename("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"
        assert validate_filename("/home/user/secret.txt") == "secret.txt"
    
    def test_null_byte_injection_blocked(self):
        """SECURITY: Null-Byte Injection verhindert"""
        filename = "safe.txt\x00malicious.exe"
        result = validate_filename(filename)
        assert "\x00" not in result
    
    def test_filename_length_limit(self):
        """SECURITY: Extrem lange Dateinamen verhindert"""
        long_filename = "a" * 300 + ".txt"
        with pytest.raises(ValidationError, match="too long"):
            validate_filename(long_filename)
    
    def test_dot_files_handled(self):
        """SECURITY: Versteckte Dateien (.) korrekt behandelt"""
        with pytest.raises(ValidationError, match="Invalid filename"):
            validate_filename(".")
        
        with pytest.raises(ValidationError, match="Invalid filename"):
            validate_filename("..")


class TestUUIDValidation:
    """Tests für UUID Format Validation"""
    
    def test_valid_uuid(self):
        """Testet gültige UUID-Formate"""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert validate_uuid(valid_uuid) == valid_uuid
    
    def test_invalid_uuid_format_blocked(self):
        """SECURITY: Ungültige UUID-Formate blockiert"""
        invalid_uuids = [
            "not-a-uuid",
            "12345678-1234-1234-1234",  # Zu kurz
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  # Nicht hex
            "550e8400-e29b-41d4-a716-446655440000-extra"  # Zu lang
        ]
        for uuid in invalid_uuids:
            with pytest.raises(ValidationError):
                validate_uuid(uuid)
    
    def test_uuid_length_limit(self):
        """SECURITY: Verhindert DoS durch extrem lange UUIDs"""
        long_uuid = "a" * 10000
        with pytest.raises(ValidationError, match="too long|Invalid UUID"):
            validate_uuid(long_uuid)


class TestPayloadSizeValidation:
    """Tests für Payload Size Limits (Memory Exhaustion Prevention)"""
    
    def test_normal_payload_accepted(self):
        """Testet dass normale Payloads akzeptiert werden"""
        payload = {
            "enc_key_b64": "c29tZS1lbmNyeXB0ZWQta2V5",
            "nonce": "cmFuZG9tbm9uY2U=",
            "ciphertext": "ZW5jcnlwdGVkZGF0YQ=="
        }
        # Sollte keine Exception werfen
        validate_payload_size(payload)
    
    def test_large_payload_blocked(self):
        """SECURITY: Verhindert Memory Exhaustion durch riesige Payloads"""
        # Simuliere 25 MB Payload (über Limit von 20 MB)
        huge_ciphertext = "A" * (25 * 1024 * 1024)
        payload = {
            "ciphertext": huge_ciphertext,
            "nonce": "test",
            "enc_key_b64": "test"
        }
        
        with pytest.raises(ValidationError, match="too large"):
            validate_payload_size(payload)
    
    def test_invalid_payload_structure_blocked(self):
        """SECURITY: Ungültige Payload-Strukturen blockiert"""
        # Circular reference (nicht JSON-serialisierbar)
        circular = {}
        circular['self'] = circular
        
        with pytest.raises(ValidationError, match="Invalid payload"):
            validate_payload_size(circular)


class TestFileEncryptionLimits:
    """Tests für File Size Limits in Verschlüsselung"""
    
    def test_normal_file_encryption(self, temp_dir):
        """Testet dass normale Dateien verschlüsselt werden können"""
        file_path = temp_dir / "normal.txt"
        file_path.write_bytes(b"Normal content")
        
        aes_key = os.urandom(32)
        result = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        assert "nonce" in result
        assert "ciphertext" in result
    
    def test_file_too_large_blocked(self, temp_dir):
        """SECURITY: Verhindert Memory Exhaustion durch zu große Dateien"""
        file_path = temp_dir / "huge.bin"
        
        # Erstelle Datei größer als Limit (17 MB)
        huge_size = MAX_FILE_SIZE + (1024 * 1024)  # 17 MB
        with open(file_path, "wb") as f:
            # Schreibe in Chunks um RAM zu schonen
            chunk_size = 1024 * 1024  # 1 MB
            for _ in range(huge_size // chunk_size + 1):
                f.write(b"X" * min(chunk_size, huge_size - f.tell()))
        
        aes_key = os.urandom(32)
        
        with pytest.raises(ValueError, match="File too large"):
            aes_gcm_encrypt_file(aes_key, str(file_path))
    
    def test_decrypt_with_path_traversal_sanitized(self, temp_dir):
        """SECURITY: Path Traversal bei Entschlüsselung verhindert"""
        # Verschlüssele normale Datei
        aes_key = os.urandom(32)
        plaintext = b"Secret content"
        
        # Simuliere verschlüsselte Daten
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        
        nonce_b64 = base64.b64encode(nonce).decode()
        ct_b64 = base64.b64encode(ct).decode()
        
        # Wechsle in temp_dir um saubere Testumgebung zu haben
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_dir)
            
            # Versuche Path Traversal im Output-Pfad
            malicious_path = "../../etc/passwd"
            
            # Die Funktion sollte nur den Basename verwenden ("passwd")
            aes_gcm_decrypt_to_file(aes_key, nonce_b64, ct_b64, malicious_path)
            
            # Prüfe dass Datei im sicheren Verzeichnis (cwd = temp_dir) erstellt wurde
            safe_path = temp_dir / "passwd"
            assert safe_path.exists(), f"Expected file at {safe_path}, got: {list(temp_dir.iterdir())}"
            assert safe_path.read_bytes() == plaintext
            
            # Wichtig: System-Datei /etc/passwd wurde NICHT überschrieben
            import pathlib
            etc_passwd = pathlib.Path("/etc/passwd")
            if etc_passwd.exists():
                # Original /etc/passwd sollte nicht unseren Test-Content haben
                assert etc_passwd.read_bytes() != plaintext
        finally:
            os.chdir(original_cwd)


class TestServerEndpointSecurity:
    """Integration Tests für Server-Endpoint Security"""
    
    def test_register_with_path_traversal_alias_blocked(self, client):
        """SECURITY: /register blockt Path Traversal in Alias"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        
        uuid_resp = client.post('/participate')
        uuid = uuid_resp.get_json()["uuid"]
        sig = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        response = client.post('/register', json={
            "alias": "../../malicious",  # Path Traversal
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig
        })
        
        assert response.status_code == 400
        assert "validation_failed" in response.get_json()["error"]
    
    def test_register_with_oversized_alias_blocked(self, client):
        """SECURITY: /register blockt zu lange Aliase (DoS Prevention)"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        
        uuid_resp = client.post('/participate')
        uuid = uuid_resp.get_json()["uuid"]
        sig = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        response = client.post('/register', json={
            "alias": "A" * 1000,  # Zu lang
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert "validation" in data["error"]
    
    def test_deliver_with_huge_payload_blocked(self, client):
        """SECURITY: /deliver blockt riesige Payloads (Memory Exhaustion)"""
        # Setup: Registriere zwei Clients
        priv1 = generate_rsa_private(bits=2048)
        pub_pem1 = pub_to_pem(priv1.public_key())
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1", "uuid": uuid1,
            "pubkey_pem": pub_pem1.decode(), "uuid_signature": sig1
        })
        
        priv2 = generate_rsa_private(bits=2048)
        pub_pem2 = pub_to_pem(priv2.public_key())
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client2", "uuid": uuid2,
            "pubkey_pem": pub_pem2.decode(), "uuid_signature": sig2
        })
        
        # Versuche riesigen Payload zu senden
        huge_ciphertext = "A" * (25 * 1024 * 1024)  # 25 MB
        deliver_sig = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "Client2",
            "proof_signature": deliver_sig,
            "payload": {
                "enc_key_b64": "dGVzdA==",
                "nonce": "dGVzdA==",
                "ciphertext": huge_ciphertext
            },
            "meta": {}
        })
        
        assert response.status_code == 400
        assert "validation" in response.get_json()["error"]
    
    def test_deliver_with_path_traversal_filename_sanitized(self, client):
        """SECURITY: /deliver sanitiert Dateinamen gegen Path Traversal"""
        # Setup zwei Clients
        priv1 = generate_rsa_private(bits=2048)
        pub_pem1 = pub_to_pem(priv1.public_key())
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1", "uuid": uuid1,
            "pubkey_pem": pub_pem1.decode(), "uuid_signature": sig1
        })
        
        priv2 = generate_rsa_private(bits=2048)
        pub_pem2 = pub_to_pem(priv2.public_key())
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client2", "uuid": uuid2,
            "pubkey_pem": pub_pem2.decode(), "uuid_signature": sig2
        })
        
        # Sende Nachricht mit bösartigem Dateinamen
        deliver_sig = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "Client2",
            "proof_signature": deliver_sig,
            "payload": {"enc_key_b64": "test", "nonce": "test", "ciphertext": "test"},
            "meta": {"filename": "../../etc/passwd"}  # Path Traversal
        })
        
        # Sollte akzeptiert werden, aber filename sanitized
        assert response.status_code == 200
        
        # Hole Nachricht und prüfe sanitierten Filename
        inbox_sig = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        inbox_resp = client.get('/inbox/Client2', headers={"X-Proof": inbox_sig})
        
        messages = inbox_resp.get_json()["messages"]
        assert len(messages) == 1
        # Filename sollte sanitized sein (nur "passwd" ohne Path)
        assert messages[0]["meta"]["filename"] == "passwd"
        assert ".." not in messages[0]["meta"]["filename"]


class TestExceptionHandling:
    """Tests für Exception Handling"""
    
    def test_file_not_found_handled(self, temp_dir):
        """Testet dass FileNotFoundError behandelt wird"""
        from clients.crypto import aes_gcm_encrypt_file
        
        nonexistent = str(temp_dir / "nonexistent.txt")
        aes_key = os.urandom(32)
        
        with pytest.raises(FileNotFoundError):
            aes_gcm_encrypt_file(aes_key, nonexistent)
    
    def test_invalid_json_handled(self, client):
        """Testet dass ungültiges JSON behandelt wird"""
        response = client.post(
            '/register',
            data="invalid json",
            content_type='application/json'
        )
        assert response.status_code == 400


class TestDifferentFileTypes:
    """Tests für verschiedene Dateitypen - stellt sicher dass alle Formate funktionieren"""
    
    def test_text_file_encryption(self, temp_dir):
        """Testet Verschlüsselung von Textdateien"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        file_path = temp_dir / "document.txt"
        content = b"This is a plain text document.\nWith multiple lines.\n"
        file_path.write_bytes(content)
        
        aes_key = os.urandom(32)
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        # Decrypt und verify
        output_path = temp_dir / "decrypted_document.txt"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        assert output_path.read_bytes() == content
    
    def test_pdf_file_encryption(self, temp_dir):
        """Testet Verschlüsselung von PDF-ähnlichen Binärdateien"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        file_path = temp_dir / "document.pdf"
        # Simuliere PDF-Header und Binärdaten
        content = b"%PDF-1.4\n" + os.urandom(1024) + b"\n%%EOF"
        file_path.write_bytes(content)
        
        aes_key = os.urandom(32)
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        output_path = temp_dir / "decrypted_document.pdf"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        assert output_path.read_bytes() == content
    
    def test_executable_file_encryption(self, temp_dir):
        """Testet Verschlüsselung von .exe Dateien (Binärdaten)"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        file_path = temp_dir / "program.exe"
        # Simuliere EXE-Header (MZ magic number) und Binärdaten
        content = b"MZ\x90\x00" + os.urandom(2048)
        file_path.write_bytes(content)
        
        aes_key = os.urandom(32)
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        output_path = temp_dir / "decrypted_program.exe"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        # Verify binary integrity
        assert output_path.read_bytes() == content
        # Verify EXE header preserved
        assert output_path.read_bytes()[:2] == b"MZ"
    
    def test_image_file_encryption(self, temp_dir):
        """Testet Verschlüsselung von Bilddateien"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        file_path = temp_dir / "photo.jpg"
        # Simuliere JPEG-Header und Binärdaten
        content = b"\xFF\xD8\xFF\xE0" + os.urandom(5000) + b"\xFF\xD9"
        file_path.write_bytes(content)
        
        aes_key = os.urandom(32)
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        output_path = temp_dir / "decrypted_photo.jpg"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        assert output_path.read_bytes() == content
    
    def test_zip_archive_encryption(self, temp_dir):
        """Testet Verschlüsselung von ZIP-Archiven"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        file_path = temp_dir / "archive.zip"
        # Simuliere ZIP-Header
        content = b"PK\x03\x04" + os.urandom(3000)
        file_path.write_bytes(content)
        
        aes_key = os.urandom(32)
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        output_path = temp_dir / "decrypted_archive.zip"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        assert output_path.read_bytes() == content
        assert output_path.read_bytes()[:4] == b"PK\x03\x04"
    
    def test_empty_file_encryption(self, temp_dir):
        """Testet Verschlüsselung von leeren Dateien"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        file_path = temp_dir / "empty.dat"
        file_path.write_bytes(b"")
        
        aes_key = os.urandom(32)
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        output_path = temp_dir / "decrypted_empty.dat"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        assert output_path.read_bytes() == b""
        assert output_path.stat().st_size == 0


class TestFileSizeLimits:
    """Detaillierte Tests für Dateigrößen-Limits"""
    
    def test_file_at_max_size_accepted(self, temp_dir):
        """Testet dass Dateien genau am Limit akzeptiert werden"""
        from clients.crypto import aes_gcm_encrypt_file, MAX_FILE_SIZE
        
        file_path = temp_dir / "at_limit.bin"
        # Erstelle Datei genau am Limit (16 MB)
        with open(file_path, "wb") as f:
            chunk_size = 1024 * 1024  # 1 MB chunks
            for _ in range(MAX_FILE_SIZE // chunk_size):
                f.write(b"X" * chunk_size)
        
        assert file_path.stat().st_size == MAX_FILE_SIZE
        
        aes_key = os.urandom(32)
        # Sollte funktionieren
        result = aes_gcm_encrypt_file(aes_key, str(file_path))
        assert "nonce" in result
        assert "ciphertext" in result
    
    def test_file_one_byte_over_limit_rejected(self, temp_dir):
        """Testet dass Dateien auch nur 1 Byte über dem Limit abgelehnt werden"""
        from clients.crypto import aes_gcm_encrypt_file, MAX_FILE_SIZE
        
        file_path = temp_dir / "over_limit.bin"
        # Erstelle Datei 1 Byte über dem Limit
        with open(file_path, "wb") as f:
            chunk_size = 1024 * 1024
            for _ in range(MAX_FILE_SIZE // chunk_size):
                f.write(b"X" * chunk_size)
            f.write(b"Y")  # 1 extra byte
        
        assert file_path.stat().st_size == MAX_FILE_SIZE + 1
        
        aes_key = os.urandom(32)
        with pytest.raises(ValueError, match="File too large"):
            aes_gcm_encrypt_file(aes_key, str(file_path))
    
    def test_different_size_files(self, temp_dir):
        """Testet verschiedene Dateigrößen unter dem Limit"""
        from clients.crypto import aes_gcm_encrypt_file
        
        test_sizes = [
            1,                      # 1 Byte
            1024,                   # 1 KB
            1024 * 100,             # 100 KB
            1024 * 1024,            # 1 MB
            1024 * 1024 * 5,        # 5 MB
            1024 * 1024 * 10,       # 10 MB
        ]
        
        aes_key = os.urandom(32)
        
        for size in test_sizes:
            file_path = temp_dir / f"file_{size}.bin"
            file_path.write_bytes(b"X" * size)
            
            # Alle sollten funktionieren
            result = aes_gcm_encrypt_file(aes_key, str(file_path))
            assert "nonce" in result
            assert "ciphertext" in result
    
    def test_filename_formats_all_accepted(self, temp_dir):
        """Testet dass verschiedene Dateiendungen akzeptiert werden"""
        from clients.crypto import aes_gcm_encrypt_file
        
        extensions = [
            "txt", "pdf", "doc", "docx", "xls", "xlsx", 
            "jpg", "png", "gif", "bmp", "svg",
            "exe", "dll", "so", "dylib",
            "zip", "tar", "gz", "7z", "rar",
            "mp3", "mp4", "avi", "mkv",
            "py", "js", "java", "cpp", "h"
        ]
        
        aes_key = os.urandom(32)
        
        for ext in extensions:
            file_path = temp_dir / f"testfile.{ext}"
            file_path.write_bytes(b"Test content for " + ext.encode())
            
            # Alle Dateitypen sollten verschlüsselbar sein
            result = aes_gcm_encrypt_file(aes_key, str(file_path))
            assert "nonce" in result
            assert "ciphertext" in result
    
    def test_special_filename_characters_handled(self, temp_dir):
        """Testet dass Dateien mit Sonderzeichen im Namen funktionieren"""
        from clients.crypto import aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
        
        # Erlaubte Sonderzeichen in Dateinamen
        special_names = [
            "file-with-dashes.txt",
            "file_with_underscores.txt",
            "file.multiple.dots.txt",
            "file (with parentheses).txt",
            "file [with brackets].txt",
        ]
        
        aes_key = os.urandom(32)
        
        for name in special_names:
            file_path = temp_dir / name
            content = f"Content for {name}".encode()
            file_path.write_bytes(content)
            
            encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
            
            output_path = temp_dir / f"dec_{name}"
            aes_gcm_decrypt_to_file(
                aes_key,
                encrypted["nonce"],
                encrypted["ciphertext"],
                str(output_path)
            )
            
            assert output_path.read_bytes() == content
