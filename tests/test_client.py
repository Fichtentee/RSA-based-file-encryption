# tests/test_client.py
import pytest
import os
import json
import base64
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call
from clients.client import get_client_dirs, save_keypair, load_priv, main
from clients.crypto import generate_rsa_private, pub_to_pem, priv_to_pem
import sys


class TestGetClientDirs:
    """Tests für get_client_dirs Funktion"""
    
    def test_returns_correct_structure(self):
        """Testet dass korrekte Verzeichnisstruktur zurückgegeben wird"""
        alias = "testclient"
        dirs = get_client_dirs(alias)
        
        assert "base" in dirs
        assert "own" in dirs
        assert "partner_keys" in dirs
        assert "received" in dirs
    
    def test_base_path_contains_alias(self):
        """Testet dass Basis-Pfad den Alias enthält"""
        alias = "alice"
        dirs = get_client_dirs(alias)
        
        assert alias in dirs["base"]
        assert dirs["base"] == f"./.tmp/{alias}"
    
    def test_subdirectories_are_relative_to_base(self):
        """Testet dass Unterverzeichnisse relativ zum Basis-Pfad sind"""
        alias = "bob"
        dirs = get_client_dirs(alias)
        
        assert dirs["own"].startswith(dirs["base"])
        assert dirs["partner_keys"].startswith(dirs["base"])
        assert dirs["received"].startswith(dirs["base"])
    
    def test_different_aliases_have_different_dirs(self):
        """Testet dass unterschiedliche Aliases unterschiedliche Verzeichnisse haben"""
        dirs1 = get_client_dirs("alice")
        dirs2 = get_client_dirs("bob")
        
        assert dirs1["base"] != dirs2["base"]
        assert dirs1["own"] != dirs2["own"]


class TestSaveKeypair:
    """Tests für save_keypair Funktion"""
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    def test_creates_directory(self, mock_makedirs, mock_file):
        """Testet dass Verzeichnis erstellt wird"""
        priv = generate_rsa_private(bits=2048)
        path_prefix = "test/path/client"
        
        save_keypair(path_prefix, priv)
        
        mock_makedirs.assert_called_once()
        call_args = mock_makedirs.call_args[0][0]
        assert "test/path" in call_args
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    def test_writes_private_key(self, mock_makedirs, mock_file):
        """Testet dass Private Key geschrieben wird"""
        priv = generate_rsa_private(bits=2048)
        path_prefix = "test/client"
        
        save_keypair(path_prefix, priv)
        
        # Prüfe ob Dateien geöffnet wurden
        calls = mock_file.call_args_list
        assert any("_priv.pem" in str(call) for call in calls)
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    def test_writes_public_key(self, mock_makedirs, mock_file):
        """Testet dass Public Key geschrieben wird"""
        priv = generate_rsa_private(bits=2048)
        path_prefix = "test/client"
        
        save_keypair(path_prefix, priv)
        
        # Prüfe ob Dateien geöffnet wurden
        calls = mock_file.call_args_list
        assert any("_pub.pem" in str(call) for call in calls)
    
    def test_integration_with_real_files(self, temp_dir):
        """Integrationstest mit echten Dateien"""
        priv = generate_rsa_private(bits=2048)
        path_prefix = str(temp_dir / "keys" / "testclient")
        
        save_keypair(path_prefix, priv)
        
        # Prüfe ob Dateien existieren
        assert os.path.exists(path_prefix + "_priv.pem")
        assert os.path.exists(path_prefix + "_pub.pem")
        
        # Prüfe ob Dateien Inhalt haben
        assert os.path.getsize(path_prefix + "_priv.pem") > 0
        assert os.path.getsize(path_prefix + "_pub.pem") > 0


class TestLoadPriv:
    """Tests für load_priv Funktion"""
    
    def test_loads_valid_key(self, temp_dir):
        """Testet dass gültiger Key geladen wird"""
        # Erstelle Test-Key
        priv = generate_rsa_private(bits=2048)
        key_path = temp_dir / "test_priv.pem"
        key_path.write_bytes(priv_to_pem(priv))
        
        # Lade Key
        loaded_priv = load_priv(str(key_path))
        
        assert loaded_priv is not None
        # Prüfe ob es der gleiche Key ist durch Vergleich der Public Keys
        assert pub_to_pem(loaded_priv.public_key()) == pub_to_pem(priv.public_key())
    
    def test_raises_on_missing_file(self):
        """Testet dass FileNotFoundError bei fehlender Datei geworfen wird"""
        with pytest.raises(FileNotFoundError):
            load_priv("/nonexistent/path/key.pem")
    
    @patch('builtins.open')
    def test_handles_permission_error(self, mock_file):
        """Testet Behandlung von PermissionError"""
        mock_file.side_effect = PermissionError("Access denied")
        
        with pytest.raises(PermissionError):
            load_priv("test.pem")
    
    def test_raises_on_invalid_key_format(self, temp_dir):
        """Testet dass Exception bei ungültigem Key-Format geworfen wird"""
        key_path = temp_dir / "invalid.pem"
        key_path.write_text("INVALID KEY DATA")
        
        with pytest.raises(Exception):
            load_priv(str(key_path))


class TestMainGenkeys:
    """Tests für main() Funktion mit genkeys Kommando"""
    
    @patch('clients.client.save_keypair')
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'testclient', 'genkeys'])
    def test_genkeys_generates_and_saves_keys(self, mock_makedirs, mock_save):
        """Testet dass genkeys Befehl Keys generiert und speichert"""
        main()
        
        # Verify dass save_keypair aufgerufen wurde
        mock_save.assert_called_once()
        
        # Verify dass private key übergeben wurde
        call_args = mock_save.call_args[0]
        assert call_args[1] is not None  # private key
    
    @patch('clients.client.save_keypair')
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'alice', '--key-prefix', 'custom/path', 'genkeys'])
    def test_genkeys_uses_custom_key_prefix(self, mock_makedirs, mock_save):
        """Testet dass custom key-prefix verwendet wird"""
        main()
        
        # Verify dass custom path verwendet wurde
        call_args = mock_save.call_args[0]
        assert "custom/path" in call_args[0]


class TestMainRegister:
    """Tests für main() Funktion mit register Kommando"""
    
    @patch('requests.post')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'testclient', '--no-verify-ssl', 'register'])
    def test_register_calls_participate_and_register(self, mock_makedirs, mock_file, mock_load, mock_post):
        """Testet dass register Befehl participate und register aufruft"""
        # Setup
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        # Mock participate response
        participate_response = MagicMock()
        participate_response.json.return_value = {"uuid": "test-uuid-1234"}
        
        # Mock register response
        register_response = MagicMock()
        register_response.json.return_value = {"status": "registered"}
        
        mock_post.side_effect = [participate_response, register_response]
        
        # Execute
        main()
        
        # Verify: 2 POST requests (participate + register)
        assert mock_post.call_count == 2
        
        # Verify participate call
        assert "/participate" in mock_post.call_args_list[0][0][0]
        
        # Verify register call
        assert "/register" in mock_post.call_args_list[1][0][0]
    
    @patch('requests.post')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'bob', '--server', 'https://custom.server:8000', '--no-verify-ssl', 'register'])
    def test_register_uses_custom_server(self, mock_makedirs, mock_file, mock_load, mock_post):
        """Testet dass custom server URL verwendet wird"""
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        participate_response = MagicMock()
        participate_response.json.return_value = {"uuid": "test-uuid"}
        register_response = MagicMock()
        register_response.json.return_value = {"status": "ok"}
        
        mock_post.side_effect = [participate_response, register_response]
        
        main()
        
        # Verify dass custom server verwendet wurde
        assert "https://custom.server:8000" in mock_post.call_args_list[0][0][0]


class TestMainRequest:
    """Tests für main() Funktion mit request Kommando"""
    
    @patch('requests.post')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'alice', '--no-verify-ssl', 'request', '--partner', 'bob'])
    def test_request_retrieves_partner_key(self, mock_makedirs, mock_file, mock_load, mock_post):
        """Testet dass request Befehl Partner-Key abruft"""
        # Setup
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        # Mock UUID file read
        mock_file.return_value.read.return_value = '{"uuid": "alice-uuid"}'
        
        # Mock server response
        response = MagicMock()
        response.ok = True
        response.json.return_value = {"partner_pubkey_pem": "PUBLIC KEY DATA"}
        mock_post.return_value = response
        
        # Execute
        main()
        
        # Verify POST to request_partner
        mock_post.assert_called_once()
        assert "/request_partner" in mock_post.call_args[0][0]
        
        # Verify request body
        request_body = mock_post.call_args[1]["json"]
        assert request_body["from_alias"] == "alice"
        assert request_body["partner_alias"] == "bob"
        assert "proof_signature" in request_body


class TestMainSend:
    """Tests für main() Funktion mit send Kommando"""
    
    @patch('requests.post')
    @patch('clients.client.load_priv')
    @patch('clients.client.load_pub')
    @patch('clients.client.aes_gcm_encrypt_file')
    @patch('os.urandom')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('os.path.basename')
    @patch('sys.argv', ['client.py', '--alias', 'alice', '--no-verify-ssl', 'send', '--partner', 'bob', '--file', 'test.txt'])
    def test_send_encrypts_and_delivers_file(self, mock_basename, mock_makedirs, mock_file, mock_urandom, 
                                             mock_encrypt, mock_load_pub, mock_load_priv, mock_post):
        """Testet dass send Befehl Datei verschlüsselt und sendet"""
        # Setup
        priv = generate_rsa_private(bits=2048)
        partner_priv = generate_rsa_private(bits=2048)
        mock_load_priv.return_value = priv
        mock_load_pub.return_value = partner_priv.public_key()
        mock_basename.return_value = "test.txt"
        
        # Mock AES key
        mock_urandom.return_value = b"0" * 32
        
        # Mock encryption result
        mock_encrypt.return_value = {
            "nonce": "nonce123",
            "ciphertext": "encrypted_data"
        }
        
        # Mock UUID file
        mock_file.return_value.read.return_value = '{"uuid": "alice-uuid"}'
        
        # Mock server response
        response = MagicMock()
        response.ok = True
        response.json.return_value = {"status": "delivered"}
        mock_post.return_value = response
        
        # Execute
        main()
        
        # Verify POST to deliver
        mock_post.assert_called_once()
        assert "/deliver" in mock_post.call_args[0][0]
        
        # Verify request body
        request_body = mock_post.call_args[1]["json"]
        assert request_body["from_alias"] == "alice"
        assert request_body["to_alias"] == "bob"
        assert "payload" in request_body
        assert "meta" in request_body


class TestMainReceive:
    """Tests für main() Funktion mit receive Kommando"""
    
    @patch('requests.get')
    @patch('clients.client.load_priv')
    @patch('clients.client.aes_gcm_decrypt_to_file')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('os.path.join')
    @patch('os.path.basename')
    @patch('sys.argv', ['client.py', '--alias', 'alice', '--no-verify-ssl', 'receive'])
    def test_receive_gets_and_decrypts_messages(self, mock_basename, mock_join, mock_makedirs, 
                                                mock_file, mock_decrypt, mock_load, mock_get):
        """Testet dass receive Befehl Nachrichten abruft und entschlüsselt"""
        # Setup
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        mock_basename.side_effect = lambda x: x.split('/')[-1] if '/' in x else x
        mock_join.side_effect = lambda *args: '/'.join(args)
        
        # Mock UUID file
        mock_file.return_value.read.return_value = '{"uuid": "alice-uuid"}'
        
        # Mock encrypted AES key
        from clients.crypto import rsa_oaep_encrypt
        aes_key = b"0" * 32
        enc_key = rsa_oaep_encrypt(priv.public_key(), aes_key)
        
        # Mock server response
        response = MagicMock()
        response.ok = True
        response.json.return_value = {
            "messages": [
                {
                    "from_alias": "bob",
                    "payload": {
                        "enc_key_b64": base64.b64encode(enc_key).decode(),
                        "nonce": "nonce123",
                        "ciphertext": "encrypted_data"
                    },
                    "meta": {"filename": "test.txt"}
                }
            ]
        }
        mock_get.return_value = response
        
        # Execute
        main()
        
        # Verify GET to inbox
        mock_get.assert_called_once()
        assert "/inbox/alice" in mock_get.call_args[0][0]
        
        # Verify decryption was called
        mock_decrypt.assert_called_once()
    
    @patch('requests.get')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'bob', '--no-verify-ssl', 'receive'])
    def test_receive_handles_empty_inbox(self, mock_makedirs, mock_file, mock_load, mock_get):
        """Testet dass leere Inbox korrekt behandelt wird"""
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        mock_file.return_value.read.return_value = '{"uuid": "bob-uuid"}'
        
        response = MagicMock()
        response.ok = True
        response.json.return_value = {"messages": []}
        mock_get.return_value = response
        
        # Execute - sollte nicht fehlschlagen
        main()
        
        mock_get.assert_called_once()
    
    @patch('requests.get')
    @patch('clients.client.load_priv')
    @patch('clients.client.aes_gcm_decrypt_to_file')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('os.path.join')
    @patch('os.path.basename')
    @patch('sys.argv', ['client.py', '--alias', 'alice', '--no-verify-ssl', 'receive'])
    def test_receive_sanitizes_filenames(self, mock_basename, mock_join, mock_makedirs, 
                                        mock_file, mock_decrypt, mock_load, mock_get):
        """Testet dass Dateinamen sanitized werden (Path Traversal Prevention)"""
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        # Mock basename to pass through
        mock_basename.side_effect = lambda x: x.split('/')[-1] if '/' in x else x
        mock_join.side_effect = lambda *args: '/'.join(args)
        
        mock_file.return_value.read.return_value = '{"uuid": "alice-uuid"}'
        
        # Malicious filename with path traversal
        from clients.crypto import rsa_oaep_encrypt
        aes_key = b"0" * 32
        enc_key = rsa_oaep_encrypt(priv.public_key(), aes_key)
        
        response = MagicMock()
        response.ok = True
        response.json.return_value = {
            "messages": [
                {
                    "from_alias": "bob",
                    "payload": {
                        "enc_key_b64": base64.b64encode(enc_key).decode(),
                        "nonce": "nonce123",
                        "ciphertext": "data"
                    },
                    "meta": {"filename": "../../../etc/passwd"}
                }
            ]
        }
        mock_get.return_value = response
        
        # Execute
        main()
        
        # Verify decrypt was called with sanitized filename
        decrypt_call = mock_decrypt.call_args[0][3]
        # Should not contain path traversal
        assert "../" not in decrypt_call
        assert "from_bob" in decrypt_call


class TestSSLVerification:
    """Tests für SSL-Verifikation"""
    
    @patch('requests.post')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'test', 'register'])
    def test_ssl_verification_enabled_by_default(self, mock_makedirs, mock_file, mock_load, mock_post):
        """Testet dass SSL-Verifikation standardmäßig aktiviert ist"""
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        participate_response = MagicMock()
        participate_response.json.return_value = {"uuid": "test-uuid"}
        register_response = MagicMock()
        register_response.json.return_value = {"status": "ok"}
        
        mock_post.side_effect = [participate_response, register_response]
        
        main()
        
        # Verify dass verify=True übergeben wurde
        for call in mock_post.call_args_list:
            assert call[1].get('verify') == True
    
    @patch('requests.post')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'test', '--no-verify-ssl', 'register'])
    def test_ssl_verification_can_be_disabled(self, mock_makedirs, mock_file, mock_load, mock_post):
        """Testet dass SSL-Verifikation deaktiviert werden kann"""
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        participate_response = MagicMock()
        participate_response.json.return_value = {"uuid": "test-uuid"}
        register_response = MagicMock()
        register_response.json.return_value = {"status": "ok"}
        
        mock_post.side_effect = [participate_response, register_response]
        
        main()
        
        # Verify dass verify=False übergeben wurde
        for call in mock_post.call_args_list:
            assert call[1].get('verify') == False


class TestErrorHandling:
    """Tests für Fehlerbehandlung"""
    
    @patch('sys.argv', ['client.py', '--alias', 'test'])
    def test_missing_subcommand_raises_error(self):
        """Testet dass fehlender Subcommand einen Fehler auslöst"""
        with pytest.raises(SystemExit):
            main()
    
    @patch('sys.argv', ['client.py', 'register'])
    def test_missing_required_alias_raises_error(self):
        """Testet dass fehlender Alias einen Fehler auslöst"""
        with pytest.raises(SystemExit):
            main()
    
    @patch('requests.get')
    @patch('clients.client.load_priv')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs')
    @patch('sys.argv', ['client.py', '--alias', 'alice', '--no-verify-ssl', 'receive'])
    def test_receive_handles_server_error(self, mock_makedirs, mock_file, mock_load, mock_get):
        """Testet dass Server-Fehler korrekt behandelt werden"""
        priv = generate_rsa_private(bits=2048)
        mock_load.return_value = priv
        
        mock_file.return_value.read.return_value = '{"uuid": "alice-uuid"}'
        
        # Server error
        response = MagicMock()
        response.ok = False
        response.status_code = 500
        response.text = "Internal Server Error"
        mock_get.return_value = response
        
        # Should not raise exception
        main()


@pytest.mark.integration
class TestClientIntegration:
    """Integrationstests mit echtem Dateisystem"""
    
    def test_full_genkeys_flow(self, temp_dir):
        """Integrationstest für Key-Generierung"""
        with patch('sys.argv', ['client.py', '--alias', 'testclient', 
                                '--key-prefix', str(temp_dir / 'client'), 'genkeys']):
            main()
        
        # Verify dass Keys erstellt wurden
        assert os.path.exists(str(temp_dir / 'client_priv.pem'))
        assert os.path.exists(str(temp_dir / 'client_pub.pem'))
