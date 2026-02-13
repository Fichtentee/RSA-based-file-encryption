# tests/test_generate_certs.py
import pytest
import subprocess
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import sys

# Import der zu testenden Funktion
from generate_certs import generate_self_signed_cert, CERT_FILE, KEY_FILE


class TestGenerateSelfSignedCert:
    """Tests für generate_self_signed_cert Funktion"""
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_generates_certificate_successfully(self, mock_run, mock_exists):
        """Testet erfolgreiche Zertifikatsgenerierung"""
        # Setup: Keine existierenden Zertifikate
        mock_exists.return_value = False
        
        # OpenSSL version check erfolgreich
        mock_run.side_effect = [
            MagicMock(returncode=0),  # openssl version
            MagicMock(returncode=0, stdout="", stderr="")  # openssl req
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: subprocess.run wurde 2x aufgerufen
        assert mock_run.call_count == 2
        
        # Verify: Zweiter Call ist openssl req mit korrekten Parametern
        cert_call = mock_run.call_args_list[1]
        assert cert_call[0][0][0] == "openssl"
        assert cert_call[0][0][1] == "req"
        assert "-x509" in cert_call[0][0]
        assert "-newkey" in cert_call[0][0]
        assert "rsa:4096" in cert_call[0][0]
        assert "-nodes" in cert_call[0][0]
        assert KEY_FILE in cert_call[0][0]
        assert CERT_FILE in cert_call[0][0]
        assert "-days" in cert_call[0][0]
        assert "365" in cert_call[0][0]
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_exits_when_openssl_not_found(self, mock_run, mock_exists):
        """Testet Exit wenn OpenSSL nicht verfügbar"""
        # Setup: Keine existierenden Zertifikate
        mock_exists.return_value = False
        # OpenSSL nicht gefunden
        mock_run.side_effect = FileNotFoundError()
        
        # Ausführen und erwarten, dass SystemExit geworfen wird
        with pytest.raises(SystemExit) as exc_info:
            generate_self_signed_cert()
        
        # Verify: Exit code ist 1
        assert exc_info.value.code == 1
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_exits_when_openssl_version_fails(self, mock_run, mock_exists):
        """Testet Exit wenn OpenSSL Version-Check fehlschlägt"""
        # Setup: Keine existierenden Zertifikate
        mock_exists.return_value = False
        # OpenSSL version schlägt fehl
        mock_run.side_effect = subprocess.CalledProcessError(1, "openssl")
        
        # Ausführen und erwarten, dass SystemExit geworfen wird
        with pytest.raises(SystemExit) as exc_info:
            generate_self_signed_cert()
        
        # Verify: Exit code ist 1
        assert exc_info.value.code == 1
    
    @patch('builtins.input')
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_skips_when_certificates_exist_and_user_declines(self, mock_run, mock_exists, mock_input):
        """Testet dass Generierung übersprungen wird wenn Zertifikate existieren und User ablehnt"""
        # Setup: Zertifikate existieren
        mock_exists.return_value = True
        mock_input.return_value = 'n'  # User lehnt Überschreiben ab
        
        # OpenSSL version check erfolgreich
        mock_run.return_value = MagicMock(returncode=0)
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: nur ein subprocess.run Call (openssl version)
        assert mock_run.call_count == 1
        mock_input.assert_called_once()
    
    @patch('builtins.input')
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_overwrites_when_certificates_exist_and_user_confirms(self, mock_run, mock_exists, mock_input):
        """Testet dass Zertifikate überschrieben werden wenn User bestätigt"""
        # Setup: Zertifikate existieren
        mock_exists.return_value = True
        mock_input.return_value = 'y'  # User bestätigt Überschreiben
        
        # OpenSSL calls erfolgreich
        mock_run.side_effect = [
            MagicMock(returncode=0),  # openssl version
            MagicMock(returncode=0, stdout="", stderr="")  # openssl req
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: beide subprocess.run Calls wurden durchgeführt
        assert mock_run.call_count == 2
        mock_input.assert_called_once()
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_exits_when_cert_generation_fails(self, mock_run, mock_exists):
        """Testet Exit wenn Zertifikatsgenerierung fehlschlägt"""
        # Setup: Keine existierenden Zertifikate
        mock_exists.return_value = False
        
        # OpenSSL version OK, aber req schlägt fehl
        mock_run.side_effect = [
            MagicMock(returncode=0),  # openssl version
            subprocess.CalledProcessError(1, "openssl", stderr="ERROR")
        ]
        
        # Ausführen und erwarten, dass SystemExit geworfen wird
        with pytest.raises(SystemExit) as exc_info:
            generate_self_signed_cert()
        
        # Verify: Exit code ist 1
        assert exc_info.value.code == 1
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_uses_correct_certificate_paths(self, mock_run, mock_exists):
        """Testet dass die korrekten Zertifikatspfade verwendet werden"""
        # Setup
        mock_exists.return_value = False
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: Pfade in Command enthalten
        cert_call_args = mock_run.call_args_list[1][0][0]
        assert CERT_FILE in cert_call_args
        assert KEY_FILE in cert_call_args
        assert CERT_FILE == "server/cert.pem"
        assert KEY_FILE == "server/key.pem"
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_certificate_validity_period(self, mock_run, mock_exists):
        """Testet dass Zertifikat für 365 Tage gültig ist"""
        # Setup
        mock_exists.return_value = False
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: -days 365 im Command
        cert_call_args = mock_run.call_args_list[1][0][0]
        days_index = cert_call_args.index("-days")
        assert cert_call_args[days_index + 1] == "365"
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_certificate_subject_details(self, mock_run, mock_exists):
        """Testet dass Subject-Details korrekt sind"""
        # Setup
        mock_exists.return_value = False
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: Subject mit localhost
        cert_call_args = mock_run.call_args_list[1][0][0]
        subj_index = cert_call_args.index("-subj")
        subject = cert_call_args[subj_index + 1]
        assert "CN=localhost" in subject
        assert "O=RSA-Hybrid-FileCrypter" in subject
        assert "C=DE" in subject
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_uses_rsa_4096_key(self, mock_run, mock_exists):
        """Testet dass RSA 4096-bit Key verwendet wird"""
        # Setup
        mock_exists.return_value = False
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: rsa:4096 im Command
        cert_call_args = mock_run.call_args_list[1][0][0]
        assert "rsa:4096" in cert_call_args
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_private_key_without_password(self, mock_run, mock_exists):
        """Testet dass Private Key ohne Passwort generiert wird"""
        # Setup
        mock_exists.return_value = False
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: -nodes Flag im Command (no DES encryption)
        cert_call_args = mock_run.call_args_list[1][0][0]
        assert "-nodes" in cert_call_args
    
    @patch('builtins.input')
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_handles_uppercase_y_for_overwrite(self, mock_run, mock_exists, mock_input):
        """Testet dass großes Y auch akzeptiert wird (wird zu lowercase konvertiert)"""
        # Setup
        mock_exists.return_value = True
        mock_input.return_value = 'Y'  # Großes Y
        
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: Zertifikat wurde generiert (Y wird zu y konvertiert durch .lower())
        assert mock_run.call_count == 2
    
    @patch('builtins.input')
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_handles_empty_input_for_overwrite(self, mock_run, mock_exists, mock_input):
        """Testet dass leere Eingabe als Ablehnung gewertet wird"""
        # Setup
        mock_exists.return_value = True
        mock_input.return_value = ''  # Leere Eingabe
        
        mock_run.return_value = MagicMock(returncode=0)
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: Zertifikat wurde nicht generiert
        assert mock_run.call_count == 1  # nur version check
    
    @patch('generate_certs.os.path.exists')
    @patch('generate_certs.subprocess.run')
    def test_subprocess_run_with_correct_parameters(self, mock_run, mock_exists):
        """Testet dass subprocess.run mit korrekten Parametern aufgerufen wird"""
        # Setup
        mock_exists.return_value = False
        mock_run.side_effect = [
            MagicMock(returncode=0),
            MagicMock(returncode=0, stdout="", stderr="")
        ]
        
        # Ausführen
        generate_self_signed_cert()
        
        # Verify: subprocess.run wurde mit capture_output, text, check aufgerufen
        cert_call = mock_run.call_args_list[1]
        assert cert_call[1]['capture_output'] == True
        assert cert_call[1]['text'] == True
        assert cert_call[1]['check'] == True


class TestConstants:
    """Tests für Modul-Konstanten"""
    
    def test_cert_file_path(self):
        """Testet dass CERT_FILE korrekt definiert ist"""
        assert CERT_FILE == "server/cert.pem"
    
    def test_key_file_path(self):
        """Testet dass KEY_FILE korrekt definiert ist"""
        assert KEY_FILE == "server/key.pem"


@pytest.mark.integration
class TestGenerateCertsIntegration:
    """Integrationstests mit echtem OpenSSL (nur wenn verfügbar)"""
    
    @pytest.fixture
    def cleanup_certs(self):
        """Fixture zum Aufräumen von Test-Zertifikaten"""
        # Setup
        test_cert = "test_cert.pem"
        test_key = "test_key.pem"
        
        # Cleanup vor Test
        for f in [test_cert, test_key]:
            if os.path.exists(f):
                os.remove(f)
        
        yield test_cert, test_key
        
        # Cleanup nach Test
        for f in [test_cert, test_key]:
            if os.path.exists(f):
                os.remove(f)
    
    def test_openssl_available(self):
        """Testet ob OpenSSL verfügbar ist"""
        try:
            result = subprocess.run(
                ["openssl", "version"],
                capture_output=True,
                check=True
            )
            assert result.returncode == 0
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("OpenSSL nicht verfügbar")
