# tests/test_server_crypto.py
import pytest
import os
import base64
from server.crypto import (
    load_public_key_pem,
    load_private_key_pem,
    rsa_pss_sign,
    rsa_pss_verify,
    rsa_oaep_encrypt,
    rsa_oaep_decrypt,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    random_bytes
)
from clients.crypto import generate_rsa_private, priv_to_pem, pub_to_pem


class TestKeyLoading:
    """Tests für Laden von RSA-Schlüsseln"""
    
    def test_load_public_key_pem(self, rsa_keypair):
        """Testet Laden eines Public Keys aus PEM"""
        _, pub = rsa_keypair
        pem = pub_to_pem(pub)
        loaded = load_public_key_pem(pem)
        
        # Vergleiche durch Verschlüsselung
        test_data = os.urandom(32)
        encrypted = rsa_oaep_encrypt(loaded, test_data)
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0
    
    def test_load_private_key_pem_without_password(self, rsa_keypair):
        """Testet Laden eines Private Keys aus PEM ohne Passwort"""
        priv, _ = rsa_keypair
        pem = priv_to_pem(priv)
        loaded = load_private_key_pem(pem)
        
        # Vergleiche durch Signatur
        test_data = b"test message"
        signature = rsa_pss_sign(loaded, test_data)
        assert isinstance(signature, bytes)
        assert len(signature) > 0
    
    def test_load_private_key_pem_with_none_password(self, rsa_keypair):
        """Testet Laden eines Private Keys mit explizit None als Passwort"""
        priv, _ = rsa_keypair
        pem = priv_to_pem(priv)
        loaded = load_private_key_pem(pem, password=None)
        
        # Verifiziere durch Entschlüsselung
        test_data = os.urandom(32)
        _, pub = rsa_keypair
        encrypted = rsa_oaep_encrypt(pub, test_data)
        decrypted = rsa_oaep_decrypt(loaded, encrypted)
        assert decrypted == test_data


class TestRSAPSSSignature:
    """Tests für RSA-PSS Signaturen (server-seitig)"""
    
    def test_rsa_pss_sign(self, rsa_keypair):
        """Testet RSA-PSS Signierung"""
        priv, pub = rsa_keypair
        data = b"Test message for signing"
        
        signature = rsa_pss_sign(priv, data)
        
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verifiziere mit rsa_pss_verify
        assert rsa_pss_verify(pub, signature, data)
    
    def test_rsa_pss_verify_success(self, rsa_keypair):
        """Testet erfolgreiche RSA-PSS Verifikation"""
        priv, pub = rsa_keypair
        data = b"message to verify"
        
        signature = rsa_pss_sign(priv, data)
        result = rsa_pss_verify(pub, signature, data)
        
        assert result is True
    
    def test_rsa_pss_verify_failure_wrong_data(self, rsa_keypair):
        """Testet fehlgeschlagene Verifikation bei falschen Daten"""
        priv, pub = rsa_keypair
        data = b"original message"
        wrong_data = b"different message"
        
        signature = rsa_pss_sign(priv, data)
        result = rsa_pss_verify(pub, signature, wrong_data)
        
        assert result is False
    
    def test_rsa_pss_verify_failure_wrong_signature(self, rsa_keypair):
        """Testet fehlgeschlagene Verifikation bei falscher Signatur"""
        _, pub = rsa_keypair
        data = b"message"
        wrong_signature = os.urandom(256)
        
        result = rsa_pss_verify(pub, wrong_signature, data)
        
        assert result is False


class TestRSAOAEP:
    """Tests für RSA-OAEP Verschlüsselung"""
    
    def test_rsa_oaep_encrypt(self, rsa_keypair):
        """Testet RSA-OAEP Verschlüsselung"""
        _, pub = rsa_keypair
        plaintext = b"Secret AES Key: " + os.urandom(32)
        
        ciphertext = rsa_oaep_encrypt(pub, plaintext)
        
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0
        assert ciphertext != plaintext
    
    def test_rsa_oaep_decrypt(self, rsa_keypair):
        """Testet RSA-OAEP Entschlüsselung"""
        priv, pub = rsa_keypair
        plaintext = os.urandom(32)
        
        ciphertext = rsa_oaep_encrypt(pub, plaintext)
        decrypted = rsa_oaep_decrypt(priv, ciphertext)
        
        assert decrypted == plaintext
    
    def test_rsa_oaep_roundtrip(self, rsa_keypair):
        """Testet vollständigen Verschlüsselung-Entschlüsselung-Zyklus"""
        priv, pub = rsa_keypair
        
        # Simuliere AES-Key Transport
        aes_key = os.urandom(32)
        
        encrypted = rsa_oaep_encrypt(pub, aes_key)
        decrypted = rsa_oaep_decrypt(priv, encrypted)
        
        assert decrypted == aes_key
        assert len(decrypted) == 32


class TestAESGCM:
    """Tests für AES-GCM Verschlüsselung (server-seitig)"""
    
    def test_aes_gcm_encrypt_without_aad(self):
        """Testet AES-GCM Verschlüsselung ohne AAD"""
        key = os.urandom(32)
        plaintext = b"Secret message to encrypt"
        
        result = aes_gcm_encrypt(key, plaintext)
        
        assert "nonce" in result
        assert "ciphertext" in result
        
        # Verifiziere Base64-Kodierung
        nonce = base64.b64decode(result["nonce"])
        ciphertext = base64.b64decode(result["ciphertext"])
        
        assert len(nonce) == 12
        assert len(ciphertext) > len(plaintext)  # Enthält Auth-Tag
    
    def test_aes_gcm_encrypt_with_aad(self):
        """Testet AES-GCM Verschlüsselung mit AAD"""
        key = os.urandom(32)
        plaintext = b"Secret message"
        aad = b"Additional authenticated data"
        
        result = aes_gcm_encrypt(key, plaintext, aad=aad)
        
        assert "nonce" in result
        assert "ciphertext" in result
    
    def test_aes_gcm_encrypt_different_key_sizes(self):
        """Testet AES-GCM mit verschiedenen Key-Größen"""
        plaintext = b"test data"
        
        # AES-128
        key128 = os.urandom(16)
        result128 = aes_gcm_encrypt(key128, plaintext)
        assert "nonce" in result128
        
        # AES-192
        key192 = os.urandom(24)
        result192 = aes_gcm_encrypt(key192, plaintext)
        assert "nonce" in result192
        
        # AES-256
        key256 = os.urandom(32)
        result256 = aes_gcm_encrypt(key256, plaintext)
        assert "nonce" in result256
    
    def test_aes_gcm_encrypt_invalid_key_size(self):
        """Testet dass ungültige Key-Größe Exception wirft"""
        invalid_key = os.urandom(15)  # Ungültig
        plaintext = b"test"
        
        with pytest.raises(ValueError, match="AES key length must be 16/24/32"):
            aes_gcm_encrypt(invalid_key, plaintext)
    
    def test_aes_gcm_decrypt_without_aad(self):
        """Testet AES-GCM Entschlüsselung ohne AAD"""
        key = os.urandom(32)
        plaintext = b"Original message"
        
        encrypted = aes_gcm_encrypt(key, plaintext)
        decrypted = aes_gcm_decrypt(key, encrypted["nonce"], encrypted["ciphertext"])
        
        assert decrypted == plaintext
    
    def test_aes_gcm_decrypt_with_aad(self):
        """Testet AES-GCM Entschlüsselung mit AAD"""
        key = os.urandom(32)
        plaintext = b"Original message"
        aad = b"Sender: Client1"
        
        encrypted = aes_gcm_encrypt(key, plaintext, aad=aad)
        decrypted = aes_gcm_decrypt(key, encrypted["nonce"], encrypted["ciphertext"], aad=aad)
        
        assert decrypted == plaintext
    
    def test_aes_gcm_roundtrip(self):
        """Testet vollständigen Verschlüsselung-Entschlüsselung-Zyklus"""
        key = os.urandom(32)
        original = b"This is the original plaintext message!"
        
        encrypted = aes_gcm_encrypt(key, original)
        decrypted = aes_gcm_decrypt(key, encrypted["nonce"], encrypted["ciphertext"])
        
        assert decrypted == original
    
    def test_aes_gcm_wrong_aad_fails(self):
        """Testet dass falsche AAD zur Exception führt"""
        key = os.urandom(32)
        plaintext = b"message"
        correct_aad = b"correct"
        wrong_aad = b"wrong"
        
        encrypted = aes_gcm_encrypt(key, plaintext, aad=correct_aad)
        
        with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
            aes_gcm_decrypt(key, encrypted["nonce"], encrypted["ciphertext"], aad=wrong_aad)
    
    def test_aes_gcm_wrong_key_fails(self):
        """Testet dass falscher Key zur Exception führt"""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        plaintext = b"message"
        
        encrypted = aes_gcm_encrypt(key1, plaintext)
        
        with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
            aes_gcm_decrypt(key2, encrypted["nonce"], encrypted["ciphertext"])
    
    def test_aes_gcm_empty_plaintext(self):
        """Testet AES-GCM mit leerem Plaintext"""
        key = os.urandom(32)
        plaintext = b""
        
        encrypted = aes_gcm_encrypt(key, plaintext)
        decrypted = aes_gcm_decrypt(key, encrypted["nonce"], encrypted["ciphertext"])
        
        assert decrypted == b""
    
    def test_aes_gcm_large_plaintext(self):
        """Testet AES-GCM mit großem Plaintext (1 MB)"""
        key = os.urandom(32)
        plaintext = os.urandom(1024 * 1024)
        
        encrypted = aes_gcm_encrypt(key, plaintext)
        decrypted = aes_gcm_decrypt(key, encrypted["nonce"], encrypted["ciphertext"])
        
        assert decrypted == plaintext


class TestRandomBytes:
    """Tests für random_bytes Funktion"""
    
    def test_random_bytes_default_size(self):
        """Testet random_bytes mit Standard-Größe (32)"""
        result = random_bytes()
        
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_random_bytes_custom_size(self):
        """Testet random_bytes mit benutzerdefinierter Größe"""
        sizes = [8, 16, 24, 32, 64, 128]
        
        for size in sizes:
            result = random_bytes(n=size)
            assert len(result) == size
    
    def test_random_bytes_uniqueness(self):
        """Testet dass random_bytes verschiedene Werte generiert"""
        result1 = random_bytes(32)
        result2 = random_bytes(32)
        
        assert result1 != result2
    
    def test_random_bytes_zero_size(self):
        """Testet random_bytes mit Größe 0"""
        result = random_bytes(0)
        
        assert result == b""
        assert len(result) == 0
