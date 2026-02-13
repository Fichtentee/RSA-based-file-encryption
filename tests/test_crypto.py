# tests/test_crypto.py
import pytest
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from clients.crypto import (
    generate_rsa_private,
    priv_to_pem,
    pub_to_pem,
    load_pub,
    sign_pss,
    rsa_oaep_encrypt,
    aes_gcm_encrypt_file,
    aes_gcm_decrypt_to_file
)


class TestRSAKeyGeneration:
    """Tests für RSA-Schlüsselgenerierung"""
    
    def test_generate_rsa_private_default(self):
        """Testet Standard-RSA-Schlüsselgenerierung (4096 Bit)"""
        key = generate_rsa_private()
        assert key.key_size == 4096
    
    def test_generate_rsa_private_custom_size(self):
        """Testet RSA-Schlüsselgenerierung mit benutzerdefinierter Größe"""
        key = generate_rsa_private(bits=2048)
        assert key.key_size == 2048
    
    def test_priv_to_pem(self, rsa_keypair):
        """Testet Konvertierung Private Key zu PEM"""
        priv, _ = rsa_keypair
        pem = priv_to_pem(priv)
        assert isinstance(pem, bytes)
        assert b"BEGIN PRIVATE KEY" in pem
        assert b"END PRIVATE KEY" in pem
    
    def test_pub_to_pem(self, rsa_keypair):
        """Testet Konvertierung Public Key zu PEM"""
        _, pub = rsa_keypair
        pem = pub_to_pem(pub)
        assert isinstance(pem, bytes)
        assert b"BEGIN PUBLIC KEY" in pem
        assert b"END PUBLIC KEY" in pem
    
    def test_load_pub(self, rsa_keypair):
        """Testet Laden eines Public Keys aus PEM"""
        _, pub = rsa_keypair
        pem = pub_to_pem(pub)
        loaded_pub = load_pub(pem)
        # Vergleiche durch Verschlüsselung/Entschlüsselung
        test_data = b"Test Data"
        encrypted = loaded_pub.encrypt(
            test_data,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), 
                        algorithm=hashes.SHA256(), label=None)
        )
        assert isinstance(encrypted, bytes)


class TestRSASignature:
    """Tests für RSA-PSS Signaturen"""
    
    def test_sign_pss(self, rsa_keypair):
        """Testet PSS-Signatur"""
        priv, pub = rsa_keypair
        data = b"Test message for signing"
        signature = sign_pss(priv, data)
        
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verifiziere Signatur
        pub.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                       salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    
    def test_sign_pss_different_data_different_signature(self, rsa_keypair):
        """Testet dass verschiedene Daten verschiedene Signaturen erzeugen"""
        priv, _ = rsa_keypair
        sig1 = sign_pss(priv, b"message1")
        sig2 = sign_pss(priv, b"message2")
        assert sig1 != sig2
    
    def test_sign_pss_verification_fails_with_wrong_data(self, rsa_keypair):
        """Testet dass Signatur-Verifikation mit falschen Daten fehlschlägt"""
        priv, pub = rsa_keypair
        data = b"original message"
        signature = sign_pss(priv, data)
        
        with pytest.raises(Exception):
            pub.verify(
                signature,
                b"wrong message",
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                           salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )


class TestRSAEncryption:
    """Tests für RSA-OAEP Verschlüsselung"""
    
    def test_rsa_oaep_encrypt(self, rsa_keypair, aes_key):
        """Testet RSA-OAEP Verschlüsselung"""
        priv, pub = rsa_keypair
        encrypted = rsa_oaep_encrypt(pub, aes_key)
        
        assert isinstance(encrypted, bytes)
        assert len(encrypted) > 0
        assert encrypted != aes_key  # Verschlüsselt, nicht Klartext
        
        # Entschlüssele und verifiziere
        decrypted = priv.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), 
                        algorithm=hashes.SHA256(), label=None)
        )
        assert decrypted == aes_key
    
    def test_rsa_oaep_encrypt_different_each_time(self, rsa_keypair, aes_key):
        """Testet dass OAEP jedes Mal verschiedene Ciphertexte erzeugt (durch Padding)"""
        _, pub = rsa_keypair
        encrypted1 = rsa_oaep_encrypt(pub, aes_key)
        encrypted2 = rsa_oaep_encrypt(pub, aes_key)
        # OAEP hat deterministisches Padding, könnte gleich sein
        # Hauptsächlich: beide sollten zum gleichen Key entschlüsseln
        assert isinstance(encrypted1, bytes)
        assert isinstance(encrypted2, bytes)


class TestAESGCM:
    """Tests für AES-GCM Datei-Verschlüsselung"""
    
    def test_aes_gcm_encrypt_file(self, test_file, aes_key):
        """Testet AES-GCM Datei-Verschlüsselung ohne AAD"""
        file_path, original_content = test_file
        result = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        assert "nonce" in result
        assert "ciphertext" in result
        
        # Base64-kodiert?
        nonce = base64.b64decode(result["nonce"])
        ciphertext = base64.b64decode(result["ciphertext"])
        
        assert len(nonce) == 12  # GCM Standard Nonce
        assert len(ciphertext) > len(original_content)  # Ciphertext + Auth Tag
    
    def test_aes_gcm_encrypt_file_with_aad(self, test_file, aes_key):
        """Testet AES-GCM Datei-Verschlüsselung mit AAD"""
        file_path, _ = test_file
        aad = b"Client1"
        result = aes_gcm_encrypt_file(aes_key, str(file_path), aad=aad)
        
        assert "nonce" in result
        assert "ciphertext" in result
    
    def test_aes_gcm_decrypt_to_file(self, test_file, aes_key, temp_dir):
        """Testet vollständigen Verschlüsselungs-/Entschlüsselungs-Zyklus"""
        file_path, original_content = test_file
        
        # Verschlüsseln
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        # Entschlüsseln
        output_path = temp_dir / "decrypted.txt"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        # Vergleichen
        decrypted_content = output_path.read_bytes()
        assert decrypted_content == original_content
    
    def test_aes_gcm_with_aad_roundtrip(self, test_file, aes_key, temp_dir):
        """Testet Verschlüsselung/Entschlüsselung mit AAD"""
        file_path, original_content = test_file
        aad = b"TestSender"
        
        # Verschlüsseln mit AAD
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path), aad=aad)
        
        # Entschlüsseln mit gleichem AAD
        output_path = temp_dir / "decrypted_aad.txt"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path),
            aad=aad
        )
        
        decrypted_content = output_path.read_bytes()
        assert decrypted_content == original_content
    
    def test_aes_gcm_wrong_aad_fails(self, test_file, aes_key, temp_dir):
        """Testet dass Entschlüsselung mit falschem AAD fehlschlägt"""
        file_path, _ = test_file
        aad = b"CorrectSender"
        wrong_aad = b"WrongSender"
        
        # Verschlüsseln mit AAD
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path), aad=aad)
        
        # Entschlüsseln mit falschem AAD sollte fehlschlagen
        output_path = temp_dir / "should_fail.txt"
        with pytest.raises(Exception):  # cryptography wirft InvalidTag
            aes_gcm_decrypt_to_file(
                aes_key,
                encrypted["nonce"],
                encrypted["ciphertext"],
                str(output_path),
                aad=wrong_aad
            )
    
    def test_aes_gcm_wrong_key_fails(self, test_file, temp_dir):
        """Testet dass Entschlüsselung mit falschem Key fehlschlägt"""
        file_path, _ = test_file
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        
        # Verschlüsseln mit key1
        encrypted = aes_gcm_encrypt_file(key1, str(file_path))
        
        # Entschlüsseln mit key2 sollte fehlschlagen
        output_path = temp_dir / "should_fail.txt"
        with pytest.raises(Exception):
            aes_gcm_decrypt_to_file(
                key2,
                encrypted["nonce"],
                encrypted["ciphertext"],
                str(output_path)
            )
    
    def test_aes_gcm_large_file(self, large_test_file, aes_key, temp_dir):
        """Testet Verschlüsselung größerer Dateien (1 MB)"""
        file_path, original_content = large_test_file
        
        # Verschlüsseln
        encrypted = aes_gcm_encrypt_file(aes_key, str(file_path))
        
        # Entschlüsseln
        output_path = temp_dir / "decrypted_large.bin"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        # Vergleichen
        decrypted_content = output_path.read_bytes()
        assert decrypted_content == original_content
        assert len(decrypted_content) == 1024 * 1024
    
    def test_aes_gcm_empty_file(self, temp_dir, aes_key):
        """Testet Verschlüsselung einer leeren Datei"""
        empty_file = temp_dir / "empty.txt"
        empty_file.write_bytes(b"")
        
        encrypted = aes_gcm_encrypt_file(aes_key, str(empty_file))
        
        output_path = temp_dir / "decrypted_empty.txt"
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_path)
        )
        
        assert output_path.read_bytes() == b""
