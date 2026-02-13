# server/crypto.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os, base64

# --- RSA Key Utils ---
def load_public_key_pem(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())

def load_private_key_pem(pem_bytes: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem_bytes, password=password, backend=default_backend())

# --- RSA-PSS Sign / Verify (Auth-Claims wie UUID) ---
def rsa_pss_sign(priv_key, data: bytes) -> bytes:
    return priv_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )  # RSASSA-PSS (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)

def rsa_pss_verify(pub_key, signature: bytes, data: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        pub_key.verify(
            signature, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False  # RSASSA-PSS (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)

# --- RSA-OAEP: Key Transport für AES-Key ---
def rsa_oaep_encrypt(pub_key, plaintext: bytes) -> bytes:
    return pub_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )  # RSAES-OAEP (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)

def rsa_oaep_decrypt(priv_key, ciphertext: bytes) -> bytes:
    return priv_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )  # RSAES-OAEP (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)

# --- AES-GCM: Datei-/Nachrichten-Verschlüsselung ---
def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> dict:
    # 32B Key (AES-256), 12B Nonce empfohlen; Nonce MUSS einzigartig sein. [3](https://csrc.nist.gov/pubs/sp/800/38/d/final)[4](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key length must be 16/24/32")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    # cryptography packt Tag ans Ende von ct; Transport per base64
    return {"nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()}

def aes_gcm_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes | None = None) -> bytes:
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)

def random_bytes(n=32) -> bytes:
    return os.urandom(n)