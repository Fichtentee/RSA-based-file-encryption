# clients/crypto.py
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, base64

def generate_rsa_private(bits=4096):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def priv_to_pem(priv) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

def pub_to_pem(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_pub(pem: bytes):
    return serialization.load_pem_public_key(pem)

def sign_pss(priv, data: bytes) -> bytes:
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )  # RSASSA-PSS (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)

def rsa_oaep_encrypt(pub, key: bytes) -> bytes:
    return pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )  # RSAES-OAEP (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)

# File size limit: 16 MB (prevents memory exhaustion)
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

def aes_gcm_encrypt_file(aes_key: bytes, filepath: str, aad: bytes | None = None) -> dict:
    """Verschlüsselt eine Datei mit AES-GCM.
    
    Security: File size limited to 16 MB to prevent memory exhaustion.
    
    Raises:
        ValueError: If file too large
        FileNotFoundError: If file doesn't exist
        PermissionError: If no read permission
    """
    # Check file size before reading
    file_size = os.path.getsize(filepath)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})")
    
    with open(filepath, "rb") as f:
        pt = f.read()
    
    nonce = os.urandom(12)  # Nonce pro Datei eindeutig! [3](https://csrc.nist.gov/pubs/sp/800/38/d/final)
    ct = AESGCM(aes_key).encrypt(nonce, pt, aad)
    return {"nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode()}

def aes_gcm_decrypt_to_file(aes_key: bytes, nonce_b64: str, ct_b64: str, out_path: str, aad: bytes | None = None):
    """Entschlüsselt AES-GCM Ciphertext in eine Datei.
    
    Security: Validates output path and decrypted size.
    Path Traversal Prevention: Blocks paths with ".." sequences.
    
    Raises:
        ValueError: If decrypted data too large or path contains traversal
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    import os
    
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    
    # Decrypt
    pt = AESGCM(aes_key).decrypt(nonce, ct, aad)
    
    # Check decrypted size
    if len(pt) > MAX_FILE_SIZE:
        raise ValueError(f"Decrypted data too large: {len(pt)} bytes")
    
    # SECURITY: Block Path Traversal Attacks
    # Normalisiere Pfadtrennzeichen
    normalized_path = out_path.replace("\\", "/")
    
    # CRITICAL: Blocke Path Traversal Sequenzen
    if ".." in normalized_path:
        # Path Traversal detected - use only basename in cwd
        safe_filename = os.path.basename(normalized_path)
        safe_filename = safe_filename.replace("..", "").replace("/", "").replace("\\", "").replace("\0", "")
        if not safe_filename or safe_filename in (".", ".."):
            safe_filename = "decrypted.bin"
        safe_path = os.path.join(os.getcwd(), safe_filename)
    else:
        # No traversal - use path as-is but sanitize filename
        dir_part = os.path.dirname(normalized_path)
        file_part = os.path.basename(normalized_path)
        
        # Sanitize filename
        file_part = file_part.replace("\0", "")
        if not file_part or file_part in (".", ".."):
            file_part = "decrypted.bin"
        
        # Reconstruct safe path
        if dir_part:
            safe_path = os.path.join(dir_part, file_part)
        else:
            safe_path = file_part
    
    with open(safe_path, "wb") as f:
        f.write(pt)