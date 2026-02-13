# server/app.py
from flask import Flask, request, jsonify
import uuid as _uuid, base64
from .storage import Store, Client, Message
from .crypto import load_public_key_pem, rsa_pss_verify
from .validation import (
    validate_alias, 
    validate_uuid, 
    validate_filename, 
    validate_payload_size,
    ValidationError
)

app = Flask(__name__)
STORE = Store()

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


@app.post("/participate")
def participate():
    # Vergibt eine frische UUID, die der Client später signiert (Identitätsnachweis)
    u = str(_uuid.uuid4())
    log.info(f"Generated new UUID: {u}")
    return jsonify({"uuid": u})
        
@app.post("/register")
def register():
    """
    Body: {
      "alias": "Client1",
      "uuid": "...",
      "pubkey_pem": "<PEM string>",
      "uuid_signature": "<base64 RSASSA-PSS(sig(uuid))>"
    }
    """
    try:
        data = request.get_json(force=True)
        
        # Input Validation
        alias = validate_alias(data["alias"].strip())
        u = validate_uuid(data["uuid"].strip())
        pub_pem = data["pubkey_pem"].encode()
        sig = base64.b64decode(data["uuid_signature"])
    except ValidationError as e:
        log.warning(f"Validation error in register: {e}")
        return jsonify({"error": "validation_failed", "detail": str(e)}), 400
    except (KeyError, ValueError, TypeError) as e:
        log.warning(f"Invalid request data: {e}")
        return jsonify({"error": "invalid_request"}), 400

    # Verifiziere Signatur mit dem übermittelten PubKey
    pub = load_public_key_pem(pub_pem)
    if not rsa_pss_verify(pub, sig, u.encode()):
        return jsonify({"error": "auth_failed"}), 401

    # UUID darf noch nicht vergeben sein; Alias darf frei sein
    if STORE.get_client_by_uuid(u) or STORE.get_client_by_alias(alias):
        return jsonify({"error": "duplicate"}), 409

    STORE.add_client(Client(alias=alias, uuid=u, pubkey_pem=pub_pem))
    log.info(f"Registered new client: alias={alias}, uuid={u}")
    return jsonify({"status": "registered", "alias": alias})

@app.post("/request_partner")
def request_partner():
    """
    Body: {
      "from_alias": "Client1",
      "proof_signature": "<base64 RSASSA-PSS(sig(own_uuid))>",
      "partner_alias": "Client2"
    }
    Response: { "partner_pubkey_pem": "<PEM..." } or 401
    """
    try:
        data = request.get_json(force=True)
        from_alias = validate_alias(data["from_alias"])
        partner_alias = validate_alias(data["partner_alias"])
        proof = base64.b64decode(data["proof_signature"])
    except ValidationError as e:
        log.warning(f"Validation error in request_partner: {e}")
        return jsonify({"error": "validation_failed"}), 400
    except (KeyError, ValueError) as e:
        log.warning(f"Invalid request data: {e}")
        return jsonify({"error": "invalid_request"}), 400

    c_from = STORE.get_client_by_alias(from_alias)
    c_to = STORE.get_client_by_alias(partner_alias)
    if not c_from or not c_to:
        return jsonify({"error": "unknown_client"}), 404

    pub_from = load_public_key_pem(c_from.pubkey_pem)
    if not rsa_pss_verify(pub_from, proof, c_from.uuid.encode()):
        return jsonify({"error": "auth_failed"}), 401

    return jsonify({"partner_pubkey_pem": c_to.pubkey_pem.decode()})

@app.post("/deliver")
def deliver():
    """
    Body: {
      "from_alias": "...",
      "to_alias": "...",
      "proof_signature": "<sig(own_uuid)>",
      "payload": {
        "enc_key_b64": "...",   # RSA-OAEP(cipher(aes_key))
        "nonce": "...",         # AES-GCM nonce (b64)
        "ciphertext": "..."     # AES-GCM (b64, enthält Tag)
      },
      "meta": {"filename": "secret.txt"}
    }
    """
    try:
        data = request.get_json(force=True)
        
        # Input Validation
        fr = validate_alias(data["from_alias"])
        to = validate_alias(data["to_alias"])
        payload = data["payload"]
        
        # Validate payload size (prevent memory exhaustion)
        validate_payload_size(payload)
        
        # Validate filename in metadata if present
        if "filename" in data.get("meta", {}):
            data["meta"]["filename"] = validate_filename(data["meta"]["filename"])
            
    except ValidationError as e:
        log.warning(f"Validation error in deliver: {e}")
        return jsonify({"error": "validation_failed", "detail": str(e)}), 400
    except (KeyError, ValueError) as e:
        log.warning(f"Invalid request data: {e}")
        return jsonify({"error": "invalid_request"}), 400
    
    c_from = STORE.get_client_by_alias(fr)
    c_to = STORE.get_client_by_alias(to)
    if not c_from or not c_to:
        return jsonify({"error": "unknown_client"}), 404
    
    # AuthN
    try:
        proof = base64.b64decode(data["proof_signature"])
        if not rsa_pss_verify(load_public_key_pem(c_from.pubkey_pem), proof, c_from.uuid.encode()):
            return jsonify({"error": "auth_failed"}), 401
    except (ValueError, Exception) as e:
        log.warning(f"Auth verification failed: {e}")
        return jsonify({"error": "auth_failed"}), 401

    STORE.enqueue(Message(from_alias=fr, to_alias=to, payload=payload, meta=data.get("meta", {})))
    return jsonify({"status": "queued"})

@app.get("/inbox/<alias>")
def inbox(alias: str):
    # (Optional) Proof per Header 'X-Proof' (sig(own_uuid)) prüfen
    try:
        alias = validate_alias(alias)
    except ValidationError as e:
        log.warning(f"Invalid alias in inbox request: {e}")
        return jsonify({"error": "validation_failed"}), 400
    
    c = STORE.get_client_by_alias(alias)
    if not c:
        return jsonify({"error": "unknown_client"}), 404
    
    try:
        proof_b64 = request.headers.get("X-Proof") or ""
        if not rsa_pss_verify(load_public_key_pem(c.pubkey_pem), base64.b64decode(proof_b64), c.uuid.encode()):
            return jsonify({"error": "auth_failed"}), 401
    except (ValueError, Exception) as e:
        log.warning(f"Auth verification failed in inbox: {e}")
        return jsonify({"error": "auth_failed"}), 401
    
    msgs = STORE.dequeue_all(alias)
    return jsonify({"messages": [m.__dict__ for m in msgs]})


if __name__ == "__main__":
    import os
    import sys
    
    # TLS-Zertifikate
    cert_file = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_file = os.path.join(os.path.dirname(__file__), "key.pem")
    
    # Prüfe ob TLS-Zertifikate existieren
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("🔒 Starting HTTPS server with TLS...")
        print(f"   Certificate: {cert_file}")
        print(f"   Server URL: https://localhost:5000")
        print("   ⚠️  Self-signed certificate - clients need verify=False")
        ssl_context = (cert_file, key_file)
    else:
        print("⚠️  WARNING: No TLS certificates found!")
        print("   Run: python generate_certs.py")
        print("   Starting HTTP server (INSECURE)...")
        print("   Server URL: http://localhost:5000")
        ssl_context = None
    
    app.run(
        debug=False, 
        host="127.0.0.1",  # Nur localhost (sicherer)
        port=5000,
        ssl_context=ssl_context
    )