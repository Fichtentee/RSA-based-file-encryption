# clients/client.py
import argparse, base64, json, os, requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from .crypto import generate_rsa_private, priv_to_pem, pub_to_pem, load_pub, sign_pss, rsa_oaep_encrypt, aes_gcm_encrypt_file, aes_gcm_decrypt_to_file
import urllib3

# Disable SSL warnings für self-signed certs (nur für Demo!)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_client_dirs(alias: str):
    """Get organized directory structure for a client."""
    base = f"./.tmp/{alias}"
    return {
        "base": base,
        "own": f"{base}/own",
        "partner_keys": f"{base}/partner_keys",
        "received": f"{base}/received"
    }

def save_keypair(path_prefix: str, priv):
    os.makedirs(os.path.dirname(path_prefix), exist_ok=True)
    with open(path_prefix + "_priv.pem", "wb") as f: f.write(priv_to_pem(priv))
    with open(path_prefix + "_pub.pem", "wb") as f: f.write(pub_to_pem(priv.public_key()))

def load_priv(path: str):
    """Lädt Private Key aus PEM-Datei mit Exception Handling."""
    from cryptography.hazmat.primitives import serialization
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        print(f"❌ Error: Private key not found: {path}")
        print(f"   Run 'genkeys' command first to generate keys")
        raise
    except PermissionError:
        print(f"❌ Error: No permission to read: {path}")
        raise
    except Exception as e:
        print(f"❌ Error loading private key: {e}")
        raise

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="https://127.0.0.1:5000", 
                    help="Server URL (default: https://127.0.0.1:5000)")
    ap.add_argument("--alias", required=True)
    ap.add_argument("--key-prefix", default=None)  # z.B. ./keys/client1
    ap.add_argument("--no-verify-ssl", action="store_true", 
                    help="Disable SSL verification (for self-signed certs)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("genkeys")
    sub.add_parser("register")
    reqp = sub.add_parser("request")
    reqp.add_argument("--partner", required=True)
    sendp = sub.add_parser("send")
    sendp.add_argument("--partner", required=True)
    sendp.add_argument("--file", required=True)
    recvp = sub.add_parser("receive")
    recvp.add_argument("--outdir", default=None)  # Will use client's received/ dir

    args = ap.parse_args()
    base = args.server.rstrip("/")
    
    # SSL verification (False for self-signed certs)
    verify_ssl = not args.no_verify_ssl
    if not verify_ssl:
        print("⚠️  SSL verification disabled (self-signed cert mode)")
    
    # Use new organized directory structure
    dirs = get_client_dirs(args.alias)
    kp = args.key_prefix or f"{dirs['own']}/{args.alias}"
    
    # Create directory structure
    for dir_path in dirs.values():
        os.makedirs(dir_path, exist_ok=True)

    if args.cmd == "genkeys":
        priv = generate_rsa_private()
        save_keypair(kp, priv)
        print(f"✓ Keys generated for {args.alias}")
        print(f"  Private key: {kp}_priv.pem")
        print(f"  Public key:  {kp}_pub.pem")
        return

    # load keys
    priv = load_priv(kp + "_priv.pem")
    pub_pem = pub_to_pem(priv.public_key())

    if args.cmd == "register":
        # 1) participate -> UUID
        r = requests.post(f"{base}/participate", verify=verify_ssl)
        uuid = r.json()["uuid"]
        sig = sign_pss(priv, uuid.encode())
        body = {
            "alias": args.alias,
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": base64.b64encode(sig).decode()
        }
        uuid_file = f"{kp}_uuid.json"
        with open(uuid_file, "w") as f:
            json.dump({"uuid": uuid}, f)
        r = requests.post(f"{base}/register", json=body, verify=verify_ssl)
        print(f"✓ {args.alias} registered (UUID: {uuid[:8]}...)")
        print(r.status_code, r.json()); return

    if args.cmd == "request":
        # Anfrage: Partner-PubKey holen
        # Proof = Signatur über eigene UUID -> wird vom Server benötigt; vereinfachend ist sie lokal nicht verfügbar.
        # Workaround: hole eigene UUID über /participate? Besser: Server sollte UUID pro Client speichern.
        # Vereinfachung: Der Client cached seine UUID nach register in uuid.json:
        with open(f"{kp}_uuid.json") as f:
            my_uuid = json.load(f)["uuid"]
        proof = base64.b64encode(sign_pss(priv, my_uuid.encode())).decode()
        r = requests.post(f"{base}/request_partner", json={
            "from_alias": args.alias,
            "partner_alias": args.partner,
            "proof_signature": proof
        }, verify=verify_ssl)
        print(r.status_code, r.json())
        if r.ok:
            partner_key_path = f"{dirs['partner_keys']}/{args.partner}_pub.pem"
            with open(partner_key_path, "wb") as f:
                f.write(r.json()["partner_pubkey_pem"].encode())
            print(f"✓ Partner key saved: {partner_key_path}")
        return

    if args.cmd == "send":
        # 1) Lade Partner-PubKey
        partner_key_path = f"{dirs['partner_keys']}/{args.partner}_pub.pem"
        with open(partner_key_path, "rb") as f:
            partner_pub_pem = f.read()
        partner_pub = load_pub(partner_pub_pem)

        # 2) Erzeuge neuen AES-Key (256 Bit)
        aes_key = os.urandom(32)

        # 3) Verschlüssele Datei (AES-GCM)
        enc = aes_gcm_encrypt_file(aes_key, args.file, aad=args.alias.encode())

        # 4) Transportiere AES-Key via RSA-OAEP (Empfänger-PubKey)
        enc_key_b64 = base64.b64encode(rsa_oaep_encrypt(partner_pub, aes_key)).decode()

        # 5) Proof (Signatur) holen
        with open(f"{kp}_uuid.json") as f:
            my_uuid = json.load(f)["uuid"]
        proof = base64.b64encode(sign_pss(priv, my_uuid.encode())).decode()

        payload = {"enc_key_b64": enc_key_b64, "nonce": enc["nonce"], "ciphertext": enc["ciphertext"]}
        r = requests.post(f"{base}/deliver", json={
            "from_alias": args.alias,
            "to_alias": args.partner,
            "proof_signature": proof,
            "payload": payload,
            "meta": {"filename": os.path.basename(args.file)}
        }, verify=verify_ssl)
        print(f"✓ File sent: {os.path.basename(args.file)} → {args.partner}")
        print(r.status_code, r.json()); return

    if args.cmd == "receive":
        # Use client's received directory if --outdir not specified
        outdir = args.outdir or dirs['received']
        os.makedirs(outdir, exist_ok=True)
        
        # Proof header
        with open(f"{kp}_uuid.json") as f:
            my_uuid = json.load(f)["uuid"]
        proof = base64.b64encode(sign_pss(priv, my_uuid.encode())).decode()
        r = requests.get(f"{base}/inbox/{args.alias}", headers={"X-Proof": proof}, verify=verify_ssl)
        if not r.ok:
            print(r.status_code, r.text); return
        msgs = r.json()["messages"]
        print(f"📬 Inbox: {len(msgs)} message(s)")
        if not msgs:
            print(f"   No messages for {args.alias}")
        for m in msgs:
            # Decrypt AES key (serverseitig verschickt durch Partner)
            enc_key = base64.b64decode(m["payload"]["enc_key_b64"])
            aes_key = priv.decrypt(
                enc_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None)
            )  # RSAES-OAEP (RFC 8017) [1](https://www.rfc-editor.org/rfc/rfc8017)
            # Datei wiederherstellen (mit Filename Sanitization)
            filename = m['meta'].get('filename', 'out.bin')
            
            # SECURITY: Sanitize filename to prevent path traversal
            # Only use basename, remove dangerous characters
            safe_filename = os.path.basename(filename)
            safe_filename = safe_filename.replace("..", "").replace("/", "").replace("\\", "")
            if not safe_filename or safe_filename in (".", ".."):
                safe_filename = "out.bin"
            
            out_path = os.path.join(outdir, f"from_{m['from_alias']}_{safe_filename}")
            aes_gcm_decrypt_to_file(aes_key, m["payload"]["nonce"], m["payload"]["ciphertext"], out_path, aad=m["from_alias"].encode())
            print(f"✓ Decrypted: {safe_filename} → {out_path}")
        return

if __name__ == "__main__":
    main()