# tests/test_flow.py
import os
import base64
import pytest
from clients.crypto import (
    generate_rsa_private, 
    priv_to_pem, 
    pub_to_pem, 
    sign_pss,
    aes_gcm_encrypt_file,
    aes_gcm_decrypt_to_file,
    rsa_oaep_encrypt
)
from server.crypto import load_public_key_pem, rsa_oaep_decrypt


def test_full_flow_with_test_client(client, tmp_path):
    """
    Vollständiger End-to-End Integrationstest mit Flask Test-Client.
    Testet den kompletten Ablauf: Registrierung, Key Exchange, verschlüsselte Nachricht.
    """
    # 1) Generiere RSA-Schlüssel für Client1 und Client2
    c1_priv = generate_rsa_private(bits=2048)
    c1_pub = c1_priv.public_key()
    c1_pub_pem = pub_to_pem(c1_pub)
    
    c2_priv = generate_rsa_private(bits=2048)
    c2_pub = c2_priv.public_key()
    c2_pub_pem = pub_to_pem(c2_pub)
    
    # 2) Client1: participate & register
    resp1 = client.post('/participate')
    assert resp1.status_code == 200
    u1 = resp1.get_json()["uuid"]
    sig1 = base64.b64encode(sign_pss(c1_priv, u1.encode())).decode()
    
    resp1_reg = client.post('/register', json={
        "alias": "Client1",
        "uuid": u1,
        "pubkey_pem": c1_pub_pem.decode(),
        "uuid_signature": sig1
    })
    assert resp1_reg.status_code == 200
    assert resp1_reg.get_json()["status"] == "registered"
    
    # 3) Client2: participate & register
    resp2 = client.post('/participate')
    assert resp2.status_code == 200
    u2 = resp2.get_json()["uuid"]
    sig2 = base64.b64encode(sign_pss(c2_priv, u2.encode())).decode()
    
    resp2_reg = client.post('/register', json={
        "alias": "Client2",
        "uuid": u2,
        "pubkey_pem": c2_pub_pem.decode(),
        "uuid_signature": sig2
    })
    assert resp2_reg.status_code == 200
    assert resp2_reg.get_json()["status"] == "registered"
    
    # 4) Client1 fordert Public Key von Client2 an
    sig1_req = base64.b64encode(sign_pss(c1_priv, u1.encode())).decode()
    resp_partner = client.post('/request_partner', json={
        "from_alias": "Client1",
        "partner_alias": "Client2",
        "proof_signature": sig1_req
    })
    assert resp_partner.status_code == 200
    partner_pub_pem = resp_partner.get_json()["partner_pubkey_pem"].encode()
    assert partner_pub_pem == c2_pub_pem
    
    # 5) Client1 verschlüsselt eine Datei und sendet sie an Client2
    # Erstelle Test-Datei
    test_file = tmp_path / "secret.txt"
    original_content = b"TOP SECRET MESSAGE FOR CLIENT2"
    test_file.write_bytes(original_content)
    
    # AES-Key generieren
    aes_key = os.urandom(32)
    
    # Datei mit AES-GCM verschlüsseln (mit AAD = Sender-Alias)
    encrypted_data = aes_gcm_encrypt_file(aes_key, str(test_file), aad=b"Client1")
    
    # AES-Key mit RSA-OAEP verschlüsseln (mit Partner Public Key)
    partner_pub_obj = load_public_key_pem(partner_pub_pem)
    enc_key = rsa_oaep_encrypt(partner_pub_obj, aes_key)
    enc_key_b64 = base64.b64encode(enc_key).decode()
    
    # Nachricht an Client2 senden
    sig1_deliver = base64.b64encode(sign_pss(c1_priv, u1.encode())).decode()
    resp_deliver = client.post('/deliver', json={
        "from_alias": "Client1",
        "to_alias": "Client2",
        "proof_signature": sig1_deliver,
        "payload": {
            "enc_key_b64": enc_key_b64,
            "nonce": encrypted_data["nonce"],
            "ciphertext": encrypted_data["ciphertext"]
        },
        "meta": {"filename": "secret.txt"}
    })
    assert resp_deliver.status_code == 200
    assert resp_deliver.get_json()["status"] == "queued"
    
    # 6) Client2 ruft seine Inbox ab
    sig2_inbox = base64.b64encode(sign_pss(c2_priv, u2.encode())).decode()
    resp_inbox = client.get('/inbox/Client2', headers={"X-Proof": sig2_inbox})
    assert resp_inbox.status_code == 200
    
    messages = resp_inbox.get_json()["messages"]
    assert len(messages) == 1
    
    msg = messages[0]
    assert msg["from_alias"] == "Client1"
    assert msg["to_alias"] == "Client2"
    assert msg["meta"]["filename"] == "secret.txt"
    
    # 7) Client2 entschlüsselt die Nachricht
    # Entschlüssele AES-Key mit privatem RSA-Key
    enc_key_bytes = base64.b64decode(msg["payload"]["enc_key_b64"])
    decrypted_aes_key = rsa_oaep_decrypt(c2_priv, enc_key_bytes)
    assert decrypted_aes_key == aes_key
    
    # Entschlüssele Datei mit AES-GCM (mit AAD = Sender-Alias)
    output_file = tmp_path / "decrypted.txt"
    aes_gcm_decrypt_to_file(
        decrypted_aes_key,
        msg["payload"]["nonce"],
        msg["payload"]["ciphertext"],
        str(output_file),
        aad=msg["from_alias"].encode()
    )
    
    # Vergleiche Inhalt
    decrypted_content = output_file.read_bytes()
    assert decrypted_content == original_content
    
    # 8) Inbox ist jetzt leer (dequeue_all entfernt Nachrichten)
    sig2_inbox2 = base64.b64encode(sign_pss(c2_priv, u2.encode())).decode()
    resp_inbox2 = client.get('/inbox/Client2', headers={"X-Proof": sig2_inbox2})
    assert resp_inbox2.status_code == 200
    assert len(resp_inbox2.get_json()["messages"]) == 0


def test_flow_with_wrong_aad_fails(client, tmp_path):
    """
    Testet dass Entschlüsselung mit falschem AAD fehlschlägt.
    Dies demonstriert die Sender-Authentifizierung durch AAD.
    """
    # Setup: Registriere zwei Clients
    c1_priv = generate_rsa_private(bits=2048)
    c1_pub_pem = pub_to_pem(c1_priv.public_key())
    u1 = client.post('/participate').get_json()["uuid"]
    sig1 = base64.b64encode(sign_pss(c1_priv, u1.encode())).decode()
    client.post('/register', json={
        "alias": "Client1", "uuid": u1,
        "pubkey_pem": c1_pub_pem.decode(), "uuid_signature": sig1
    })
    
    c2_priv = generate_rsa_private(bits=2048)
    c2_pub_pem = pub_to_pem(c2_priv.public_key())
    u2 = client.post('/participate').get_json()["uuid"]
    sig2 = base64.b64encode(sign_pss(c2_priv, u2.encode())).decode()
    client.post('/register', json={
        "alias": "Client2", "uuid": u2,
        "pubkey_pem": c2_pub_pem.decode(), "uuid_signature": sig2
    })
    
    # Verschlüssele mit AAD="Client1"
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"test content")
    
    aes_key = os.urandom(32)
    encrypted = aes_gcm_encrypt_file(aes_key, str(test_file), aad=b"Client1")
    
    # Simuliere manipulierte Nachricht (falscher Sender im AAD)
    output_file = tmp_path / "output.txt"
    with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
        aes_gcm_decrypt_to_file(
            aes_key,
            encrypted["nonce"],
            encrypted["ciphertext"],
            str(output_file),
            aad=b"MaliciousClient"  # Falscher Sender
        )


def test_multiple_messages_in_inbox(client):
    """
    Testet dass mehrere Nachrichten korrekt in der Inbox landen.
    """
    # Registriere 3 Clients
    clients_data = []
    for i in range(1, 4):
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        uuid = client.post('/participate').get_json()["uuid"]
        sig = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        client.post('/register', json={
            "alias": f"Client{i}",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig
        })
        clients_data.append((priv, uuid, sig))
    
    # Client1 und Client2 senden Nachrichten an Client3
    for i in [0, 1]:  # Client1, Client2
        priv, uuid, _ = clients_data[i]
        sig_deliver = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        resp = client.post('/deliver', json={
            "from_alias": f"Client{i+1}",
            "to_alias": "Client3",
            "proof_signature": sig_deliver,
            "payload": {"data": f"message from Client{i+1}"},
            "meta": {}
        })
        assert resp.status_code == 200
    
    # Client3 ruft Inbox ab
    priv3, uuid3, _ = clients_data[2]
    sig3 = base64.b64encode(sign_pss(priv3, uuid3.encode())).decode()
    resp_inbox = client.get('/inbox/Client3', headers={"X-Proof": sig3})
    
    assert resp_inbox.status_code == 200
    messages = resp_inbox.get_json()["messages"]
    assert len(messages) == 2
    
    # Verifiziere Absender
    senders = {msg["from_alias"] for msg in messages}
    assert senders == {"Client1", "Client2"}