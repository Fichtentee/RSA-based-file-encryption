# tests/test_server.py
import pytest
import json
import base64
from clients.crypto import generate_rsa_private, pub_to_pem, sign_pss
from server.storage import Store


class TestParticipateEndpoint:
    """Tests für /participate Endpoint"""
    
    def test_participate_returns_uuid(self, client):
        """Testet dass /participate eine UUID zurückgibt"""
        response = client.post('/participate')
        assert response.status_code == 200
        
        data = response.get_json()
        assert "uuid" in data
        assert isinstance(data["uuid"], str)
        assert len(data["uuid"]) > 0
    
    def test_participate_returns_different_uuids(self, client):
        """Testet dass jeder Aufruf eine neue UUID generiert"""
        response1 = client.post('/participate')
        response2 = client.post('/participate')
        
        uuid1 = response1.get_json()["uuid"]
        uuid2 = response2.get_json()["uuid"]
        
        assert uuid1 != uuid2


class TestRegisterEndpoint:
    """Tests für /register Endpoint"""
    
    def test_register_success(self, client):
        """Testet erfolgreiche Client-Registrierung"""
        # Generiere Keys
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        
        # Hole UUID
        uuid_response = client.post('/participate')
        uuid = uuid_response.get_json()["uuid"]
        
        # Signiere UUID
        signature = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        # Registriere
        response = client.post('/register', json={
            "alias": "TestClient",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": signature
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert "status" in data
        assert data["status"] == "registered"
    
    def test_register_with_invalid_signature(self, client):
        """Testet Registrierung mit ungültiger Signatur"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        
        uuid_response = client.post('/participate')
        uuid = uuid_response.get_json()["uuid"]
        
        # Falsche Signatur
        wrong_signature = base64.b64encode(b"invalid_signature").decode()
        
        response = client.post('/register', json={
            "alias": "TestClient",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": wrong_signature
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data
    
    def test_register_duplicate_alias(self, client):
        """Testet Registrierung mit bereits existierendem Alias"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        
        # Erste Registrierung
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv, uuid1.encode())).decode()
        
        response1 = client.post('/register', json={
            "alias": "TestClient",
            "uuid": uuid1,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig1
        })
        assert response1.status_code == 200
        
        # Zweite Registrierung mit gleichem Alias
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv, uuid2.encode())).decode()
        
        response2 = client.post('/register', json={
            "alias": "TestClient",  # Gleicher Alias
            "uuid": uuid2,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig2
        })
        
        assert response2.status_code == 409
        data = response2.get_json()
        assert "error" in data


class TestRequestPartnerEndpoint:
    """Tests für /request_partner Endpoint"""
    
    def setup_two_clients(self, client):
        """Helper: Registriert zwei Clients"""
        # Client1
        priv1 = generate_rsa_private(bits=2048)
        pub_pem1 = pub_to_pem(priv1.public_key())
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1",
            "uuid": uuid1,
            "pubkey_pem": pub_pem1.decode(),
            "uuid_signature": sig1
        })
        
        # Client2
        priv2 = generate_rsa_private(bits=2048)
        pub_pem2 = pub_to_pem(priv2.public_key())
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client2",
            "uuid": uuid2,
            "pubkey_pem": pub_pem2.decode(),
            "uuid_signature": sig2
        })
        
        return (priv1, sig1, pub_pem1), (priv2, sig2, pub_pem2)
    
    def test_request_partner_success(self, client):
        """Testet erfolgreiche Partner-Key-Anfrage"""
        (priv1, sig1, _), (_, _, pub_pem2) = self.setup_two_clients(client)
        
        response = client.post('/request_partner', json={
            "from_alias": "Client1",
            "partner_alias": "Client2",
            "proof_signature": sig1
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert "partner_pubkey_pem" in data
        assert data["partner_pubkey_pem"] == pub_pem2.decode()
    
    def test_request_partner_nonexistent(self, client):
        """Testet Anfrage nach nicht existierendem Partner"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        uuid = client.post('/participate').get_json()["uuid"]
        sig = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig
        })
        
        response = client.post('/request_partner', json={
            "from_alias": "Client1",
            "partner_alias": "NonExistent",
            "proof_signature": sig
        })
        
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data
    
    def test_request_partner_invalid_proof(self, client):
        """Testet Partner-Key-Anfrage mit ungültiger Signatur"""
        self.setup_two_clients(client)
        
        response = client.post('/request_partner', json={
            "from_alias": "Client1",
            "partner_alias": "Client2",
            "proof_signature": base64.b64encode(b"invalid").decode()
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data


class TestDeliverEndpoint:
    """Tests für /deliver Endpoint"""
    
    def setup_two_clients(self, client):
        """Helper: Registriert zwei Clients"""
        priv1 = generate_rsa_private(bits=2048)
        pub_pem1 = pub_to_pem(priv1.public_key())
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1",
            "uuid": uuid1,
            "pubkey_pem": pub_pem1.decode(),
            "uuid_signature": sig1
        })
        
        priv2 = generate_rsa_private(bits=2048)
        pub_pem2 = pub_to_pem(priv2.public_key())
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client2",
            "uuid": uuid2,
            "pubkey_pem": pub_pem2.decode(),
            "uuid_signature": sig2
        })
        
        return (priv1, sig1), (priv2, sig2)
    
    def test_deliver_success(self, client):
        """Testet erfolgreiche Nachrichtenübertragung"""
        (priv1, sig1), _ = self.setup_two_clients(client)
        
        # Hole UUID von Client1 für neue Signatur
        from server.app import STORE
        c1 = STORE.get_client_by_alias("Client1")
        fresh_sig = base64.b64encode(sign_pss(priv1, c1.uuid.encode())).decode()
        
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "Client2",
            "proof_signature": fresh_sig,
            "payload": {
                "enc_key_b64": "fake_encrypted_key",
                "nonce": "fake_nonce",
                "ciphertext": "fake_ciphertext"
            },
            "meta": {"filename": "test.txt"}
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert "status" in data
        assert data["status"] == "queued"
    
    def test_deliver_to_nonexistent_client(self, client):
        """Testet Nachricht an nicht existierenden Client"""
        (priv1, _), _ = self.setup_two_clients(client)
        
        from server.app import STORE
        c1 = STORE.get_client_by_alias("Client1")
        fresh_sig = base64.b64encode(sign_pss(priv1, c1.uuid.encode())).decode()
        
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "NonExistent",
            "proof_signature": fresh_sig,
            "payload": {"data": "test"},
            "meta": {}
        })
        
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data
    
    def test_deliver_invalid_proof(self, client):
        """Testet Nachrichtenübertragung mit ungültiger Signatur"""
        self.setup_two_clients(client)
        
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "Client2",
            "proof_signature": base64.b64encode(b"invalid").decode(),
            "payload": {"data": "test"},
            "meta": {}
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data


class TestInboxEndpoint:
    """Tests für /inbox/<alias> Endpoint"""
    
    def setup_with_message(self, client):
        """Helper: Setup mit einer Nachricht in der Inbox"""
        priv1 = generate_rsa_private(bits=2048)
        pub_pem1 = pub_to_pem(priv1.public_key())
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1",
            "uuid": uuid1,
            "pubkey_pem": pub_pem1.decode(),
            "uuid_signature": sig1
        })
        
        priv2 = generate_rsa_private(bits=2048)
        pub_pem2 = pub_to_pem(priv2.public_key())
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client2",
            "uuid": uuid2,
            "pubkey_pem": pub_pem2.decode(),
            "uuid_signature": sig2
        })
        
        # Sende Nachricht von Client1 an Client2 (neue Signatur für deliver)
        deliver_sig = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "Client2",
            "proof_signature": deliver_sig,
            "payload": {"test": "data"},
            "meta": {"filename": "test.txt"}
        })
        
        return priv2, sig2
    
    def test_inbox_retrieve_messages(self, client):
        """Testet Abrufen von Nachrichten aus Inbox"""
        priv2, sig2 = self.setup_with_message(client)
        
        # Erstelle neue Signatur für inbox-Zugriff
        from server.app import STORE
        c2 = STORE.get_client_by_alias("Client2")
        inbox_proof = base64.b64encode(sign_pss(priv2, c2.uuid.encode())).decode()
        
        response = client.get('/inbox/Client2', headers={"X-Proof": inbox_proof})
        
        assert response.status_code == 200
        data = response.get_json()
        assert "messages" in data
        assert len(data["messages"]) == 1
        assert data["messages"][0]["from_alias"] == "Client1"
        assert data["messages"][0]["to_alias"] == "Client2"
    
    def test_inbox_empty(self, client):
        """Testet Abrufen aus leerer Inbox"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        uuid = client.post('/participate').get_json()["uuid"]
        sig = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": sig
        })
        
        # Erstelle neue Signatur für inbox-Zugriff
        inbox_proof = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        response = client.get('/inbox/Client1', headers={"X-Proof": inbox_proof})
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["messages"] == []
    
    def test_inbox_invalid_proof(self, client):
        """Testet Inbox-Zugriff mit ungültiger Signatur"""
        priv2, _ = self.setup_with_message(client)
        
        # Verwende gültiges Base64, aber ungültige Signatur
        invalid_proof = base64.b64encode(b"invalid_signature_data").decode()
        response = client.get('/inbox/Client2', headers={"X-Proof": invalid_proof})
        
        assert response.status_code == 401
        data = response.get_json()
        assert "error" in data
    
    def test_inbox_nonexistent_client(self, client):
        """Testet Inbox-Zugriff für nicht existierenden Client"""
        response = client.get('/inbox/NonExistent', headers={"X-Proof": "fake"})
        
        assert response.status_code == 404
        data = response.get_json()
        assert "error" in data


class TestRegisterErrorHandling:
    """Tests für Error-Handling in /register Endpoint"""
    
    def test_register_with_missing_fields(self, client):
        """Testet Registrierung mit fehlenden Pflichtfeldern"""
        # Missing 'uuid' field
        response = client.post('/register', json={
            "alias": "TestClient",
            "pubkey_pem": "PUBLIC KEY",
            "uuid_signature": "signature"
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert data["error"] == "invalid_request"
    
    def test_register_with_invalid_json(self, client):
        """Testet Registrierung mit ungültigen Datentypen"""
        # uuid_signature should be base64 string, not int
        response = client.post('/register', json={
            "alias": "TestClient",
            "uuid": "test-uuid",
            "pubkey_pem": "PUBLIC KEY",
            "uuid_signature": 12345  # Invalid type
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
    
    def test_register_with_invalid_alias_format(self, client):
        """Testet Registrierung mit ungültigem Alias-Format (ValidationError)"""
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        uuid = client.post('/participate').get_json()["uuid"]
        signature = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        # Alias with path traversal
        response = client.post('/register', json={
            "alias": "../../../etc/passwd",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": signature
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "validation_failed"


class TestRequestPartnerErrorHandling:
    """Tests für Error-Handling in /request_partner Endpoint"""
    
    def test_request_partner_with_missing_fields(self, client):
        """Testet request_partner mit fehlenden Feldern"""
        # Missing 'partner_alias'
        response = client.post('/request_partner', json={
            "from_alias": "Client1",
            "proof_signature": "signature"
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
        assert data["error"] == "invalid_request"
    
    def test_request_partner_with_invalid_alias_format(self, client):
        """Testet request_partner mit ungültigem Alias-Format"""
        response = client.post('/request_partner', json={
            "from_alias": "../../malicious",
            "partner_alias": "Client2",
            "proof_signature": base64.b64encode(b"test").decode()
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "validation_failed"
    
    def test_request_partner_with_invalid_base64(self, client):
        """Testet request_partner mit ungültigem Base64"""
        response = client.post('/request_partner', json={
            "from_alias": "Client1",
            "partner_alias": "Client2",
            "proof_signature": "not-valid-base64!!!"
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data


class TestDeliverErrorHandling:
    """Tests für Error-Handling in /deliver Endpoint"""
    
    def test_deliver_with_missing_fields(self, client):
        """Testet deliver mit fehlenden Feldern"""
        # Missing 'to_alias'
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "proof_signature": "sig",
            "payload": {"data": "test"}
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_request"
    
    def test_deliver_with_invalid_alias_format(self, client):
        """Testet deliver mit ungültigem Alias-Format (ValidationError)"""
        response = client.post('/deliver', json={
            "from_alias": "../../../root",
            "to_alias": "Client2",
            "proof_signature": base64.b64encode(b"test").decode(),
            "payload": {"enc_key_b64": "key", "nonce": "n", "ciphertext": "ct"}
        })
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "validation_failed"
    
    def test_deliver_with_corrupted_proof_signature(self, client):
        """Testet deliver mit korrupter Signatur (Exception in auth)"""
        # Setup zwei Clients
        priv1 = generate_rsa_private(bits=2048)
        pub_pem1 = pub_to_pem(priv1.public_key())
        uuid1 = client.post('/participate').get_json()["uuid"]
        sig1 = base64.b64encode(sign_pss(priv1, uuid1.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client1",
            "uuid": uuid1,
            "pubkey_pem": pub_pem1.decode(),
            "uuid_signature": sig1
        })
        
        priv2 = generate_rsa_private(bits=2048)
        pub_pem2 = pub_to_pem(priv2.public_key())
        uuid2 = client.post('/participate').get_json()["uuid"]
        sig2 = base64.b64encode(sign_pss(priv2, uuid2.encode())).decode()
        
        client.post('/register', json={
            "alias": "Client2",
            "uuid": uuid2,
            "pubkey_pem": pub_pem2.decode(),
            "uuid_signature": sig2
        })
        
        # Deliver mit ungültiger Signatur (zu kurz, verursacht Exception)
        response = client.post('/deliver', json={
            "from_alias": "Client1",
            "to_alias": "Client2",
            "proof_signature": base64.b64encode(b"x").decode(),  # Zu kurz
            "payload": {"enc_key_b64": "key", "nonce": "n", "ciphertext": "ct"}
        })
        
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "auth_failed"


class TestInboxErrorHandling:
    """Tests für Error-Handling in /inbox Endpoint"""
    
    def test_inbox_with_invalid_alias_format(self, client):
        """Testet inbox mit ungültigem Alias-Format"""
        # Use alias with special characters that fail validation
        response = client.get('/inbox/' + 'a' * 256, headers={"X-Proof": "test"})
        
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "validation_failed"
    
    def test_inbox_with_corrupted_proof(self, client):
        """Testet inbox mit korrupter Proof-Signatur (Exception)"""
        # Registriere Client
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        uuid = client.post('/participate').get_json()["uuid"]
        signature = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        client.post('/register', json={
            "alias": "TestClient",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": signature
        })
        
        # Inbox-Zugriff mit zu kurzer Signatur (verursacht Exception)
        invalid_proof = base64.b64encode(b"x").decode()
        response = client.get('/inbox/TestClient', headers={"X-Proof": invalid_proof})
        
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "auth_failed"
    
    def test_inbox_with_missing_proof_header(self, client):
        """Testet inbox ohne X-Proof Header"""
        # Registriere Client
        priv = generate_rsa_private(bits=2048)
        pub_pem = pub_to_pem(priv.public_key())
        uuid = client.post('/participate').get_json()["uuid"]
        signature = base64.b64encode(sign_pss(priv, uuid.encode())).decode()
        
        client.post('/register', json={
            "alias": "TestClient",
            "uuid": uuid,
            "pubkey_pem": pub_pem.decode(),
            "uuid_signature": signature
        })
        
        # Kein X-Proof Header
        response = client.get('/inbox/TestClient')
        
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "auth_failed"
