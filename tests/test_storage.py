# tests/test_storage.py
import pytest
from server.storage import Store, Client, Message


class TestClient:
    """Tests für Client Dataclass"""
    
    def test_client_creation(self):
        """Testet Erstellung eines Clients"""
        client = Client(
            alias="TestClient",
            uuid="test-uuid",
            pubkey_pem=b"fake-pem-key"
        )
        assert client.alias == "TestClient"
        assert client.uuid == "test-uuid"
        assert client.pubkey_pem == b"fake-pem-key"


class TestMessage:
    """Tests für Message Dataclass"""
    
    def test_message_creation_with_defaults(self):
        """Testet Erstellung einer Nachricht mit Standardwerten"""
        msg = Message(
            from_alias="Client1",
            to_alias="Client2",
            payload={"data": "test"}
        )
        assert msg.from_alias == "Client1"
        assert msg.to_alias == "Client2"
        assert msg.payload == {"data": "test"}
        assert msg.meta == {}
    
    def test_message_creation_with_meta(self):
        """Testet Erstellung einer Nachricht mit Metadaten"""
        msg = Message(
            from_alias="Client1",
            to_alias="Client2",
            payload={"data": "test"},
            meta={"filename": "test.txt"}
        )
        assert msg.meta == {"filename": "test.txt"}


class TestStore:
    """Tests für Server Storage"""
    
    def test_store_initialization(self, store):
        """Testet Initialisierung eines leeren Stores"""
        assert len(store.clients_by_alias) == 0
        assert len(store.clients_by_uuid) == 0
        assert len(store.inbox) == 0
    
    def test_add_client(self, store, sample_client):
        """Testet Hinzufügen eines Clients"""
        store.add_client(sample_client)
        
        assert len(store.clients_by_alias) == 1
        assert len(store.clients_by_uuid) == 1
        assert "TestClient" in store.clients_by_alias
        assert "test-uuid-1234" in store.clients_by_uuid
        assert "TestClient" in store.inbox
    
    def test_add_multiple_clients(self, store):
        """Testet Hinzufügen mehrerer Clients"""
        client1 = Client(alias="Client1", uuid="uuid-1", pubkey_pem=b"key1")
        client2 = Client(alias="Client2", uuid="uuid-2", pubkey_pem=b"key2")
        
        store.add_client(client1)
        store.add_client(client2)
        
        assert len(store.clients_by_alias) == 2
        assert len(store.clients_by_uuid) == 2
        assert "Client1" in store.clients_by_alias
        assert "Client2" in store.clients_by_alias
    
    def test_get_client_by_alias(self, store, sample_client):
        """Testet Abrufen eines Clients per Alias"""
        store.add_client(sample_client)
        
        retrieved = store.get_client_by_alias("TestClient")
        assert retrieved is not None
        assert retrieved.alias == "TestClient"
        assert retrieved.uuid == "test-uuid-1234"
    
    def test_get_client_by_alias_not_found(self, store):
        """Testet Abrufen eines nicht existierenden Clients per Alias"""
        result = store.get_client_by_alias("NonExistent")
        assert result is None
    
    def test_get_client_by_uuid(self, store, sample_client):
        """Testet Abrufen eines Clients per UUID"""
        store.add_client(sample_client)
        
        retrieved = store.get_client_by_uuid("test-uuid-1234")
        assert retrieved is not None
        assert retrieved.alias == "TestClient"
    
    def test_get_client_by_uuid_not_found(self, store):
        """Testet Abrufen eines nicht existierenden Clients per UUID"""
        result = store.get_client_by_uuid("non-existent-uuid")
        assert result is None
    
    def test_enqueue_message(self, store):
        """Testet Einreihen einer Nachricht"""
        client = Client(alias="Client1", uuid="uuid-1", pubkey_pem=b"key")
        store.add_client(client)
        
        msg = Message(
            from_alias="Client2",
            to_alias="Client1",
            payload={"data": "test"}
        )
        store.enqueue(msg)
        
        assert len(store.inbox["Client1"]) == 1
        assert store.inbox["Client1"][0].from_alias == "Client2"
    
    def test_enqueue_multiple_messages(self, store):
        """Testet Einreihen mehrerer Nachrichten"""
        client = Client(alias="Client1", uuid="uuid-1", pubkey_pem=b"key")
        store.add_client(client)
        
        msg1 = Message(from_alias="Client2", to_alias="Client1", payload={"id": 1})
        msg2 = Message(from_alias="Client3", to_alias="Client1", payload={"id": 2})
        msg3 = Message(from_alias="Client2", to_alias="Client1", payload={"id": 3})
        
        store.enqueue(msg1)
        store.enqueue(msg2)
        store.enqueue(msg3)
        
        assert len(store.inbox["Client1"]) == 3
    
    def test_enqueue_to_non_existing_client(self, store):
        """Testet Einreihen zu nicht existierendem Client (erstellt automatisch Inbox)"""
        msg = Message(from_alias="Client1", to_alias="NonExistent", payload={})
        store.enqueue(msg)
        
        assert "NonExistent" in store.inbox
        assert len(store.inbox["NonExistent"]) == 1
    
    def test_dequeue_all(self, store):
        """Testet Abrufen aller Nachrichten aus Inbox"""
        client = Client(alias="Client1", uuid="uuid-1", pubkey_pem=b"key")
        store.add_client(client)
        
        msg1 = Message(from_alias="Client2", to_alias="Client1", payload={"id": 1})
        msg2 = Message(from_alias="Client3", to_alias="Client1", payload={"id": 2})
        
        store.enqueue(msg1)
        store.enqueue(msg2)
        
        messages = store.dequeue_all("Client1")
        
        assert len(messages) == 2
        assert messages[0].payload["id"] == 1
        assert messages[1].payload["id"] == 2
        
        # Inbox sollte jetzt leer sein
        assert "Client1" not in store.inbox or len(store.inbox.get("Client1", [])) == 0
    
    def test_dequeue_all_empty_inbox(self, store):
        """Testet Abrufen aus leerer Inbox"""
        messages = store.dequeue_all("NonExistent")
        assert messages == []
    
    def test_dequeue_all_removes_from_inbox(self, store):
        """Testet dass dequeue_all die Nachrichten entfernt"""
        client = Client(alias="Client1", uuid="uuid-1", pubkey_pem=b"key")
        store.add_client(client)
        
        msg = Message(from_alias="Client2", to_alias="Client1", payload={})
        store.enqueue(msg)
        
        assert len(store.inbox["Client1"]) == 1
        
        messages = store.dequeue_all("Client1")
        assert len(messages) == 1
        
        # Zweiter Abruf sollte leer sein
        messages2 = store.dequeue_all("Client1")
        assert messages2 == []
    
    def test_multiple_clients_separate_inboxes(self, store):
        """Testet dass mehrere Clients separate Inboxes haben"""
        client1 = Client(alias="Client1", uuid="uuid-1", pubkey_pem=b"key1")
        client2 = Client(alias="Client2", uuid="uuid-2", pubkey_pem=b"key2")
        
        store.add_client(client1)
        store.add_client(client2)
        
        msg1 = Message(from_alias="Client2", to_alias="Client1", payload={"for": "Client1"})
        msg2 = Message(from_alias="Client1", to_alias="Client2", payload={"for": "Client2"})
        
        store.enqueue(msg1)
        store.enqueue(msg2)
        
        inbox1 = store.dequeue_all("Client1")
        inbox2 = store.dequeue_all("Client2")
        
        assert len(inbox1) == 1
        assert len(inbox2) == 1
        assert inbox1[0].payload["for"] == "Client1"
        assert inbox2[0].payload["for"] == "Client2"
