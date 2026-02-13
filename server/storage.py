# server/storage.py
from dataclasses import dataclass, field
from typing import Dict, Optional, List

@dataclass
class Client:
    alias: str
    uuid: str
    pubkey_pem: bytes  # PEM-encoded RSA public key

@dataclass
class Message:
    from_alias: str
    to_alias: str
    payload: dict  # {"enc_key": "...b64...", "nonce": "...", "ciphertext": "..."}
    meta: dict = field(default_factory=dict)

class Store:
    def __init__(self):
        self.clients_by_alias: Dict[str, Client] = {}
        self.clients_by_uuid: Dict[str, Client] = {}
        self.inbox: Dict[str, List[Message]] = {}

    def add_client(self, c: Client):
        self.clients_by_alias[c.alias] = c
        self.clients_by_uuid[c.uuid] = c
        self.inbox.setdefault(c.alias, [])

    def get_client_by_alias(self, alias: str) -> Optional[Client]:
        return self.clients_by_alias.get(alias)

    def get_client_by_uuid(self, uuid: str) -> Optional[Client]:
        return self.clients_by_uuid.get(uuid)

    def enqueue(self, msg: Message):
        self.inbox.setdefault(msg.to_alias, []).append(msg)

    def dequeue_all(self, alias: str) -> List[Message]:
        return self.inbox.pop(alias, [])