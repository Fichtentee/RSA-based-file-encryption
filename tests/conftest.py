# tests/conftest.py
import pytest
import os
import tempfile
from pathlib import Path
from clients.crypto import generate_rsa_private, pub_to_pem
from server.storage import Store, Client
from server.app import app as flask_app


@pytest.fixture
def temp_dir():
    """Temporäres Verzeichnis für Tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_file(temp_dir):
    """Erstellt eine Test-Datei"""
    file_path = temp_dir / "test.txt"
    content = b"This is a test file for encryption."
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture
def large_test_file(temp_dir):
    """Erstellt eine größere Test-Datei (1 MB)"""
    file_path = temp_dir / "large_test.bin"
    content = os.urandom(1024 * 1024)  # 1 MB
    file_path.write_bytes(content)
    return file_path, content


@pytest.fixture
def rsa_keypair():
    """Generiert ein RSA-Schlüsselpaar für Tests"""
    private_key = generate_rsa_private(bits=2048)  # Kleinere Keys für schnellere Tests
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def aes_key():
    """Generiert einen zufälligen AES-256 Key"""
    return os.urandom(32)


@pytest.fixture
def store():
    """Erstellt einen frischen Store"""
    return Store()


@pytest.fixture
def sample_client():
    """Erstellt einen Test-Client"""
    priv = generate_rsa_private(bits=2048)
    pub_pem = pub_to_pem(priv.public_key())
    return Client(
        alias="TestClient",
        uuid="test-uuid-1234",
        pubkey_pem=pub_pem
    )


@pytest.fixture
def app():
    """Flask Test-App mit frischem Store"""
    from server.app import app as flask_app
    from server.storage import Store
    import server.app
    
    flask_app.config['TESTING'] = True
    # Reset Store für jeden Test
    server.app.STORE = Store()
    return flask_app


@pytest.fixture
def client(app):
    """Flask Test-Client"""
    return app.test_client()
