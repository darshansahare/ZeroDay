import os
import pytest
from fastapi.testclient import TestClient
from main import app
from app.api.routes import set_backend_config
from app.core.governance import governance

TEST_ADMIN_KEY = "test-admin-secret-key-for-zeroday-testing-only"
os.environ["ADMIN_API_KEY"] = TEST_ADMIN_KEY


@pytest.fixture(autouse=True)
def setup_test_credentials():
    """Ensure test suite has simulated credentials active by default."""
    os.environ["ADMIN_API_KEY"] = TEST_ADMIN_KEY
    set_backend_config(nebius_key="test-nebius-key", tavily_key="test-tavily-key")
    yield


@pytest.fixture
def client():
    governance.reset()
    c = TestClient(app)
    c.headers["X-API-Key"] = os.getenv("ADMIN_API_KEY", TEST_ADMIN_KEY)
    return c
