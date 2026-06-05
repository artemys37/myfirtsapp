import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import ASGITransport, AsyncClient

from app.main import app

pytestmark = pytest.mark.anyio

@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.anyio
async def test_health_endpoint(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ok"}


@pytest.mark.anyio
async def test_integration_status_db_ok(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})

    fake_collections = {
        "campaigns": AsyncMock(),
        "hosts": AsyncMock(),
        "vulns": AsyncMock(),
        "auth_results": AsyncMock(),
        "reports": AsyncMock(),
    }

    async def fake_count(*args, **kwargs):
        return 0

    for col in fake_collections.values():
        col.count_documents = fake_count

    def fake_getitem(name):
        return fake_collections.get(name, AsyncMock())

    fake_db.__getitem__ = fake_getitem

    with patch("app.routers.integration.get_db", return_value=fake_db):
        response = await client.get("/api/integration/status")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["components"]["backend"]["status"] == "ok"
    assert data["components"]["database"]["status"] == "ok"


@pytest.mark.anyio
async def test_integration_status_db_error(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(side_effect=Exception("MongoDB not reachable"))

    with patch("app.routers.integration.get_db", return_value=fake_db):
        response = await client.get("/api/integration/status")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert data["components"]["backend"]["status"] == "ok"
    assert data["components"]["database"]["status"] == "error"
    assert "MongoDB not reachable" in data["components"]["database"]["error"]


@pytest.mark.anyio
async def test_integration_status_structure(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})

    fake_collection = AsyncMock()
    fake_collection.count_documents = AsyncMock(return_value=5)
    fake_db.__getitem__ = MagicMock(return_value=fake_collection)

    with patch("app.routers.integration.get_db", return_value=fake_db):
        response = await client.get("/api/integration/status")

    data = response.json()
    assert "timestamp" in data
    assert "backend" in data["components"]
    assert "database" in data["components"]
    assert "version" in data["components"]["backend"]
    assert "python" in data["components"]["backend"]
    assert "type" in data["components"]["database"]
    assert "stats" in data["components"]["database"]

    stats = data["components"]["database"]["stats"]
    for col in ("campaigns", "hosts", "vulns", "auth_results", "reports"):
        assert col in stats
        assert stats[col] == 5


@pytest.mark.anyio
async def test_integration_status_collection_counts(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})

    counts = {"campaigns": 3, "hosts": 12, "vulns": 47, "auth_results": 8, "reports": 2}

    def make_collection(n):
        c = MagicMock()
        c.count_documents = AsyncMock(return_value=n)
        return c

    fake_collections = {name: make_collection(n) for name, n in counts.items()}
    fake_db.__getitem__ = MagicMock(side_effect=lambda name: fake_collections.get(name, make_collection(0)))

    with patch("app.routers.integration.get_db", return_value=fake_db):
        response = await client.get("/api/integration/status")

    data = response.json()
    stats = data["components"]["database"]["stats"]
    assert stats["campaigns"] == 3
    assert stats["hosts"] == 12
    assert stats["vulns"] == 47
    assert stats["auth_results"] == 8
    assert stats["reports"] == 2


@pytest.mark.anyio
async def test_frontend_backend_health_chain(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})
    fake_collection = MagicMock(spec_set=["find", "sort", "to_list"])
    fake_cursor = AsyncMock()
    fake_cursor.sort = MagicMock(return_value=fake_cursor)
    fake_cursor.to_list = AsyncMock(return_value=[])
    fake_collection.find = MagicMock(return_value=fake_cursor)
    fake_db.__getitem__ = MagicMock(return_value=fake_collection)
    fake_db.campaigns = fake_collection

    with patch("app.routers.integration.get_db", return_value=fake_db):
        with patch("app.routers.scan.get_db", return_value=fake_db):
            response = await client.get("/api/scan/")

    assert response.status_code == 200
    data = response.json()
    assert data == []


@pytest.mark.anyio
async def test_integration_then_scan_full_chain(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})

    fake_collections = {
        "campaigns": MagicMock(),
        "hosts": MagicMock(),
        "vulns": MagicMock(),
        "auth_results": MagicMock(),
        "reports": MagicMock(),
    }
    for col in fake_collections.values():
        col.count_documents = AsyncMock(return_value=0)

    fake_db.__getitem__ = MagicMock(side_effect=lambda name: fake_collections.get(name, MagicMock()))

    fake_cursor = AsyncMock()
    fake_cursor.sort = MagicMock(return_value=fake_cursor)
    fake_cursor.to_list = AsyncMock(return_value=[])
    fake_collections["campaigns"].find = MagicMock(return_value=fake_cursor)
    fake_db.campaigns = fake_collections["campaigns"]

    with patch("app.routers.integration.get_db", return_value=fake_db):
        with patch("app.routers.scan.get_db", return_value=fake_db):
            resp_int = await client.get("/api/integration/status")
            resp_scan = await client.get("/api/scan/")

    assert resp_int.status_code == 200
    assert resp_int.json()["components"]["database"]["stats"]["campaigns"] == 0

    assert resp_scan.status_code == 200
    assert resp_scan.json() == []


@pytest.mark.anyio
async def test_integration_endpoint_returns_backend_info(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})

    def make_col(n):
        c = MagicMock()
        c.count_documents = AsyncMock(return_value=n)
        return c

    fake_db.__getitem__ = MagicMock(side_effect=lambda name: make_col(0))

    with patch("app.routers.integration.get_db", return_value=fake_db):
        response = await client.get("/api/integration/status")

    data = response.json()
    backend = data["components"]["backend"]
    assert "version" in backend
    assert backend["version"] == "1.0.0"
    assert "python" in backend
    assert "host" in backend


@pytest.mark.anyio
async def test_scan_create_and_list_chain(client):
    fake_db = MagicMock()
    fake_db.command = AsyncMock(return_value={"ok": 1.0})

    fake_collection = MagicMock()
    fake_collection.find = MagicMock(return_value=MagicMock(
        sort=MagicMock(return_value=MagicMock(
            to_list=AsyncMock(return_value=[])
        ))
    ))
    fake_insert_result = MagicMock()
    fake_insert_result.inserted_id = "507f1f77bcf86cd799439011"
    fake_collection.insert_one = AsyncMock(return_value=fake_insert_result)
    fake_collection.update_one = AsyncMock()

    fake_db.__getitem__ = MagicMock(return_value=fake_collection)
    fake_db.campaigns = fake_collection

    with patch("app.routers.scan.get_db", return_value=fake_db):
        with patch("app.routers.scan.run_scan"):
            resp_create = await client.post(
                "/api/scan/start",
                json={
                    "name": "Test Campaign",
                    "target": {
                        "network": "192.168.1.0/24",
                        "ports": "22,80,443",
                        "include_udp": False,
                    },
                },
            )

    assert resp_create.status_code == 200
    data = resp_create.json()
    assert data["status"] == "started"
    assert "scan_id" in data

    with patch("app.routers.scan.get_db", return_value=fake_db):
        resp_list = await client.get("/api/scan/")
    assert resp_list.status_code == 200
