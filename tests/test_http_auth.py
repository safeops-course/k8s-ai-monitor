"""HTTP API auth: fail closed, every route except /healthz, /healthz checks the store."""
import unittest
from unittest import mock

from aiohttp.test_utils import TestClient, TestServer

from src import config
from src.handlers import startup


class _FakeStore:
    def __init__(self, ok=True):
        self.ok = ok

    def ping(self):
        if not self.ok:
            raise RuntimeError("unable to open database file")


class TestHttpAuth(unittest.IsolatedAsyncioTestCase):
    async def _client(self):
        client = TestClient(TestServer(startup._build_app()))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        return client

    async def test_no_token_locks_the_api(self):
        with mock.patch.object(config, "INTERNAL_TOKEN", ""):
            client = await self._client()
            for path in ("/state", "/incidents", "/certs", "/llm-usage", "/reports"):
                resp = await client.get(path)
                self.assertEqual(resp.status, 401, path)
            self.assertEqual((await client.post("/report")).status, 401)

    async def test_wrong_token_forbidden_on_routes_that_had_no_check(self):
        with mock.patch.object(config, "INTERNAL_TOKEN", "s3cret"):
            client = await self._client()
            for path in ("/state", "/incidents", "/certs", "/reports", "/maintenance", "/suppressions"):
                resp = await client.get(path, headers={"X-Internal-Token": "wrong"})
                self.assertEqual(resp.status, 403, path)

    async def test_healthz_needs_no_token_and_pings_the_store(self):
        with mock.patch.object(config, "INTERNAL_TOKEN", ""), \
             mock.patch.object(startup, "_store", _FakeStore()):
            client = await self._client()
            resp = await client.get("/healthz")
            self.assertEqual(resp.status, 200)

    async def test_healthz_unhealthy_when_store_fails(self):
        with mock.patch.object(startup, "_store", _FakeStore(ok=False)):
            client = await self._client()
            resp = await client.get("/healthz")
            self.assertEqual(resp.status, 503)


if __name__ == "__main__":
    unittest.main()
