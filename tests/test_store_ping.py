"""SqliteStore.ping(): healthy only when the existing database can be read and written."""
import os
import stat
import tempfile
import unittest

from src.engine.store.sqlite import SqliteStore


class TestStorePing(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "store.db")
        self.store = SqliteStore(self.path)

    def tearDown(self):
        os.chmod(self.dir, stat.S_IRWXU)
        for name in os.listdir(self.dir):
            os.chmod(os.path.join(self.dir, name), stat.S_IRUSR | stat.S_IWUSR)
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_healthy_store(self):
        self.store.ping()

    def test_missing_file_is_not_recreated(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        with self.assertRaises(Exception):
            self.store.ping()
        self.assertFalse(os.path.exists(self.path))

    @unittest.skipIf(os.geteuid() == 0, "root ignores file permissions")
    def test_read_only_store_is_unhealthy(self):
        for name in os.listdir(self.dir):
            os.chmod(os.path.join(self.dir, name), stat.S_IRUSR)
        os.chmod(self.dir, stat.S_IRUSR | stat.S_IXUSR)
        with self.assertRaises(Exception):
            self.store.ping()


if __name__ == "__main__":
    unittest.main()
