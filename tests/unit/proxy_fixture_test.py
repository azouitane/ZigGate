#!/usr/bin/env python3
"""Socket-free checks for the actual mock backend's activation and threading policy."""
import importlib.util
from pathlib import Path
import socketserver
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'integration' / 'proxy_test.py'
spec = importlib.util.spec_from_file_location('proxy_integration', SOURCE)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


class BackendFixtureTest(unittest.TestCase):
    def test_listen_uses_burst_sized_backlog(self):
        # Execute TCPServer's real bind/activate path without making a socket.
        fake = Mock()
        fake.getsockname.return_value = ('127.0.0.1', 8001)
        with patch.object(proxy.socket, 'socket', return_value=fake):
            backend = proxy.Backend('test')
            self.addCleanup(backend.server_close)
        fake.listen.assert_called_once_with(proxy.BACKEND_BACKLOG)
        self.assertGreaterEqual(proxy.BACKEND_BACKLOG, proxy.MAX_CONCURRENT_CLIENTS)
        self.assertEqual(proxy.MAX_CONCURRENT_CLIENTS, 100)

    def test_handler_dispatch_remains_threaded(self):
        self.assertIs(proxy.Backend.process_request, socketserver.ThreadingMixIn.process_request)
        self.assertTrue(proxy.Backend.daemon_threads)


if __name__ == '__main__':
    unittest.main()
