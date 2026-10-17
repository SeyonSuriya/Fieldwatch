import contextlib
import argparse
import http.client
import threading
import unittest
from http.server import ThreadingHTTPServer

from reference_device import FIXTURE, bind_address, handler_for


@contextlib.contextmanager
def fixture(mode):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(mode))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class ReferenceDeviceTest(unittest.TestCase):
    def request(self, port, method="HEAD", path="/", headers=None):
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=3)) as client:
            client.request(method, path, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()

    def test_exposed_fixture_returns_only_synthetic_header(self):
        with fixture("exposed") as port:
            status, headers, body = self.request(port)
        self.assertEqual(200, status)
        self.assertEqual(FIXTURE["marker"], headers["X-Fieldwatch-Lab-Canary"])
        self.assertEqual(FIXTURE["modes"]["exposed"]["build"], headers["X-Fieldwatch-Lab-Build"])
        self.assertEqual(b"", body)

    def test_protected_fixture_blocks_and_accepts_no_credentials(self):
        with fixture("protected") as port:
            for headers in ({}, {"Authorization": "Basic ZmFrZTpmYWtl"}):
                status, received, body = self.request(port, headers=headers)
                self.assertEqual(401, status)
                self.assertNotIn("X-Fieldwatch-Lab-Canary", received)
                self.assertEqual('Basic realm="FieldwatchLab"', received["WWW-Authenticate"])
                self.assertEqual(b"", body)

    def test_other_paths_and_get_cannot_read_files(self):
        with fixture("exposed") as port:
            self.assertEqual(404, self.request(port, path="/private")[0])
            status, _, body = self.request(port, method="GET")
            self.assertEqual(405, status)
            self.assertEqual(b"", body)

    def test_only_explicit_private_or_loopback_binds(self):
        for value in ("127.0.0.1", "192.168.1.10", "10.1.2.3", "172.16.0.1"):
            self.assertEqual(value, bind_address(value))
        for value in ("0.0.0.0", "8.8.8.8", "224.0.0.1", "169.254.1.1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                bind_address(value)


if __name__ == "__main__":
    unittest.main()
