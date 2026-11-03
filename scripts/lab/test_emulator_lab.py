import contextlib
import http.client
import socketserver
import ssl
import subprocess
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from emulator_lab import FailureHandler, quiet_handler


@contextlib.contextmanager
def server(handler, server_type=ThreadingHTTPServer):
    instance = server_type(("127.0.0.1", 0), handler)
    instance.daemon_threads = True
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance.server_address[1]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=3)


class EmulatorLabTest(unittest.TestCase):
    def test_host_service_modes_keep_distinct_synthetic_results(self):
        for mode, expected in (("exposed", 200), ("protected", 401)):
            with server(quiet_handler(mode)) as port:
                with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=3)) as client:
                    client.request("HEAD", "/")
                    response = client.getresponse()
                    self.assertEqual(expected, response.status)
                    self.assertEqual(mode == "exposed", response.getheader("X-Fieldwatch-Lab-Canary") is not None)
                    self.assertEqual(b"", response.read())

    def test_invalid_tls_fixture_rejects_a_standard_tls_client(self):
        import socket
        with server(FailureHandler, socketserver.ThreadingTCPServer) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                with self.assertRaises(ssl.SSLError):
                    ssl.create_default_context().wrap_socket(connection, server_hostname="localhost")

    def test_invalid_port_range_fails_before_starting_services(self):
        script = Path(__file__).with_name("emulator_lab.py")
        result = subprocess.run([sys.executable, str(script), "--base-port", "65533"], capture_output=True, timeout=5)
        self.assertEqual(2, result.returncode)
        self.assertNotIn(b"READY", result.stdout)


if __name__ == "__main__":
    unittest.main()
