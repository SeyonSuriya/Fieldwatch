"""Loopback-only services for Fieldwatch emulator instrumentation. No real target data."""
import argparse
import signal
import socketserver
import threading
import time
from http.server import ThreadingHTTPServer

from reference_device import handler_for


class FailureHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            self.rfile.read(5)
            # Deliberately invalid TLS, to exercise handshake failure without a trust bypass.
            self.wfile.write(b"HTTP/1.0 400 Invalid TLS fixture\r\n\r\n")
        except (OSError, TimeoutError):
            pass


def slow_handler():
    base = handler_for("exposed")

    class SlowHandler(base):
        def do_HEAD(self):
            time.sleep(8)
            try:
                super().do_HEAD()
            except (OSError, TimeoutError):
                pass

        def log_message(self, *_):
            pass

    return SlowHandler


def quiet_handler(mode):
    base = handler_for(mode)

    class QuietHandler(base):
        def log_message(self, *_):
            pass

    return QuietHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-port", type=int, default=18081)
    args = parser.parse_args()
    if not 1024 <= args.base_port <= 65532:
        parser.error("Base port must be 1024–65532.")
    servers = []
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        for offset, handler in enumerate((quiet_handler("exposed"), quiet_handler("protected"), slow_handler(), FailureHandler)):
            server_type = socketserver.ThreadingTCPServer if handler is FailureHandler else ThreadingHTTPServer
            server = server_type(("127.0.0.1", args.base_port + offset), handler)
            server.daemon_threads = True
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"READY loopback lab ports {args.base_port}–{args.base_port + 3}", flush=True)
        stop.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
