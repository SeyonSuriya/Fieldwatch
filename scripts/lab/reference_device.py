"""Synthetic Fieldwatch HEAD-only fixture. Serves no files, media or credentials."""
import argparse
import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "app/src/test/resources/device-validation/reference-fixtures.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def handler_for(mode):
    config = FIXTURE["modes"][mode]

    class ReferenceHandler(BaseHTTPRequestHandler):
        server_version = "FieldwatchReferenceLab/1"
        sys_version = ""
        timeout = 3

        def do_HEAD(self):
            if self.path != "/":
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(config["status"])
            self.send_header("X-Fieldwatch-Lab-Product", FIXTURE["product"])
            self.send_header("X-Fieldwatch-Lab-Build", config["build"])
            self.send_header("X-Fieldwatch-Lab-Protocol", FIXTURE["protocol"])
            if mode == "exposed":
                self.send_header("X-Fieldwatch-Lab-Canary", FIXTURE["marker"])
            else:
                # Deliberately never accepts credentials. This is a negative control only.
                self.send_header("WWW-Authenticate", 'Basic realm="FieldwatchLab"')
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        def do_GET(self):
            self.send_response(405)
            self.send_header("Allow", "HEAD")
            self.send_header("Content-Length", "0")
            self.end_headers()

    return ReferenceHandler


def bind_address(value):
    address = ipaddress.IPv4Address(value)
    private_ranges = [ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not address.is_loopback and not any(address in network for network in private_ranges):
        raise argparse.ArgumentTypeError("Choose loopback or a specific private lab IPv4 interface; wildcard/public binds are unsupported.")
    return str(address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=FIXTURE["modes"], required=True)
    parser.add_argument("--bind", type=bind_address, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("Port must be 1–65535.")
    with ThreadingHTTPServer((args.bind, args.port), handler_for(args.mode)) as server:
        print(f"LAB ONLY: {args.mode} fixture on {args.bind}:{args.port}; HEAD / only; Ctrl+C stops it.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
