#!/usr/bin/env python3
"""
Website Monitor CLI Tool with TLS Support

Measures DNS, TCP, TLS, HTTP metrics and validates content via regex.
Outputs results as compact JSON with rounded values.

Dependencies:
  - Python 3.7+
  - Standard library only

Usage:
  ./wgss_003.py \
    --url https://example.com/path \
    --port 443 \
    --regex "pattern" \
    --timeout 10 \
    [--insecure]
"""
import argparse
import socket
import ssl
import sys
import time
import json
import re
from urllib.parse import urlparse

def parse_args():
    p = argparse.ArgumentParser(description="Website Monitor CLI Tool with TLS Support")
    p.add_argument("--url", required=True,
                   help="Target URL including scheme (http:// or https://) and path")
    p.add_argument("--port", type=int,
                   help="Override port (default 80 for HTTP, 443 for HTTPS)")
    p.add_argument("--regex", required=True,
                   help="Regex pattern to search in response body")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Timeout in seconds for DNS, connect, and read")
    p.add_argument("--insecure", action="store_true",
                   help="Disable TLS certificate verification")
    return p.parse_args()

def get_dns_server():
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                if line.startswith('nameserver'):
                    return line.split()[1]
    except Exception:
        pass
    return None

def main():
    args = parse_args()
    parsed = urlparse(args.url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    port = args.port or (443 if scheme == 'https' else 80)
    timeout = args.timeout

    result = {
        "dns_resolution_time": None,
        "dns_resolved_ip": None,
        "dns_server_ip": get_dns_server(),
        "tcp_connect_time": None,
        "tls_handshake_time": None,
        "tls_version": None,
        "cipher_suite": None,
        "http_status": None,
        "http_version": None,
        "content_length": None,
        "time_to_first_byte": None,
        "content_download_time": None,
        "regex_match": None,
        "target_url": args.url,
        "source_hostname": socket.gethostname(),
        "timeout_occurred": False,
        "message": None,
    }

    # DNS resolution
    try:
        t0 = time.perf_counter()
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        t1 = time.perf_counter()
        result["dns_resolution_time"] = t1 - t0
        family, socktype, proto, _, sockaddr = addrinfo[0]
        result["dns_resolved_ip"] = sockaddr[0]
    except Exception as e:
        result["message"] = f"DNS error: {e}"
        print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
        sys.exit(1)

    # TCP connect and TLS handshake
    sock = None
    try:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.connect((result["dns_resolved_ip"], port))
        t1 = time.perf_counter()
        result["tcp_connect_time"] = t1 - t0

        if scheme == 'https':
            ctx = ssl.create_default_context()
            if args.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            t2 = time.perf_counter()
            conn = ctx.wrap_socket(sock, server_hostname=host)
            t3 = time.perf_counter()
            result["tls_handshake_time"] = t3 - t2
            result["tls_version"] = conn.version()
            result["cipher_suite"] = conn.cipher()[0]
        else:
            conn = sock

        # Send HTTP GET
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: close\r\n"
            "User-Agent: PythonMonitor/1.0\r\n\r\n"
        ).encode('utf-8')
        conn.settimeout(timeout)
        conn.sendall(req)

        # Time to first byte
        t0 = time.perf_counter()
        first = conn.recv(1)
        t1 = time.perf_counter()
        result["time_to_first_byte"] = t1 - t0
        data = first

        # Read remainder
        t2 = time.perf_counter()
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        t3 = time.perf_counter()
        result["content_download_time"] = t3 - t2

        # Parse HTTP
        header, _, body = data.partition(b"\r\n\r\n")
        status = header.split(b"\r\n")[0].decode('utf-8', errors='ignore').split()
        if len(status) >= 2 and status[0].startswith('HTTP/'):
            result["http_status"] = int(status[1])
            result["http_version"] = status[0].split('/')[1]
        result["content_length"] = len(body)

        # Regex validation
        result["regex_match"] = bool(re.search(args.regex, body.decode('utf-8', errors='ignore')))
        result["message"] = "Success"

    except socket.timeout as e:
        result["timeout_occurred"] = True
        result["message"] = f"Timeout: {e}"
    except Exception as e:
        result["message"] = f"Error: {e}"
    finally:
        if sock:
            sock.close()

    # Round float metrics to 2 decimal places
    for key in ("dns_resolution_time", "tcp_connect_time", "tls_handshake_time", "time_to_first_byte", "content_download_time"):
        if isinstance(result.get(key), float):
            result[key] = round(result[key], 3)

    # Output compact single-line JSON
    print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))

if __name__ == '__main__':
    main()
