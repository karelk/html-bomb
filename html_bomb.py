#!/usr/bin/python3

import socket
import ssl
import threading
import sys
import os

# Load bomb payload once
if not os.path.exists('bomb.gz'):
    print("ERROR: bomb.gz not found")
    sys.exit(1)

with open('bomb.gz', 'rb') as f:
    BOMB = f.read()

print(f"Loaded {len(BOMB)} byte bomb")

# Check for SSL cert
HAS_SSL = os.path.exists('cert.pem') and os.path.exists('key.pem')
if not HAS_SSL:
    print("WARNING: cert.pem/key.pem not found - HTTPS will not work")
    print("Generate: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj '/CN=localhost'")

def handle_client(conn, addr):
    try:
        hostname = socket.gethostbyaddr(addr[0])[0]
    except:
        hostname = addr[0]
    
    try:
        request = conn.recv(4096).decode('utf-8', errors='ignore')
        # Extract URL from first line: "GET /path HTTP/1.1"
        try:
            url = request.split(' ')[1]
        except:
            url = "?"
        
        # Serve robots.txt to well-behaved crawlers
        if url == "/robots.txt":
            robots = b"User-agent: *\nDisallow: /\n"
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(robots)).encode() + b"\r\n"
                b"\r\n"
            )
            conn.sendall(response + robots)
            print(f"{addr[0]:<16}   {hostname:<40} \033[96m{url}\033[0m \033[1;92m✓\033[0m")
        else:
            # Bomb malicious scanners who ignore robots.txt
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Encoding: gzip\r\n"
                b"Content-Length: " + str(len(BOMB)).encode() + b"\r\n"
                b"\r\n"
            )
            conn.sendall(response + BOMB)
            print(f"{addr[0]:<16}   {hostname:<40} \033[96m{url}\033[0m \033[1;91m✗\033[0m")
    except (ConnectionResetError, BrokenPipeError):
        print(f"{addr[0]:<16}   {hostname:<40} \033[1;33m·\033[0m")
    except socket.timeout:
        print(f"{addr[0]:<16}   {hostname:<40} \033[1;33m·\033[0m")
    except:
        print(f"{addr[0]:<16}   {hostname:<40} \033[1;33m·\033[0m")
    finally:
        conn.close()

def run_server(port, use_ssl=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', port))
    sock.listen(5)
    
    if use_ssl and HAS_SSL:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        print(f"Listening on port {port} (HTTPS)")
    else:
        context = None
        print(f"Listening on port {port} (HTTP)")
    
    while True:
        conn, addr = sock.accept()
        if context:
            try:
                conn = context.wrap_socket(conn, server_side=True)
            except:
                print(f"{addr[0]:<16}   ssl-failed")
                conn.close()
                continue
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    # Start HTTP on 80
    threading.Thread(target=run_server, args=(80, False), daemon=True).start()
    
    # Start HTTPS on 443 if certs exist
    if HAS_SSL:
        threading.Thread(target=run_server, args=(443, True), daemon=True).start()
    
    print("Press Ctrl+C to stop")
    try:
        while True:
            threading.Event().wait()
    except KeyboardInterrupt:
        print("\nDone")

