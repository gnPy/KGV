#!/usr/bin/env python3
"""
KGV — Krypt Guard Vault | Server
==================================
A Zero-Knowledge vault server that:
  • Authenticates users via the SRP protocol (password is NEVER seen).
  • Stores AES-256-GCM ciphertext (encryption key is NEVER held).

Even with full database access, an attacker obtains
zero passwords and zero plaintext files.
"""

import socket
import json
import struct
import binascii
import os
import re
import threading
import signal
import sys
from datetime import datetime
import srp

# ─── Configuration ────────────────────────────────────────────────────────────
HOST = '127.0.0.1'
PORT = 65432
VAULT_DIR = "kgv_vault"
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB hard limit per message
HEADER_SIZE = 4                       # 4-byte length prefix
MAX_FILENAME_LEN = 200
ALLOWED_FILENAME_RE = re.compile(r'^[\w\-. ]+$')  # alphanumeric, dash, dot, space

# ─── Initialisation ──────────────────────────────────────────────────────────
os.makedirs(VAULT_DIR, exist_ok=True)

# In-memory user database (demonstration purposes).
# Format: {"username": {"salt": <hex>, "vkey": <hex>}}
user_db = {}
db_lock = threading.Lock()

# Graceful shutdown flag
shutdown_event = threading.Event()


# ─── Helpers ──────────────────────────────────────────────────────────────────
def timestamp():
    """Return a compact timestamp for log lines."""
    return datetime.now().strftime("%H:%M:%S")


def log(tag, msg):
    """Timestamped tagged logger."""
    print(f"[{timestamp()}] [{tag}] {msg}")


def send_msg(conn, obj):
    """
    Send a JSON message with a 4-byte big-endian length prefix.
    This eliminates the classic TCP partial-read / message-boundary bug.
    """
    payload = json.dumps(obj).encode('utf-8')
    length = struct.pack('!I', len(payload))
    conn.sendall(length + payload)


def recv_msg(conn):
    """
    Receive a length-prefixed JSON message. Returns the parsed dict,
    or None if the connection was closed cleanly.
    Raises ValueError on protocol errors.
    """
    # Read the 4-byte length header
    header = _recv_exact(conn, HEADER_SIZE)
    if header is None:
        return None  # clean disconnect

    msg_len = struct.unpack('!I', header)[0]
    if msg_len > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {msg_len} bytes (limit {MAX_MESSAGE_SIZE})")
    if msg_len == 0:
        raise ValueError("Empty message received")

    data = _recv_exact(conn, msg_len)
    if data is None:
        raise ValueError("Connection closed mid-message")

    return json.loads(data.decode('utf-8'))


def _recv_exact(conn, n):
    """Read exactly n bytes from the socket, or return None on clean close."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None if len(buf) == 0 else None
        buf.extend(chunk)
    return bytes(buf)


def sanitize_filename(name):
    """
    Validate and sanitise a user-supplied filename.
    Returns the cleaned name or raises ValueError.
    """
    name = name.strip()
    if not name:
        raise ValueError("Filename cannot be empty.")
    if len(name) > MAX_FILENAME_LEN:
        raise ValueError(f"Filename too long (max {MAX_FILENAME_LEN} chars).")
    # Block path traversal
    if '..' in name or '/' in name or '\\' in name:
        raise ValueError("Filename contains illegal path characters.")
    if not ALLOWED_FILENAME_RE.match(name):
        raise ValueError("Filename contains disallowed characters.")
    return name


def validate_hex(value, field_name):
    """Ensure a value is valid hexadecimal."""
    if not value or not isinstance(value, str):
        raise ValueError(f"'{field_name}' must be a non-empty hex string.")
    try:
        binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        raise ValueError(f"'{field_name}' is not valid hex.")


def validate_username(uname):
    """Ensure a username is sane."""
    if not uname or not isinstance(uname, str):
        raise ValueError("Username must be a non-empty string.")
    if len(uname) > 64:
        raise ValueError("Username too long (max 64 chars).")
    if not re.match(r'^[\w\-]+$', uname):
        raise ValueError("Username may only contain letters, digits, underscores, and hyphens.")


# ─── Client Handler ──────────────────────────────────────────────────────────
def handle_client(conn, addr):
    """
    Handle one client connection.  Supports the following commands:
      REGISTER   – store a new SRP verifier (no password ever sent)
      AUTH_STEP1 – begin the SRP handshake
      AUTH_STEP2 – complete the SRP handshake
      UPLOAD     – store an encrypted file blob (requires auth)
      DOWNLOAD   – retrieve an encrypted file blob (requires auth)
      LIST       – list stored files for the authenticated user
      DELETE     – delete a stored file (requires auth)
    """
    log("→", f"New connection from {addr}")
    conn.settimeout(300)  # 5-minute idle timeout per socket

    authenticated_user = None
    svr = None  # SRP Verifier state for this session

    while not shutdown_event.is_set():
        try:
            req = recv_msg(conn)
            if req is None:
                break  # clean disconnect

            cmd = req.get('cmd')
            if not cmd or not isinstance(cmd, str):
                send_msg(conn, {"status": "Error", "msg": "Missing or invalid 'cmd' field."})
                continue

            # ── REGISTER ──────────────────────────────────────────────
            if cmd == 'REGISTER':
                try:
                    uname = req['user']
                    validate_username(uname)
                    validate_hex(req.get('salt'), 'salt')
                    validate_hex(req.get('vkey'), 'vkey')
                except (KeyError, ValueError) as e:
                    send_msg(conn, {"status": "Error", "msg": str(e)})
                    continue

                with db_lock:
                    if uname in user_db:
                        send_msg(conn, {"status": "Error", "msg": "User already exists."})
                        continue
                    user_db[uname] = {
                        'salt': req['salt'],
                        'vkey': req['vkey'],
                    }
                log("✓", f"Registered user '{uname}' — verifier stored, password NEVER seen")
                send_msg(conn, {"status": "Success", "msg": f"User '{uname}' registered."})

            # ── AUTH STEP 1 ───────────────────────────────────────────
            elif cmd == 'AUTH_STEP1':
                try:
                    uname = req['user']
                    validate_username(uname)
                    validate_hex(req.get('A'), 'A')
                except (KeyError, ValueError) as e:
                    send_msg(conn, {"status": "Error", "msg": str(e)})
                    continue

                with db_lock:
                    record = user_db.get(uname)
                if record is None:
                    log("✗", f"Auth Step 1 — unknown user '{uname}'")
                    send_msg(conn, {"status": "Error", "msg": "Unknown user."})
                    continue

                A = binascii.unhexlify(req['A'])
                salt = binascii.unhexlify(record['salt'])
                vkey = binascii.unhexlify(record['vkey'])

                svr = srp.Verifier(
                    uname.encode(), salt, vkey, A,
                    hash_alg=srp.SHA256, ng_type=srp.NG_2048,
                )
                s, B = svr.get_challenge()

                if s is None or B is None:
                    log("✗", f"Auth Step 1 — SRP challenge failed for '{uname}'")
                    send_msg(conn, {"status": "Error", "msg": "SRP challenge generation failed."})
                    svr = None
                    continue

                log("…", f"Auth Step 1 OK for '{uname}' — challenge sent")
                send_msg(conn, {
                    "status": "OK",
                    "salt": binascii.hexlify(s).decode(),
                    "B": binascii.hexlify(B).decode(),
                })

            # ── AUTH STEP 2 ───────────────────────────────────────────
            elif cmd == 'AUTH_STEP2':
                if svr is None:
                    send_msg(conn, {"status": "Error", "msg": "No active SRP session. Run AUTH_STEP1 first."})
                    continue

                try:
                    validate_hex(req.get('M'), 'M')
                except ValueError as e:
                    send_msg(conn, {"status": "Error", "msg": str(e)})
                    continue

                M = binascii.unhexlify(req['M'])
                HAMK = svr.verify_session(M)

                if HAMK is not None:
                    authenticated_user = req.get('user', '?')
                    log("✓", f"Auth complete — '{authenticated_user}' verified (password NEVER transmitted)")
                    send_msg(conn, {
                        "status": "Success",
                        "HAMK": binascii.hexlify(HAMK).decode(),
                    })
                else:
                    log("✗", f"Auth Step 2 — invalid SRP proof from '{req.get('user', '?')}'")
                    send_msg(conn, {"status": "Failed", "msg": "SRP proof invalid."})
                    svr = None  # reset session on failure

            # ── UPLOAD ────────────────────────────────────────────────
            elif cmd == 'UPLOAD':
                if not authenticated_user:
                    send_msg(conn, {"status": "Unauthorized", "msg": "Login first."})
                    continue

                try:
                    filename = sanitize_filename(req.get('filename', ''))
                    ciphertext = req.get('ciphertext', '')
                    if not ciphertext or not isinstance(ciphertext, str):
                        raise ValueError("Ciphertext payload is empty or invalid.")
                    validate_hex(ciphertext, 'ciphertext')
                except (ValueError, KeyError) as e:
                    send_msg(conn, {"status": "Error", "msg": str(e)})
                    continue

                filepath = os.path.join(VAULT_DIR, f"{authenticated_user}_{filename}")
                with open(filepath, "w") as f:
                    f.write(ciphertext)

                log("↑", f"Stored '{filename}' for '{authenticated_user}' — server has NO decryption key")
                send_msg(conn, {"status": "Stored Securely", "msg": f"'{filename}' saved."})

            # ── DOWNLOAD ──────────────────────────────────────────────
            elif cmd == 'DOWNLOAD':
                if not authenticated_user:
                    send_msg(conn, {"status": "Unauthorized", "msg": "Login first."})
                    continue

                try:
                    filename = sanitize_filename(req.get('filename', ''))
                except ValueError as e:
                    send_msg(conn, {"status": "Error", "msg": str(e)})
                    continue

                filepath = os.path.join(VAULT_DIR, f"{authenticated_user}_{filename}")
                if not os.path.isfile(filepath):
                    send_msg(conn, {"status": "Error", "msg": f"File '{filename}' not found."})
                    continue

                with open(filepath, "r") as f:
                    ciphertext = f.read()

                log("↓", f"Serving '{filename}' to '{authenticated_user}'")
                send_msg(conn, {"status": "Success", "ciphertext": ciphertext})

            # ── LIST ──────────────────────────────────────────────────
            elif cmd == 'LIST':
                if not authenticated_user:
                    send_msg(conn, {"status": "Unauthorized", "msg": "Login first."})
                    continue

                prefix = f"{authenticated_user}_"
                files = sorted([
                    f[len(prefix):]
                    for f in os.listdir(VAULT_DIR)
                    if f.startswith(prefix)
                ])
                log("≡", f"Listed {len(files)} file(s) for '{authenticated_user}'")
                send_msg(conn, {"status": "Success", "files": files})

            # ── DELETE ────────────────────────────────────────────────
            elif cmd == 'DELETE':
                if not authenticated_user:
                    send_msg(conn, {"status": "Unauthorized", "msg": "Login first."})
                    continue

                try:
                    filename = sanitize_filename(req.get('filename', ''))
                except ValueError as e:
                    send_msg(conn, {"status": "Error", "msg": str(e)})
                    continue

                filepath = os.path.join(VAULT_DIR, f"{authenticated_user}_{filename}")
                if not os.path.isfile(filepath):
                    send_msg(conn, {"status": "Error", "msg": f"File '{filename}' not found."})
                    continue

                os.remove(filepath)
                log("✕", f"Deleted '{filename}' for '{authenticated_user}'")
                send_msg(conn, {"status": "Success", "msg": f"'{filename}' deleted."})

            else:
                send_msg(conn, {"status": "Error", "msg": f"Unknown command '{cmd}'."})

        except socket.timeout:
            log("⏱", f"Connection from {addr} timed out")
            break
        except (ConnectionResetError, BrokenPipeError):
            break
        except json.JSONDecodeError as e:
            log("!", f"Malformed JSON from {addr}: {e}")
            break
        except ValueError as e:
            log("!", f"Protocol error from {addr}: {e}")
            break
        except Exception as e:
            log("!", f"Unexpected error from {addr}: {e}")
            break

    log("←", f"Connection from {addr} closed")
    try:
        conn.close()
    except OSError:
        pass


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner = r"""
    ╔══════════════════════════════════════════════════════╗
    ║          KGV — Krypt Guard Vault | Server            ║
    ║          Zero-Knowledge Encrypted Storage             ║
    ╚══════════════════════════════════════════════════════╝"""
    print(banner)
    print(f"    Listening on  : {HOST}:{PORT}")
    print(f"    Vault directory: {os.path.abspath(VAULT_DIR)}/")
    print(f"    Max message   : {MAX_MESSAGE_SIZE // (1024*1024)} MB")
    print("    ⚠  The server NEVER sees passwords or plaintext files.")
    print()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.settimeout(1.0)  # allow periodic shutdown checks
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)

    def signal_handler(sig, frame):
        log("!", "Shutdown signal received — stopping server…")
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    threads = []
    try:
        while not shutdown_event.is_set():
            try:
                conn, addr = server_sock.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
                threads.append(t)
            except socket.timeout:
                continue
    finally:
        server_sock.close()
        log("!", "Server shut down cleanly.")


if __name__ == "__main__":
    main()
