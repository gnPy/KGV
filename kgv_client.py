#!/usr/bin/env python3
"""
KGV — Krypt Guard Vault | Client
===================================
This client performs two cryptographic operations entirely on your machine:
  1. SRP handshake  — proves your identity to the server WITHOUT
                      ever transmitting your password.
  2. AES-256-GCM    — derives a local encryption key via PBKDF2
                      and encrypts files BEFORE they leave this device.

The server never sees the password or the plaintext.
"""

import socket
import json
import struct
import binascii
import os
import sys
import re
import getpass
import srp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Configuration ────────────────────────────────────────────────────────────
HOST = '127.0.0.1'
PORT = 65432
CLIENT_DIR = "kgv_downloads"
MAX_MESSAGE_SIZE = 10 * 1024 * 1024   # must match server
HEADER_SIZE = 4
PBKDF2_ITERATIONS = 480_000
MIN_PASSWORD_LEN = 6

os.makedirs(CLIENT_DIR, exist_ok=True)


# ─── Length-Prefixed Messaging ────────────────────────────────────────────────
def send_msg(sock, obj):
    """Send a JSON message with a 4-byte big-endian length prefix."""
    payload = json.dumps(obj).encode('utf-8')
    length = struct.pack('!I', len(payload))
    sock.sendall(length + payload)


def recv_msg(sock):
    """Receive a length-prefixed JSON message. Returns dict or None."""
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None

    msg_len = struct.unpack('!I', header)[0]
    if msg_len > MAX_MESSAGE_SIZE:
        raise ValueError(f"Server message too large: {msg_len} bytes")
    if msg_len == 0:
        raise ValueError("Empty message from server")

    data = _recv_exact(sock, msg_len)
    if data is None:
        raise ValueError("Connection closed mid-message")

    return json.loads(data.decode('utf-8'))


def _recv_exact(sock, n):
    """Read exactly n bytes from the socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None if len(buf) == 0 else None
        buf.extend(chunk)
    return bytes(buf)


# ─── Cryptographic Helpers ────────────────────────────────────────────────────
def derive_local_aes_key(password: str, salt_hex: str) -> bytes:
    """
    Derive a 256-bit AES key from the user's password via PBKDF2-HMAC-SHA256.
    480,000 iterations make brute-force infeasible.
    This key is generated locally and NEVER transmitted.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=binascii.unhexlify(salt_hex),
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_data(aes_key: bytes, plaintext: bytes) -> str:
    """
    Encrypt plaintext with AES-256-GCM.
    Returns hex-encoded (nonce ‖ ciphertext ‖ tag) blob.
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit random nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return binascii.hexlify(nonce + ciphertext).decode()


def decrypt_data(aes_key: bytes, blob_hex: str) -> bytes:
    """
    Decrypt an AES-256-GCM blob (hex-encoded nonce ‖ ciphertext ‖ tag).
    Returns the original plaintext bytes.
    Raises an exception on tampered or wrong-key data.
    """
    raw = binascii.unhexlify(blob_hex)
    if len(raw) < 13:  # 12-byte nonce + at least 1 byte
        raise ValueError("Ciphertext blob is too short to be valid.")
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─── Input Validation ────────────────────────────────────────────────────────
def validate_username(uname):
    """Validate a username string."""
    if not uname:
        raise ValueError("Username cannot be empty.")
    if len(uname) > 64:
        raise ValueError("Username too long (max 64 characters).")
    if not re.match(r'^[\w\-]+$', uname):
        raise ValueError("Username may only contain letters, digits, underscores, and hyphens.")
    return uname


def validate_password(pwd):
    """Validate a password string."""
    if not pwd:
        raise ValueError("Password cannot be empty.")
    if len(pwd) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    return pwd


def safe_input(prompt, secret=False):
    """Read input, optionally masking for passwords."""
    try:
        if secret:
            return getpass.getpass(prompt)
        return input(prompt).strip()
    except EOFError:
        return ""


# ─── Menu Actions ─────────────────────────────────────────────────────────────
def do_register(sock):
    """Register a new user. Only the SRP verifier is sent — NOT the password."""
    print("\n  ── Register a New Account ──")
    try:
        uname = validate_username(safe_input("  Username: "))
        pwd = validate_password(safe_input("  Password: ", secret=True))
    except ValueError as e:
        print(f"  [!] {e}")
        return

    salt, vkey = srp.create_salted_verification_key(
        uname.encode(), pwd.encode(),
        hash_alg=srp.SHA256, ng_type=srp.NG_2048,
    )

    send_msg(sock, {
        "cmd": "REGISTER",
        "user": uname,
        "salt": binascii.hexlify(salt).decode(),
        "vkey": binascii.hexlify(vkey).decode(),
    })

    resp = recv_msg(sock)
    if resp and resp.get("status") == "Success":
        print(f"  [✓] {resp['msg']}")
        print("      → Only the SRP verifier was sent. Your password stayed on this machine.")
    else:
        print(f"  [✗] Registration failed: {resp.get('msg', 'Unknown error') if resp else 'No response'}")


def do_login(sock) -> tuple:
    """
    Authenticate via SRP (zero-knowledge proof).
    Returns (username, salt_hex, aes_key) on success, or (None, None, None).
    """
    print("\n  ── Login ──")
    try:
        uname = validate_username(safe_input("  Username: "))
        pwd = validate_password(safe_input("  Password: ", secret=True))
    except ValueError as e:
        print(f"  [!] {e}")
        return None, None, None

    # ── Step 1: Start SRP handshake ──
    usr = srp.User(uname.encode(), pwd.encode(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()

    send_msg(sock, {
        "cmd": "AUTH_STEP1",
        "user": uname,
        "A": binascii.hexlify(A).decode(),
    })

    resp1 = recv_msg(sock)
    if not resp1 or resp1.get('status') != 'OK':
        msg = resp1.get('msg', 'Unknown error') if resp1 else 'No response from server'
        print(f"  [✗] Auth Step 1 failed: {msg}")
        return None, None, None

    salt_hex = resp1['salt']
    B = binascii.unhexlify(resp1['B'])

    # ── Step 2: Process server challenge & send proof ──
    M = usr.process_challenge(binascii.unhexlify(salt_hex), B)
    if M is None:
        print("  [✗] SRP challenge processing failed (possible protocol mismatch).")
        return None, None, None

    send_msg(sock, {
        "cmd": "AUTH_STEP2",
        "user": uname,
        "M": binascii.hexlify(M).decode(),
    })

    resp2 = recv_msg(sock)
    if not resp2 or resp2.get('status') != 'Success':
        msg = resp2.get('msg', 'Invalid credentials') if resp2 else 'No response'
        print(f"  [✗] Authentication failed: {msg}")
        return None, None, None

    # ── Step 3: Verify server's proof (mutual authentication) ──
    HAMK = binascii.unhexlify(resp2['HAMK'])
    usr.verify_session(HAMK)

    print("  [✓] Zero-Knowledge Authentication Successful!")
    print("      → Your password was NEVER sent over the network.")

    # Derive local AES key
    aes_key = derive_local_aes_key(pwd, salt_hex)
    print("  [✓] Local AES-256 encryption key derived (key stays on this machine).")

    return uname, salt_hex, aes_key


def do_upload_text(sock, aes_key):
    """Encrypt a text secret and upload it to the vault."""
    print("\n  ── Upload Secret Text ──")
    filename = safe_input("  Filename (e.g. secret_note.enc): ") or "my_secret.enc"
    secret = safe_input("  Enter the secret data to encrypt:\n  > ")

    if not secret:
        print("  [!] Nothing to encrypt.")
        return

    ciphertext = encrypt_data(aes_key, secret.encode('utf-8'))

    print(f"\n  [*] Plaintext size  : {len(secret)} chars")
    print(f"  [*] Ciphertext size : {len(ciphertext)} hex chars")
    print(f"  [*] Preview         : {ciphertext[:40]}…")

    send_msg(sock, {
        "cmd": "UPLOAD",
        "filename": filename,
        "ciphertext": ciphertext,
    })

    resp = recv_msg(sock)
    if resp and resp.get("status") == "Stored Securely":
        print(f"  [✓] '{filename}' uploaded! The server stored pure ciphertext — it cannot decrypt it.")
    else:
        print(f"  [✗] Upload failed: {resp.get('msg', 'Unknown error') if resp else 'No response'}")


def do_upload_file(sock, aes_key):
    """Encrypt a local file and upload it to the vault."""
    print("\n  ── Upload Encrypted File ──")
    filepath = safe_input("  Path to the file: ")
    if not filepath or not os.path.isfile(filepath):
        print(f"  [!] File not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        plaintext = f.read()

    if len(plaintext) == 0:
        print("  [!] File is empty.")
        return

    filename = os.path.basename(filepath) + ".enc"
    ciphertext = encrypt_data(aes_key, plaintext)

    print(f"\n  [*] Original size   : {len(plaintext):,} bytes")
    print(f"  [*] Ciphertext size : {len(ciphertext):,} hex chars")

    send_msg(sock, {
        "cmd": "UPLOAD",
        "filename": filename,
        "ciphertext": ciphertext,
    })

    resp = recv_msg(sock)
    if resp and resp.get("status") == "Stored Securely":
        print(f"  [✓] '{filename}' uploaded securely.")
    else:
        print(f"  [✗] Upload failed: {resp.get('msg', 'Unknown error') if resp else 'No response'}")


def do_download(sock, aes_key):
    """Download an encrypted file from the vault and decrypt it locally."""
    print("\n  ── Download & Decrypt ──")
    filename = safe_input("  Filename to download: ")
    if not filename:
        print("  [!] Filename cannot be empty.")
        return

    send_msg(sock, {"cmd": "DOWNLOAD", "filename": filename})

    resp = recv_msg(sock)
    if not resp or resp.get("status") != "Success":
        print(f"  [✗] Download failed: {resp.get('msg', 'Unknown error') if resp else 'No response'}")
        return

    try:
        plaintext = decrypt_data(aes_key, resp['ciphertext'])
    except Exception as e:
        print(f"  [✗] Decryption failed (wrong key or tampered data): {e}")
        return

    # Save decrypted file locally
    base = filename.removesuffix(".enc") if filename.endswith(".enc") else filename
    out_path = os.path.join(CLIENT_DIR, base)
    with open(out_path, "wb") as f:
        f.write(plaintext)

    print(f"  [✓] Decrypted and saved to: {out_path}")

    # If it looks like text, also show a preview
    try:
        text = plaintext.decode('utf-8')
        preview = text[:300].replace('\n', '\n      ')
        print(f"  [*] Content preview:\n      {preview}")
    except UnicodeDecodeError:
        print(f"  [*] (Binary file — {len(plaintext):,} bytes saved)")


def do_list(sock):
    """List all files stored in the vault for this user."""
    print("\n  ── Your Encrypted Files ──")
    send_msg(sock, {"cmd": "LIST"})
    resp = recv_msg(sock)
    if not resp or resp.get("status") != "Success":
        print(f"  [✗] Could not list files: {resp.get('msg', 'Unknown error') if resp else 'No response'}")
        return

    files = resp.get("files", [])
    if not files:
        print("  (No files stored yet.)")
    else:
        print(f"  Found {len(files)} file(s):")
        for i, f in enumerate(files, 1):
            print(f"    {i}. {f}")


def do_delete(sock):
    """Delete a file from the vault."""
    print("\n  ── Delete File ──")
    filename = safe_input("  Filename to delete: ")
    if not filename:
        print("  [!] Filename cannot be empty.")
        return

    confirm = safe_input(f"  Are you sure you want to delete '{filename}'? (y/N): ").lower()
    if confirm != 'y':
        print("  [*] Cancelled.")
        return

    send_msg(sock, {"cmd": "DELETE", "filename": filename})
    resp = recv_msg(sock)
    if resp and resp.get("status") == "Success":
        print(f"  [✓] {resp['msg']}")
    else:
        print(f"  [✗] Delete failed: {resp.get('msg', 'Unknown error') if resp else 'No response'}")


# ─── Main Loop ────────────────────────────────────────────────────────────────
def run_client():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # 30-second connection timeout
        sock.connect((HOST, PORT))
        sock.settimeout(300)  # 5-minute idle timeout after connect
    except ConnectionRefusedError:
        print("[✗] Could not connect to the KGV server. Is kgv_server.py running?")
        sys.exit(1)
    except socket.timeout:
        print("[✗] Connection timed out.")
        sys.exit(1)

    banner = r"""
    ╔══════════════════════════════════════════════════════╗
    ║          KGV — Krypt Guard Vault | Client            ║
    ║          Zero-Knowledge Encrypted Storage             ║
    ╚══════════════════════════════════════════════════════╝"""
    print(banner)
    print(f"    Connected to {HOST}:{PORT}")
    print()

    authenticated_user = None
    aes_key = None

    try:
        while True:
            print()
            if not authenticated_user:
                print("  ┌─────────────────────────────────────────┐")
                print("  │  KGV Menu                               │")
                print("  ├─────────────────────────────────────────┤")
                print("  │  1. Register a new account              │")
                print("  │  2. Login                               │")
                print("  │  q. Quit                                │")
                print("  └─────────────────────────────────────────┘")
            else:
                print(f"  ┌─────────────────────────────────────────┐")
                print(f"  │  KGV — Logged in as: {authenticated_user:<19s}│")
                print(f"  ├─────────────────────────────────────────┤")
                print(f"  │  3. Upload secret text                  │")
                print(f"  │  4. Upload a file                       │")
                print(f"  │  5. Download & decrypt a file           │")
                print(f"  │  6. List my files                       │")
                print(f"  │  7. Delete a file                       │")
                print(f"  │  q. Quit                                │")
                print(f"  └─────────────────────────────────────────┘")

            choice = safe_input("  Select: ").lower()

            if choice == '1':
                do_register(sock)
            elif choice == '2':
                user, salt, key = do_login(sock)
                if user:
                    authenticated_user = user
                    aes_key = key
            elif choice == '3' and authenticated_user:
                do_upload_text(sock, aes_key)
            elif choice == '4' and authenticated_user:
                do_upload_file(sock, aes_key)
            elif choice == '5' and authenticated_user:
                do_download(sock, aes_key)
            elif choice == '6' and authenticated_user:
                do_list(sock)
            elif choice == '7' and authenticated_user:
                do_delete(sock)
            elif choice == 'q':
                break
            else:
                print("  [!] Invalid choice. Please select from the menu above.")

    except KeyboardInterrupt:
        print("\n  [!] Interrupted.")
    except (ConnectionResetError, BrokenPipeError):
        print("\n  [!] Lost connection to server.")
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}")
    finally:
        try:
            sock.close()
        except OSError:
            pass
        print("  [*] Disconnected from KGV server.")


if __name__ == "__main__":
    run_client()
