#!/usr/bin/env python3
"""
KGV — Krypt Guard Vault | End-to-End Test
===========================================
Automated smoke test covering: register, authenticate (SRP),
upload, list, download, decrypt, delete, and ciphertext verification.
"""

import socket
import json
import struct
import binascii
import os
import sys
import srp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = '127.0.0.1'
PORT = 65432
HEADER_SIZE = 4
MAX_MSG = 10 * 1024 * 1024


# ─── Messaging (must match server) ───────────────────────────────────────────
def send_msg(sock, obj):
    payload = json.dumps(obj).encode('utf-8')
    sock.sendall(struct.pack('!I', len(payload)) + payload)


def recv_msg(sock):
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None
    msg_len = struct.unpack('!I', header)[0]
    assert msg_len <= MAX_MSG, f"Message too large: {msg_len}"
    data = _recv_exact(sock, msg_len)
    assert data is not None, "Connection closed mid-message"
    return json.loads(data.decode('utf-8'))


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def derive_key(password, salt_hex):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=binascii.unhexlify(salt_hex), iterations=480000)
    return kdf.derive(password.encode())


# ─── Test ─────────────────────────────────────────────────────────────────────
def test():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("[TEST] ✗ Could not connect. Is kgv_server.py running?")
        sys.exit(1)

    print("[KGV TEST] Connected to Krypt Guard Vault server")
    uname, pwd = "testuser", "SuperSecret123!"

    # 1. Register
    salt, vkey = srp.create_salted_verification_key(
        uname.encode(), pwd.encode(),
        hash_alg=srp.SHA256, ng_type=srp.NG_2048,
    )
    send_msg(sock, {"cmd": "REGISTER", "user": uname,
                     "salt": binascii.hexlify(salt).decode(),
                     "vkey": binascii.hexlify(vkey).decode()})
    resp = recv_msg(sock)
    assert resp["status"] == "Success", f"Register failed: {resp}"
    print("[KGV TEST] ✓ Registration successful")

    # 2. Duplicate registration should fail
    send_msg(sock, {"cmd": "REGISTER", "user": uname,
                     "salt": binascii.hexlify(salt).decode(),
                     "vkey": binascii.hexlify(vkey).decode()})
    resp = recv_msg(sock)
    assert resp["status"] == "Error", f"Duplicate register should fail: {resp}"
    print("[KGV TEST] ✓ Duplicate registration correctly rejected")

    # 3. Auth Step 1
    usr = srp.User(uname.encode(), pwd.encode(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()
    send_msg(sock, {"cmd": "AUTH_STEP1", "user": uname,
                     "A": binascii.hexlify(A).decode()})
    resp1 = recv_msg(sock)
    assert resp1["status"] == "OK", f"Auth Step 1 failed: {resp1}"
    print("[KGV TEST] ✓ Auth Step 1 — challenge received")

    # 4. Auth Step 2
    salt_srv = binascii.unhexlify(resp1['salt'])
    B = binascii.unhexlify(resp1['B'])
    M = usr.process_challenge(salt_srv, B)
    assert M is not None, "SRP challenge processing failed"
    send_msg(sock, {"cmd": "AUTH_STEP2", "user": uname,
                     "M": binascii.hexlify(M).decode()})
    resp2 = recv_msg(sock)
    assert resp2["status"] == "Success", f"Auth Step 2 failed: {resp2}"
    HAMK = binascii.unhexlify(resp2['HAMK'])
    usr.verify_session(HAMK)
    print("[KGV TEST] ✓ Auth Step 2 — zero-knowledge authentication complete")

    # 5. Encrypt and Upload
    aes_key = derive_key(pwd, resp1['salt'])
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    secret = b"TOP SECRET: The answer is 42."
    ct = aesgcm.encrypt(nonce, secret, None)
    blob = binascii.hexlify(nonce + ct).decode()

    send_msg(sock, {"cmd": "UPLOAD", "filename": "test_secret.enc",
                     "ciphertext": blob})
    resp3 = recv_msg(sock)
    assert resp3["status"] == "Stored Securely", f"Upload failed: {resp3}"
    print("[KGV TEST] ✓ Encrypted upload successful")

    # 6. List files
    send_msg(sock, {"cmd": "LIST"})
    resp4 = recv_msg(sock)
    assert "test_secret.enc" in resp4.get("files", []), f"List failed: {resp4}"
    print(f"[KGV TEST] ✓ File listing OK: {resp4['files']}")

    # 7. Download and decrypt
    send_msg(sock, {"cmd": "DOWNLOAD", "filename": "test_secret.enc"})
    resp5 = recv_msg(sock)
    assert resp5["status"] == "Success", f"Download failed: {resp5}"
    raw = binascii.unhexlify(resp5['ciphertext'])
    plaintext = aesgcm.decrypt(raw[:12], raw[12:], None)
    assert plaintext == secret, f"Decryption mismatch: {plaintext}"
    print(f"[KGV TEST] ✓ Download & decrypt OK: {plaintext.decode()}")

    # 8. Verify server file is just ciphertext on disk
    srv_file = os.path.join("kgv_vault", f"{uname}_test_secret.enc")
    with open(srv_file) as f:
        stored = f.read()
    assert stored == blob, "Stored ciphertext mismatch"
    print(f"[KGV TEST] ✓ Server stores pure ciphertext ({len(stored)} hex chars)")

    # 9. Delete file
    send_msg(sock, {"cmd": "DELETE", "filename": "test_secret.enc"})
    resp6 = recv_msg(sock)
    assert resp6["status"] == "Success", f"Delete failed: {resp6}"
    assert not os.path.exists(srv_file), "File still exists after DELETE"
    print("[KGV TEST] ✓ File deletion successful")

    # 10. Verify list is now empty
    send_msg(sock, {"cmd": "LIST"})
    resp7 = recv_msg(sock)
    assert len(resp7.get("files", [])) == 0, f"Files should be empty: {resp7}"
    print("[KGV TEST] ✓ File list is empty after delete")

    # 11. Upload without auth on a new connection should fail
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.settimeout(10)
    sock2.connect((HOST, PORT))
    send_msg(sock2, {"cmd": "UPLOAD", "filename": "hack.enc", "ciphertext": "aabbccdd"})
    resp8 = recv_msg(sock2)
    assert resp8["status"] == "Unauthorized", f"Unauth upload should fail: {resp8}"
    sock2.close()
    print("[KGV TEST] ✓ Unauthenticated upload correctly rejected")

    sock.close()
    print()
    print("[KGV TEST] ═══════════════════════════════════════")
    print("[KGV TEST]   ALL 11 TESTS PASSED ✓")
    print("[KGV TEST] ═══════════════════════════════════════")


if __name__ == "__main__":
    test()
