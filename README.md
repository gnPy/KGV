# KGV — Krypt Guard Vault

**A zero-knowledge encrypted file vault where the server can never see your password or your files.**

---

## What Is This?

KGV is a client-server system that lets you store files in a remote vault **without trusting the server**. Two layers of cryptography make this possible:

1. **Your password never leaves your machine.** Authentication uses the [Secure Remote Password (SRP)](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol) protocol — the server verifies you know the password through a mathematical proof, without ever receiving the password itself.

2. **Your files are encrypted before upload.** The client derives a strong 256-bit AES key from your password locally (using PBKDF2 with 480,000 iterations), encrypts your files with AES-256-GCM, and only sends the ciphertext. The server stores it as-is.

**Bottom line:** If the server is breached, the attacker gets nothing — no passwords (only SRP verifiers) and no readable files (only AES ciphertext they can't decrypt).

---

## Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### 2. Install Dependencies

```bash
cd /path/to/KGV
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

This installs two packages:
- `srp` — Secure Remote Password protocol
- `cryptography` — AES-256-GCM encryption and PBKDF2 key derivation

### 3. Start the Server

Open a terminal and run:

```bash
source venv/bin/activate
python3 kgv_server.py
```

You'll see:

```
    ╔══════════════════════════════════════════════════════╗
    ║          KGV — Krypt Guard Vault | Server            ║
    ║          Zero-Knowledge Encrypted Storage             ║
    ╚══════════════════════════════════════════════════════╝
    Listening on  : 127.0.0.1:65432
    Vault directory: /path/to/KGV/kgv_vault/
    ⚠  The server NEVER sees passwords or plaintext files.
```

### 4. Start the Client

Open a **second terminal** and run:

```bash
source venv/bin/activate
python3 kgv_client.py
```

You'll see an interactive menu.

---

## How to Use It

### Register

1. Select option **1** from the menu.
2. Enter a username and password.
3. The client computes an SRP verifier and sends it to the server. **Your password stays on your machine.**

### Login

1. Select option **2**.
2. Enter your credentials.
3. The SRP handshake runs — both sides verify each other through mathematical proofs.
4. On success, a local AES-256 key is derived from your password. This key never leaves your machine.

### Upload a Secret (text)

1. Select option **3** (after logging in).
2. Type a filename and the secret text.
3. The text is encrypted locally with AES-256-GCM, then only the ciphertext is sent.

### Upload a File

1. Select option **4**.
2. Give the path to any file on your machine.
3. The file is encrypted and uploaded as `<filename>.enc`.

### Download & Decrypt

1. Select option **5**.
2. Enter the filename.
3. The ciphertext is downloaded and decrypted locally using your AES key.
4. The decrypted file is saved to the `kgv_downloads/` directory.

### List Files

1. Select option **6** to see all your encrypted files on the server.

### Delete a File

1. Select option **7**.
2. Enter the filename. Confirm the deletion.

---

## Project Structure

```
KGV/
├── kgv_server.py       # Vault server (SRP auth + ciphertext storage)
├── kgv_client.py       # Interactive client (encryption + SRP)
├── kgv_test.py         # Automated end-to-end test suite (11 tests)
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── kgv_vault/          # (auto-created) Server stores encrypted blobs here
└── kgv_downloads/      # (auto-created) Client saves decrypted files here
```

---

## How to Prove It Is Zero-Knowledge

This is useful for demonstrations, thesis defenses, or audits.

### Step 1: Show the server's storage

After uploading a file, open the `kgv_vault/` folder. Every file is pure hexadecimal ciphertext — unreadable without the client's AES key.

```bash
cat kgv_vault/testuser_my_secret.enc
# Output: a3f7c2...  (meaningless ciphertext)
```

### Step 2: Show the server logs

The server terminal will print messages like:

```
[✓] Registered user 'testuser' — verifier stored, password NEVER seen
[✓] Auth complete — 'testuser' verified (password NEVER transmitted)
[↑] Stored 'my_secret.enc' for 'testuser' — server has NO decryption key
```

### Step 3: Show that the server has no keys

The server code has:
- **No password variable** — only SRP verifiers (one-way mathematical values).
- **No AES key** — the key is derived only inside `kgv_client.py`.
- **No decryption function** — the server literally cannot decrypt the stored files.

### Step 4: Run the automated test suite

```bash
python3 kgv_test.py
```

This runs 11 automated checks including registration, authentication, encrypted upload, download, decryption, deletion, and unauthorized access rejection.

---

## How It Works (Technical Detail)

### Authentication Flow (SRP Protocol)

```
Client                                    Server
  │                                         │
  │── REGISTER: salt + verifier ──────────→ │  Password NEVER sent
  │                                         │  (only SRP verifier stored)
  │                                         │
  │── AUTH_STEP1: sends A ────────────────→ │
  │←── Challenge: salt + B ────────────────│
  │── AUTH_STEP2: sends M (proof) ────────→ │
  │←── Mutual proof: HAMK ────────────────│
  │                                         │
  ✓ Both sides verified.                   ✓
```

- `A` and `B` are ephemeral public values.
- `M` is a proof the client knows the password.
- `HAMK` is a proof the server knows the verifier.
- **The password itself is never part of any message.**

### Encryption Flow (AES-256-GCM)

```
Password ──→ PBKDF2 (480K iterations) ──→ 256-bit AES Key (local only)
                                              │
Plaintext ──→ AES-256-GCM + random nonce ──→ Ciphertext ──→ Sent to server
```

- PBKDF2 with 480,000 iterations makes brute-force attacks infeasible.
- AES-256-GCM provides both encryption and tamper detection.
- A fresh random 96-bit nonce is generated for every encryption.
- The AES key exists **only in client memory** — it is never stored or sent.

### Robustness Features

| Feature | Description |
|---------|-------------|
| Length-prefixed messaging | 4-byte header prevents TCP partial-read bugs |
| Input validation | Usernames, filenames, and hex values are validated |
| Filename sanitization | Path traversal attacks (`../`) are blocked |
| Socket timeouts | 5-minute idle timeout; 30-second connect timeout |
| Graceful shutdown | Server handles SIGINT/SIGTERM cleanly |
| Thread safety | User database protected by a mutex lock |
| Password masking | Passwords are hidden during input (via `getpass`) |
| Message size limit | 10 MB hard cap prevents memory exhaustion |
| Duplicate user check | Re-registering an existing username is rejected |

---

## Threat Model

| Threat | Protected? | How |
|--------|-----------|-----|
| Server breach — passwords stolen | ✅ Yes | Server stores only SRP verifiers (one-way; not reversible) |
| Server breach — files stolen | ✅ Yes | Files are AES-256-GCM ciphertext; key only exists on client |
| Man-in-the-middle on login | ✅ Yes | SRP provides mutual authentication without transmitting the password |
| Replay attacks | ✅ Yes | SRP uses ephemeral values; AES-GCM uses random nonces |
| Brute-force password cracking | ✅ Yes | PBKDF2 with 480,000 iterations makes each guess very expensive |
| Path traversal attacks | ✅ Yes | Filenames are sanitized; `../` and `/` are rejected |
| Unauthorized file access | ✅ Yes | Every command except REGISTER requires a valid SRP session |

---

## Running the Tests

Make sure the server is running in a separate terminal, then:

```bash
source venv/bin/activate
python3 kgv_test.py
```

Expected output:

```
[KGV TEST] Connected to Krypt Guard Vault server
[KGV TEST] ✓ Registration successful
[KGV TEST] ✓ Duplicate registration correctly rejected
[KGV TEST] ✓ Auth Step 1 — challenge received
[KGV TEST] ✓ Auth Step 2 — zero-knowledge authentication complete
[KGV TEST] ✓ Encrypted upload successful
[KGV TEST] ✓ File listing OK: ['test_secret.enc']
[KGV TEST] ✓ Download & decrypt OK: TOP SECRET: The answer is 42.
[KGV TEST] ✓ Server stores pure ciphertext (114 hex chars)
[KGV TEST] ✓ File deletion successful
[KGV TEST] ✓ File list is empty after delete
[KGV TEST] ✓ Unauthenticated upload correctly rejected

[KGV TEST]   ALL 11 TESTS PASSED ✓
```

---

## License

This project is provided for educational and demonstration purposes.
