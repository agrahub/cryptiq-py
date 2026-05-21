# cryptiq

A lightweight, backend-agnostic cryptography abstraction layer for Python.

## Overview

cryptiq provides a unified and strongly-typed interface over multiple cryptography backends.

It focuses on consistency, composability, and safe defaults while allowing flexibility between implementations such as `cryptography` and `pycryptodome`.

---

## Features

- Backend-agnostic cryptographic API
- RSA key generation and loading
- Unified encryption/decryption interface
- Strong typing with overload-safe APIs
- Support for multiple key formats (PEM/bytes/string)
- Pluggable backend system (`cryptography`, `pycryptodome`)
- Clean separation of crypto logic and type definitions

---

## Installation

Using uv:

```bash
uv add cryptiq
```

Or pip:

```bash
pip install cryptiq
```

---

## Usage

### Key Generation

```python
from cryptiq.enums import Backend
from cryptiq.rsa import generate_private

keypair = generate_private(Backend.CRYPTOGRAPHY)
```

---

### Loading Keys

```python
from cryptiq.keys import load_private
from cryptiq.enums import Backend

key = load_private(
    Backend.CRYPTOGRAPHY,
    path="private.pem",
    password=None,
)
```

---

### Encryption

```python
from cryptiq.rsa import encrypt
from cryptiq.enums import Backend

ciphertext = encrypt(
    key,
    "hello world"
)
```

---

### Bytes Mode

```python
ciphertext = encrypt(key, b"hello world")
```

---

## Design Philosophy

cryptiq follows these principles:

- Backend abstraction without leaking implementation details
- Strong typing with explicit overloads
- Consistent input/output behavior across APIs
- Prefer safe defaults over flexible ambiguity
- Keep crypto primitives simple and composable

---

## Non-goals

cryptiq does NOT aim to:

- Replace full-featured crypto libraries like `cryptography`
- Implement low-level cryptographic primitives from scratch
- Provide opinionated security policies (key storage, rotation, etc.)
- Become a framework-level security system
- Hide cryptographic behavior behind excessive abstraction

---

## Architecture Notes

cryptiq is built around a backend dispatch model:

- `Backend` enum selects implementation
- Each backend returns its native key types
- Public APIs normalize behavior through typed unions and overloads

This allows flexibility while keeping a consistent external API surface.