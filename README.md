# JWKS Server

A Python server that provides JSON Web Key Set (JWKS) endpoints for JWT verification.

## Features
- JWKS endpoint at `/.well-known/jwks.json`
- JWT token generation
- Key expiration management
- SQLite database storage

## Usage
```bash
pip install -r requirements.txt
pip install argon2-cffi
python3 jwks_server.py
