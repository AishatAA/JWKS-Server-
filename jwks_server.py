
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

# Host and port for the server
hostName = "localhost"
serverPort = 8080

# Initialize SQLite database and connect
db_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create keys table if not exists
cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid TEXT PRIMARY KEY,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
""")

# Generate private keys if the table is empty
cursor.execute("SELECT COUNT(*) FROM keys")
if cursor.fetchone()[0] == 0:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize private keys into PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Store private keys in the database
    cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", 
                   ("goodKID", pem, int(datetime.datetime.utcnow().timestamp() + 3600)))  # 1 hour expiry
    cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", 
                   ("expiredKID", expired_pem, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())))
    conn.commit()

# Get current private key from database
cursor.execute("SELECT key FROM keys WHERE kid = 'goodKID'")
private_key_row = cursor.fetchone()
private_key = serialization.load_pem_private_key(private_key_row[0], password=None, backend=default_backend())

# Get public key numbers for JWKS
public_numbers = private_key.public_key().public_numbers()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        if parsed_path.path == "/auth":
            headers = {"kid": "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                
            # Get the appropriate private key
            kid = headers["kid"]
            cursor.execute("SELECT key FROM keys WHERE kid = ?", (kid,))
            key_data = cursor.fetchone()
            key = serialization.load_pem_private_key(key_data[0], password=None, backend=default_backend())
            
            encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            # Get only valid (non-expired) keys
            cursor.execute("SELECT kid FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
            valid_keys = cursor.fetchall()
            
            keys = {"keys": []}
            for (kid,) in valid_keys:
                cursor.execute("SELECT key FROM keys WHERE kid = ?", (kid,))
                key_data = cursor.fetchone()
                key = serialization.load_pem_private_key(key_data[0], password=None, backend=default_backend())
                pub_numbers = key.public_key().public_numbers()
                
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": kid,
                    "n": int_to_base64(pub_numbers.n),
                    "e": int_to_base64(pub_numbers.e),
                })
            
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("JWKS Server started http://%s:%s" % (hostName, serverPort))
    
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    conn.close()
    print("Server stopped.")
