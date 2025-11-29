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
import logging
import uuid
from argon2 import PasswordHasher

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

hostName = "localhost"
serverPort = 8080

db_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_file, check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid TEXT PRIMARY KEY,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
""")

cursor.execute("SELECT COUNT(*) FROM keys")
if cursor.fetchone()[0] == 0:
    try:
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

        current_time = datetime.datetime.now(datetime.timezone.utc)
        expired_time = current_time - datetime.timedelta(hours=1)

        cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", 
                       ("goodKID", pem, int(current_time.timestamp() + 3600)))
        cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", 
                       ("expiredKID", expired_pem, int(expired_time.timestamp())))
        conn.commit()
        logger.info("Generated and stored initial RSA keys")
    except Exception as e:
        logger.error(f"Error generating keys: {e}")

ph = PasswordHasher()

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def hash_password(password):
    try:
        return ph.hash(password)
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        return None

def verify_password(password, password_hash):
    try:
        return ph.verify(password_hash, password)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False

def register_user(username, email, password):
    try:
        if not username or not email or not password:
            return {"error": "Username, email and password are required"}, 400
        
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            return {"error": "Username or email already exists"}, 409
        
        password_hash = hash_password(password)
        if not password_hash:
            return {"error": "Error creating user"}, 500
        
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", 
                       (username, password_hash, email))
        conn.commit()
        
        logger.info(f"User registered: {username}")
        return {"message": "User registered successfully"}, 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return {"error": "Internal server error"}, 500

def log_auth_request(request_ip, user_id):
    try:
        cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", 
                       (request_ip, user_id))
        conn.commit()
    except Exception as e:
        logger.error(f"Error logging auth request: {e}")

class MyServer(BaseHTTPRequestHandler):
    def _send_response(self, data, status_code=200, content_type="application/json"):
        try:
            self.send_response(status_code)
            self.send_header("Content-type", content_type)
            self.end_headers()
            if data:
                if content_type == "application/json":
                    self.wfile.write(bytes(json.dumps(data), "utf-8"))
                else:
                    self.wfile.write(bytes(data, "utf-8"))
        except Exception as e:
            logger.error(f"Error sending response: {e}")
    
    def _send_error(self, status_code, message):
        self._send_response({"error": message}, status_code)
    
    def log_message(self, format, *args):
        logger.info("%s - %s", self.address_string(), format % args)
    
    def do_PUT(self):
        self._send_error(405, "Method Not Allowed")
    
    def do_PATCH(self):
        self._send_error(405, "Method Not Allowed")
    
    def do_DELETE(self):
        self._send_error(405, "Method Not Allowed")
    
    def do_HEAD(self):
        self._send_error(405, "Method Not Allowed")
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
            else:
                data = {}
        except (ValueError, json.JSONDecodeError) as e:
            logger.warning(f"Invalid JSON in request: {e}")
            self._send_error(400, "Invalid JSON")
            return
        except Exception as e:
            logger.error(f"Error reading request data: {e}")
            self._send_error(400, "Bad Request")
            return
        
        if parsed_path.path == "/register":
            try:
                username = data.get("username")
                email = data.get("email")
                password = data.get("password")
                
                response, status_code = register_user(username, email, password)
                self._send_response(response, status_code)
                
            except KeyError as e:
                logger.warning(f"Missing field in registration: {e}")
                self._send_error(400, f"Missing required field: {e}")
            except Exception as e:
                logger.error(f"Registration error: {e}")
                self._send_error(500, "Internal server error")
            return
        
        elif parsed_path.path == "/auth":
            try:
                current_time = datetime.datetime.now(datetime.timezone.utc)
                
                headers = {"kid": "goodKID"}
                token_payload = {
                    "user": "username",
                    "exp": current_time + datetime.timedelta(hours=1)
                }
                
                if 'expired' in params:
                    headers["kid"] = "expiredKID"
                    token_payload["exp"] = current_time - datetime.timedelta(hours=1)
                
                username = data.get("username")
                password = data.get("password")
                
                if username and password:
                    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
                    user_data = cursor.fetchone()
                    
                    if user_data and verify_password(password, user_data[1]):
                        user_id = user_data[0]
                        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
                        conn.commit()
                        
                        client_ip = self.client_address[0]
                        log_auth_request(client_ip, user_id)
                        
                        token_payload["user"] = username
                        token_payload["user_id"] = user_id
                    else:
                        self._send_error(401, "Invalid credentials")
                        return
                
                kid = headers["kid"]
                cursor.execute("SELECT key FROM keys WHERE kid = ?", (kid,))
                key_data = cursor.fetchone()
                
                if not key_data:
                    logger.error(f"Key not found: {kid}")
                    self._send_error(500, "Key not found")
                    return
                
                key = serialization.load_pem_private_key(key_data[0], password=None, backend=default_backend())
                encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)
                
                self._send_response({"token": encoded_jwt}, 200)
                
            except Exception as e:
                logger.error(f"Auth error: {e}")
                self._send_error(500, "Internal server error")
            return
        
        self._send_error(405, "Method Not Allowed")
    
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            try:
                current_time = datetime.datetime.now(datetime.timezone.utc)
                
                cursor.execute("SELECT kid FROM keys WHERE exp > ?", (int(current_time.timestamp()),))
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
                
                self._send_response(keys, 200)
                
            except Exception as e:
                logger.error(f"JWKS error: {e}")
                self._send_error(500, "Internal server error")
            return
        
        self._send_error(405, "Method Not Allowed")

if __name__ == "__main__":
    try:
        webServer = HTTPServer((hostName, serverPort), MyServer)
        logger.info(f"JWKS Server started http://{hostName}:{serverPort}")
        
        webServer.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        webServer.server_close()
        conn.close()
        logger.info("Server stopped.")
