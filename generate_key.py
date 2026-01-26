import secrets
import base64

def generate_master_key():
    key = secrets.token_bytes(32)
    key_b64 = base64.b64encode(key).decode('ascii')
    print(f"Agrega a tus variables de entorno:")
    print(f"export MASTER_ENCRYPTION_KEY='{key_b64}'")

if __name__ == '__main__':
    generate_master_key()
