"""Módulo de cifrado AES-256-GCM"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64

class SecretsCrypto:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Clave debe ser de 32 bytes (256 bits)")
        self.cipher = AESGCM(key)
    
    def encrypt(self, plaintext: str) -> dict:
        """
        Cifra con AES-GCM generando nonce único.
        
        Threat Model:
        - T-008: Nonce único previene ataques de reutilización
        - T-007: GCM incluye authentication tag
        """
        nonce = os.urandom(12)  # 96 bits para GCM
        ciphertext = self.cipher.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            None
        )
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce
        }
    
    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """
        Descifra y valida integridad.
        
        Raises:
            ValueError: Si detecta tampering (T-007)
        """
        try:
            plaintext = self.cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode('utf-8')
        except Exception:
            raise ValueError("Fallo en verificación de integridad")

def key_from_base64(key_b64: str) -> bytes:
    """Convierte clave Base64 a bytes"""
    if key_b64 == 'DEMO_KEY_INSECURE':
        print("⚠️  Usando clave de demostración insegura")
        return b'0' * 32
    
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError("Clave inválida")
    return key
