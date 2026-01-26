from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class SecretsCrypto:
    def __init__(self, key: bytes):
        if len(key) != 32:  # 256 bits
            raise ValueError("La clave debe ser de 256 bits")
        self.cipher = AESGCM(key)
    
    def encrypt(self, plaintext: str) -> dict:
        """
        Cifra con AES-256-GCM generando nonce único por operación.
        
        Returns:
            {
                'ciphertext': bytes,  # Dato cifrado
                'nonce': bytes,       # IV único (96 bits)
                'tag': bytes          # Tag de autenticación (incluido en ciphertext)
            }
        """
        # Generar nonce criptográficamente seguro
        nonce = os.urandom(12)  # 96 bits recomendados para GCM
        
        # GCM incluye autenticación (AEAD)
        ciphertext = self.cipher.encrypt(
            nonce, 
            plaintext.encode('utf-8'), 
            None  # Sin datos asociados adicionales
        )
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'algorithm': 'AES-256-GCM'
        }
    
    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """
        Descifra y valida integridad con tag de autenticación.
        
        Raises:
            InvalidTag: Si el ciphertext fue modificado
        """
        plaintext = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
