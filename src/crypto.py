"""
Módulo de cifrado para Secure Secrets API
Implementa AES-256-GCM con generación segura de nonces
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
import base64
from typing import Dict

class SecretsCrypto:
    """
    Gestor de cifrado usando AES-256-GCM (Authenticated Encryption).
    
    AES-GCM proporciona:
    - Confidencialidad: El contenido no puede leerse sin la clave
    - Integridad: Detecta modificaciones del ciphertext
    - Autenticidad: Verifica que el cifrado fue hecho con la clave correcta
    """
    
    def __init__(self, key: bytes):
        """
        Args:
            key: Clave de 256 bits (32 bytes) para AES-256
        
        Raises:
            ValueError: Si la clave no tiene exactamente 32 bytes
        """
        if len(key) != 32:
            raise ValueError(
                f"La clave debe ser de 256 bits (32 bytes). "
                f"Recibida: {len(key)} bytes"
            )
        self.cipher = AESGCM(key)
    
    def encrypt(self, plaintext: str) -> Dict[str, bytes]:
        """
        Cifra un texto plano usando AES-256-GCM.
        
        Args:
            plaintext: Texto a cifrar (secreto)
        
        Returns:
            Diccionario con:
            - ciphertext: Datos cifrados (incluye authentication tag)
            - nonce: IV único usado para este cifrado
            - algorithm: Identificador del algoritmo
        
        Nota sobre el nonce:
        - Se genera con os.urandom() para máxima entropía
        - Debe ser único para cada operación con la misma clave
        - 96 bits (12 bytes) es el tamaño recomendado para GCM
        - NO es secreto, se almacena junto al ciphertext
        """
        # Generar nonce criptográficamente seguro
        # Probabilidad de colisión: 2^-96 ≈ 1 en 79 mil billones de billones
        nonce = os.urandom(12)
        
        # Cifrar con autenticación
        # GCM automáticamente agrega un tag de 128 bits al ciphertext
        ciphertext = self.cipher.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            None  # Associated data (opcional, no usado aquí)
        )
        
        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'algorithm': 'AES-256-GCM'
        }
    
    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """
        Descifra un ciphertext y valida su integridad.
        
        Args:
            ciphertext: Datos cifrados (con tag incluido)
            nonce: IV usado durante el cifrado
        
        Returns:
            Texto plano descifrado
        
        Raises:
            InvalidTag: Si el ciphertext fue modificado o el tag no coincide
            UnicodeDecodeError: Si el plaintext no es UTF-8 válido
        """
        try:
            plaintext_bytes = self.cipher.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode('utf-8')
        except InvalidTag:
            # Esto indica que:
            # 1. El ciphertext fue modificado (tampering)
            # 2. Se usó un nonce incorrecto
            # 3. Se usó una clave incorrecta
            raise ValueError(
                "Fallo en la verificación de integridad. "
                "El secreto pudo haber sido modificado."
            )
    
    @staticmethod
    def encode_for_storage(data: bytes) -> str:
        """
        Codifica bytes a string para almacenamiento en DB.
        
        Args:
            data: Bytes a codificar
        
        Returns:
            String Base64 (seguro para almacenar en texto)
        """
        return base64.b64encode(data).decode('ascii')
    
    @staticmethod
    def decode_from_storage(data: str) -> bytes:
        """
        Decodifica string Base64 a bytes originales.
        
        Args:
            data: String Base64
        
        Returns:
            Bytes originales
        """
        return base64.b64decode(data)


def generate_master_key() -> bytes:
    """
    Genera una clave maestra aleatoria de 256 bits.
    
    IMPORTANTE: En producción, esta clave debe:
    1. Generarse UNA SOLA VEZ durante setup inicial
    2. Almacenarse en un KMS (Key Management Service):
       - AWS KMS
       - HashiCorp Vault
       - Azure Key Vault
       - Google Cloud KMS
    3. NUNCA estar en código fuente o repositorio Git
    4. Tener backups cifrados en ubicación segura
    5. Rotarse periódicamente (ej: cada 90 días)
    
    Returns:
        32 bytes aleatorios criptográficamente seguros
    """
    return os.urandom(32)


def key_to_base64(key: bytes) -> str:
    """
    Convierte clave a formato Base64 para variables de entorno.
    
    Args:
        key: Clave de 32 bytes
    
    Returns:
        String Base64 (ej: "k8jD3mP9qR2sT5vW8xZ1aB4cE6fG9hJ0")
    
    Ejemplo de uso:
        >>> key = generate_master_key()
        >>> key_b64 = key_to_base64(key)
        >>> print(f"export MASTER_ENCRYPTION_KEY='{key_b64}'")
    """
    return base64.b64encode(key).decode('ascii')


def key_from_base64(key_b64: str) -> bytes:
    """
    Convierte clave desde Base64 a bytes.
    
    Args:
        key_b64: String Base64
    
    Returns:
        32 bytes
    
    Raises:
        ValueError: Si el Base64 no decodifica a exactamente 32 bytes
    """
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError(
            f"La clave decodificada debe ser de 32 bytes, "
            f"recibida: {len(key)} bytes"
        )
    return key


# Script de generación (ejecutar una vez)
if __name__ == '__main__':
    print("=== Generador de Clave Maestra ===\n")
    
    key = generate_master_key()
    key_b64 = key_to_base64(key)
    
    print("✅ Clave generada exitosamente\n")
    print("Agrega esta línea a tu archivo .env:")
    print(f"MASTER_ENCRYPTION_KEY={key_b64}\n")
    print("⚠️  ADVERTENCIAS:")
    print("   - Guarda esta clave en un lugar SEGURO")
    print("   - NUNCA la subas a Git o repositorios públicos")
    print("   - En producción, usa un KMS (AWS KMS, Vault, etc.)")
    print("   - Si pierdes esta clave, NO podrás descifrar secretos existentes")
