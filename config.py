import os
import secrets

def get_master_key() -> bytes:
    """
    Obtiene clave maestra desde variable de entorno.
    En producción debe venir de un KMS (AWS KMS, HashiCorp Vault, etc.)
    """
    key_b64 = os.environ.get('MASTER_ENCRYPTION_KEY')
    
    if not key_b64:
        if os.environ.get('ENV') == 'production':
            raise RuntimeError("MASTER_ENCRYPTION_KEY no configurada en producción")
        else:
            # Solo para desarrollo: generar clave efímera
            print("⚠️  WARNING: Usando clave efímera de desarrollo")
            return secrets.token_bytes(32)
    
    # Decodificar desde base64
    import base64
    key = base64.b64decode(key_b64)
    
    if len(key) != 32:
        raise ValueError("La clave debe ser de 256 bits (32 bytes)")
    
    return key
