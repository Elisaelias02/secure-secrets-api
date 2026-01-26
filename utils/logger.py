import re
import logging

class SecureFormatter(logging.Formatter):
    """Sanitiza logs para prevenir exposición de secretos"""
    
    PATTERNS = [
        (r'"secret":\s*"[^"]+"', '"secret": "[REDACTED]"'),
        (r'"password":\s*"[^"]+"', '"password": "[REDACTED]"'),
        (r'Bearer\s+[\w\-\.]+', 'Bearer [REDACTED]'),
        (r'api[_-]?key[\s:=]+[\w\-]+', 'api_key=[REDACTED]'),
        # Detectar patrones de Base64 largos (posibles secretos cifrados)
        (r'[A-Za-z0-9+/]{40,}={0,2}', '[BASE64_REDACTED]')
    ]
    
    def format(self, record):
        message = super().format(record)
        for pattern, replacement in self.PATTERNS:
            message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)
        return message

# Configuración
logger = logging.getLogger('secure_secrets_api')
handler = logging.StreamHandler()
handler.setFormatter(SecureFormatter())
logger.addHandler(handler)
