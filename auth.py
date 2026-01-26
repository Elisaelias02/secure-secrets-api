import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
ALGORITHM = 'HS256'  # No permitir 'none' algorithm

def create_token(user_id: str) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow(),
        'iss': 'secure-secrets-api'
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        # Validación estricta de algoritmo
        payload = jwt.decode(
            token, 
            SECRET_KEY, 
            algorithms=[ALGORITHM],  # Whitelist explícita
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'require': ['exp', 'iat', 'user_id']
            }
        )
        return payload
    except jwt.InvalidTokenError as e:
        raise AuthenticationError(f"Token inválido: {e}")
