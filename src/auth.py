"""Módulo de autenticación JWT"""

import jwt
from datetime import datetime, timedelta
import os
from functools import wraps
from flask import request, jsonify
import time

JWT_SECRET = os.environ.get('JWT_SECRET', 'INSECURE_DEV_SECRET')
JWT_ALGORITHM = 'HS256'

# Rate limiting simple en memoria
request_counts = {}

class AuthenticationError(Exception):
    pass

def create_token(user_id: str) -> str:
    """
    Genera JWT con expiración.
    
    Threat Model:
    - T-001: Algoritmo HS256 (no 'none')
    - T-015: Expiración de 1 hora
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    """
    Valida JWT.
    
    Threat Model:
    - T-001: Whitelist de algoritmos
    """
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],  # No permite 'none'
            options={'verify_signature': True, 'verify_exp': True}
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token expirado")
    except jwt.InvalidTokenError:
        raise AuthenticationError("Token inválido")

def require_auth(f):
    """Decorador para proteger endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization')
        
        if not auth or not auth.startswith('Bearer '):
            return jsonify({'error': 'Token requerido'}), 401
        
        token = auth.split(' ')[1]
        
        try:
            payload = verify_token(token)
            request.user_id = payload['user_id']
            return f(*args, **kwargs)
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 401
    
    return decorated

def rate_limit(max_requests: int, window_minutes: int):
    """
    Rate limiting simple.
    
    Threat Model:
    - T-005: DoS prevention
    - T-014: Credential stuffing mitigation
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            identifier = request.remote_addr
            current_time = time.time()
            
            if identifier not in request_counts:
                request_counts[identifier] = []
            
            # Limpiar requests antiguos
            window = window_minutes * 60
            request_counts[identifier] = [
                t for t in request_counts[identifier]
                if current_time - t < window
            ]
            
            if len(request_counts[identifier]) >= max_requests:
                return jsonify({'error': 'Rate limit excedido'}), 429
            
            request_counts[identifier].append(current_time)
            return f(*args, **kwargs)
        
        return decorated
    return decorator
