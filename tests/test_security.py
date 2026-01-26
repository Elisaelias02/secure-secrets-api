"""Tests de seguridad - Validación de mitigaciones del Threat Model"""

import pytest
from src.app import app
from src.crypto import SecretsCrypto
from src.auth import create_token
import jwt
import os

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwt_none_algorithm_rejected(client):
    """T-001: Rechazar algoritmo 'none' en JWT"""
    payload = {'user_id': 'attacker', 'exp': 9999999999}
    fake_token = jwt.encode(payload, '', algorithm='none')
    
    response = client.get(
        '/secrets/test',
        headers={'Authorization': f'Bearer {fake_token}'}
    )
    
    assert response.status_code == 401

def test_unique_nonces():
    """T-008: Verificar nonces únicos en 1000 operaciones"""
    key = os.urandom(32)
    crypto = SecretsCrypto(key)
    
    nonces = set()
    for _ in range(1000):
        result = crypto.encrypt("test")
        assert result['nonce'] not in nonces
        nonces.add(result['nonce'])

def test_tampering_detection():
    """T-007: GCM debe detectar modificación del ciphertext"""
    key = os.urandom(32)
    crypto = SecretsCrypto(key)
    
    encrypted = crypto.encrypt("original")
    
    # Modificar un byte
    tampered = bytearray(encrypted['ciphertext'])
    tampered[0] ^= 0xFF
    
    with pytest.raises(ValueError, match="integridad"):
        crypto.decrypt(bytes(tampered), encrypted['nonce'])

def test_sql_injection_blocked(client):
    """T-011: SQL injection debe ser bloqueado por queries parametrizadas"""
    token = create_token('user123')
    
    payloads = ["1' OR '1'='1", "1; DROP TABLE secrets--"]
    
    for payload in payloads:
        response = client.get(
            f'/secrets/{payload}',
            headers={'Authorization': f'Bearer {token}'}
        )
        # Debe retornar 404, no 500 (error SQL)
        assert response.status_code == 404

def test_ownership_validation(client):
    """T-006: Usuario no debe acceder a secretos de otros"""
    token1 = create_token('user_1')
    token2 = create_token('user_2')
    
    # User 1 crea secreto
    resp = client.post(
        '/secrets',
        json={'secret': 'confidential'},
        headers={'Authorization': f'Bearer {token1}'}
    )
    secret_id = resp.json['secret_id']
    
    # User 2 intenta acceder
    resp = client.get(
        f'/secrets/{secret_id}',
        headers={'Authorization': f'Bearer {token2}'}
    )
    
    assert resp.status_code == 404

def test_rate_limiting(client):
    """T-005: Rate limit debe bloquear exceso de requests"""
    token = create_token('user123')
    
    # Enviar 15 requests (límite: 10/min en /auth/token)
    responses = []
    for _ in range(15):
        resp = client.post('/auth/token', json={'user_id': 'test'})
        responses.append(resp.status_code)
    
    # Algunas deben ser 429
    assert 429 in responses
