import pytest
from app import app, crypto, db
import jwt

class TestAuthSecurity:
    def test_jwt_none_algorithm_rejected(self):
        """T-001: Verificar rechazo de algoritmo 'none'"""
        payload = {'user_id': 'attacker', 'exp': 9999999999}
        token = jwt.encode(payload, '', algorithm='none')
        
        response = app.test_client().get(
            '/secrets/test',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        assert response.status_code == 401
        assert 'invalid' in response.json['error'].lower()
    
    def test_expired_token_rejected(self):
        """T-015: Tokens expirados deben ser rechazados"""
        token = create_expired_token('user123')
        
        response = app.test_client().get(
            '/secrets/test',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        assert response.status_code == 401
        assert 'expired' in response.json['error'].lower()

class TestCryptoSecurity:
    def test_unique_nonces(self):
        """T-008: Verificar nonces únicos en operaciones múltiples"""
        nonces = set()
        plaintext = "test_secret"
        
        for _ in range(10000):
            result = crypto.encrypt(plaintext)
            nonce = result['nonce']
            
            # Verificar que nonce es único
            assert nonce not in nonces, "Nonce reutilizado detectado"
            nonces.add(nonce)
    
    def test_tampering_detection(self):
        """T-007: GCM debe detectar modificaciones"""
        plaintext = "original_secret"
        encrypted = crypto.encrypt(plaintext)
        
        # Modificar un byte del ciphertext
        tampered = bytearray(encrypted['ciphertext'])
        tampered[0] ^= 0xFF  # Flip bits
        
        with pytest.raises(crypto.InvalidTag):
            crypto.decrypt(bytes(tampered), encrypted['nonce'])

class TestInputValidation:
    def test_sql_injection_attempts(self):
        """T-011: SQL injection debe ser bloqueado"""
        payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE secrets--",
            "1' UNION SELECT * FROM users--"
        ]
        
        token = get_valid_token()
        
        for payload in payloads:
            response = app.test_client().get(
                f'/secrets/{payload}',
                headers={'Authorization': f'Bearer {token}'}
            )
            
            # Debe retornar 404 (no encontrado), no 500 (error SQL)
            assert response.status_code == 404

class TestLoggingSecurity:
    def test_secrets_not_in_logs(self, caplog):
        """T-004: Secretos no deben aparecer en logs"""
        secret_value = "super_secret_api_key_12345"
        
        with caplog.at_level(logging.INFO):
            app.test_client().post('/secrets', json={
                'secret': secret_value
            }, headers={'Authorization': f'Bearer {get_valid_token()}'})
        
        # Verificar que el secreto NO aparece en ningún log
        for record in caplog.records:
            assert secret_value not in record.message
            assert '[REDACTED]' in record.message or secret_value not in record.getMessage()

class TestRateLimiting:
    def test_rate_limiting(self):
        """T-005: Rate limiting debe bloquear exceso de requests"""
        token = get_valid_token()
        
        # Enviar 150 requests (límite: 100/min)
        responses = []
        for _ in range(150):
            resp = app.test_client().get(
                '/secrets',
                headers={'Authorization': f'Bearer {token}'}
            )
            responses.append(resp.status_code)
        
        # Al menos algunas deben ser bloqueadas (429)
        assert 429 in responses
        assert responses.count(429) >= 50
