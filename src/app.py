from flask import Flask, request, jsonify
from crypto import SecretsCrypto, key_from_base64
from auth import create_token, verify_token, require_auth, rate_limit, AuthenticationError
import os
import sqlite3
import secrets
from datetime import datetime

app = Flask(__name__)

# Configuración
MASTER_KEY = key_from_base64(os.environ.get('MASTER_KEY', 'DEMO_KEY_INSECURE'))
crypto = SecretsCrypto(MASTER_KEY)

# Base de datos simple
def get_db():
    conn = sqlite3.connect('secrets.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            secret_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ============================================================================
# ENDPOINTS
# ============================================================================

@app.route('/auth/token', methods=['POST'])
@rate_limit(max_requests=10, window_minutes=1)
def login():
    """
    Genera un JWT token (versión simplificada - sin password real)
    
    Threat Model Coverage:
    - T-001: JWT Spoofing (mitigado con HS256)
    - T-014: Credential Stuffing (rate limiting aplicado)
    """
    data = request.get_json()
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'user_id requerido'}), 400
    
    # En producción: validar username/password contra DB
    token = create_token(user_id)
    
    return jsonify({
        'token': token,
        'expires_in': 3600
    }), 200


@app.route('/secrets', methods=['POST'])
@require_auth
@rate_limit(max_requests=50, window_minutes=1)
def create_secret():
    """
    Crea un secreto cifrado
    
    Threat Model Coverage:
    - T-004: Info Disclosure (logs sanitizados)
    - T-008: IV Reuse (nonce único por operación)
    - T-009: Hardcoded Key (clave desde env var)
    """
    data = request.get_json()
    plaintext = data.get('secret')
    
    if not plaintext:
        return jsonify({'error': 'Campo "secret" requerido'}), 400
    
    if len(plaintext) > 10000:  # 10KB límite
        return jsonify({'error': 'Secreto demasiado grande'}), 400
    
    # Cifrar
    encrypted = crypto.encrypt(plaintext)
    
    # Guardar en DB
    secret_id = secrets.token_urlsafe(16)
    conn = get_db()
    conn.execute(
        'INSERT INTO secrets (secret_id, user_id, ciphertext, nonce, created_at) VALUES (?, ?, ?, ?, ?)',
        (secret_id, request.user_id, encrypted['ciphertext'], encrypted['nonce'], datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()
    
    # Log sanitizado (T-004 mitigation)
    app.logger.info(f"Secreto creado: {secret_id} por user {request.user_id}")
    
    return jsonify({
        'secret_id': secret_id,
        'created_at': datetime.utcnow().isoformat()
    }), 201


@app.route('/secrets/<secret_id>', methods=['GET'])
@require_auth
@rate_limit(max_requests=100, window_minutes=1)
def get_secret(secret_id):
    """
    Recupera un secreto (descifrado)
    
    Threat Model Coverage:
    - T-006: Privilege Escalation (validación de ownership)
    - T-007: Tampering Detection (GCM tag validation)
    - T-011: SQL Injection (query parametrizada)
    """
    conn = get_db()
    
    # Query parametrizada (T-011 mitigation)
    cursor = conn.execute(
        'SELECT ciphertext, nonce FROM secrets WHERE secret_id = ? AND user_id = ?',
        (secret_id, request.user_id)
    )
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'error': 'Secreto no encontrado'}), 404
    
    # Descifrar (T-007: detecta tampering automáticamente)
    try:
        plaintext = crypto.decrypt(row['ciphertext'], row['nonce'])
    except ValueError as e:
        app.logger.error(f"Tampering detectado en secret {secret_id}")
        return jsonify({'error': 'Integridad del secreto comprometida'}), 500
    
    return jsonify({
        'secret_id': secret_id,
        'secret': plaintext
    }), 200


@app.route('/secrets/<secret_id>', methods=['DELETE'])
@require_auth
def delete_secret(secret_id):
    """
    Elimina un secreto
    
    Threat Model Coverage:
    - T-006: Privilege Escalation (validación de ownership)
    """
    conn = get_db()
    cursor = conn.execute(
        'DELETE FROM secrets WHERE secret_id = ? AND user_id = ?',
        (secret_id, request.user_id)
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    
    if not deleted:
        return jsonify({'error': 'Secreto no encontrado'}), 404
    
    return jsonify({'message': 'Secreto eliminado'}), 200


@app.errorhandler(AuthenticationError)
def handle_auth_error(e):
    return jsonify({'error': str(e)}), 401


@app.errorhandler(500)
def handle_error(e):
    # No exponer detalles internos (T-004)
    app.logger.error(f"Error interno: {e}")
    return jsonify({'error': 'Error interno del servidor'}), 500


if __name__ == '__main__':
    print("⚠️  ADVERTENCIA: Este es un proyecto educativo")
    print("   No usar en producción sin revisión de seguridad\n")
    app.run(debug=False, host='127.0.0.1', port=5000)
