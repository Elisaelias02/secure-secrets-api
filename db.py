import sqlite3
from typing import Optional

class SecretsDB:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()
    
    def insert_secret(self, user_id: str, ciphertext: bytes, nonce: bytes) -> str:
        """
        Inserta secreto usando consultas parametrizadas.
        NUNCA construye queries con f-strings o concatenación.
        """
        secret_id = secrets.token_urlsafe(16)
        
        # ✅ CORRECTO: Parámetros vinculados
        query = """
            INSERT INTO secrets (secret_id, user_id, ciphertext, nonce, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
        """
        
        self.conn.execute(query, (secret_id, user_id, ciphertext, nonce))
        self.conn.commit()
        
        return secret_id
    
    def get_secret(self, secret_id: str, user_id: str) -> Optional[dict]:
        """
        Recupera secreto validando ownership.
        """
        # ✅ CORRECTO: WHERE con parámetros
        query = """
            SELECT ciphertext, nonce, created_at 
            FROM secrets 
            WHERE secret_id = ? AND user_id = ?
        """
        
        cursor = self.conn.execute(query, (secret_id, user_id))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return {
            'ciphertext': row['ciphertext'],
            'nonce': row['nonce'],
            'created_at': row['created_at']
        }
