# Secure Secrets API - Threat Model Demo

API para demostrar threat modeling con STRIDE.

## ¿Qué hace?
- Almacena secretos cifrados (AES-256-GCM)
- Autenticación con JWT
- 3 endpoints: crear, leer, eliminar secretos

## ⚠️ Propósito Educativo
Este proyecto NO es production-ready. Su objetivo es:
1. Documentar amenazas usando STRIDE
2. Implementar mitigaciones básicas
3. Servir como ejercicio de análisis de seguridad

## ¿Como Empezar?
```bash
# Instalar dependencias
pip install -r requirements.txt

# Generar clave de cifrado
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Copiar output a .env como MASTER_KEY

# Ejecutar
python src/app.py

# Probar
curl -X POST http://localhost:5000/secrets \
  -H "Content-Type: application/json" \
  -d '{"secret": "mi_api_key_123"}'
```

## 📚 Stack Técnico
- Python 3.10+
- Flask (web framework)
- cryptography (AES-GCM)
- PyJWT (autenticación)
- SQLite (storage)

---

**Autor**: Elisa - AEGIS | H4ck The World  
**Curso**: Ciberseguridad Avanzada para Desarrolladores
