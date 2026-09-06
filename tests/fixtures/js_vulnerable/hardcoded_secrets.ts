// VIGILO-JS-005: Hardcoded Secrets

export const AWS_CONFIG = {
  // Finding 1: Real AWS Access Key ID pattern
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  region: 'us-east-1',
};

// Finding 2: Sensitive Variable Assignment
export const API_KEY = 'custom_secret_key_production_val_987654321';

// Finding 3: JWT Token
export const JWT_AUTH_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZVNlY3VyZSJ9.c2VjdXJlX3NpZ25hdHVyZV9leGFtcGxlX3ZpZ2lsb190ZXN0';

// Finding 4: Database Connection URI with embedded credentials
export const DB_URI = 'postgres://admin:SuperSecretPass123!@db.production.internal:5432/appdb';
