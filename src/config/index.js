require('dotenv').config();

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT, 10) || 3000,
  db: {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_HOST,
    database: process.env.DB_NAME || 'CPC_TRACKING',
    options: {
      encrypt: process.env.DB_ENCRYPT === 'true',
      trustServerCertificate: process.env.DB_TRUST_SERVER_CERT === 'true',
      enableArithAbort: true,
      connectionTimeout: 30000,
      requestTimeout: 30000
    },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
  },
  jwt: {
    secret: requireEnv('JWT_SECRET'),
    expiresIn: '12h'
  },
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10)
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 min default
    max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10)
  }
};

module.exports = config;
