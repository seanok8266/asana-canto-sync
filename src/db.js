import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Initialize table
export async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tokens (
      service TEXT PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      expires_in INTEGER,
      token_type TEXT
    );
  `);
}

// Save token for a service ("asana" or "canto")
export async function saveToken(service, tokenData) {
  await pool.query(
    `
      INSERT INTO tokens (service, access_token, refresh_token, expires_in, token_type)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (service) DO UPDATE SET
        access_token = EXCLUDED.access_token,
        refresh_token = EXCLUDED.refresh_token,
        expires_in = EXCLUDED.expires_in,
        token_type = EXCLUDED.token_type;
    `,
    [
      service,
      tokenData.access_token,
      tokenData.refresh_token,
      tokenData.expires_in || null,
      tokenData.token_type || "bearer",
    ]
  );
}

// ✅ This is what server.js needs
export async function getToken(service) {
  const result = await pool.query(
    `
    SELECT 
      service,
      access_token,
      refresh_token,
      expires_in,
      token_type,
      domain,
      mapping,
      expires_at
    FROM tokens 
    WHERE service = $1 
    LIMIT 1
    `,
    [service]
  );
  return result.rows[0] || null;
}

