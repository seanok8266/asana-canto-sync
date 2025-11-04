import pkg from "pg";
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

export async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS asana_tokens (
      user_id TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at TIMESTAMP
    );
  `);
  console.log("✅ Database ready");
}

export async function saveToken(tokenData) {
  const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000);

  await pool.query(
    `INSERT INTO asana_tokens (user_id, access_token, refresh_token, expires_at)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (user_id)
     DO UPDATE SET access_token = $2, refresh_token = $3, expires_at = $4`,
    [
      tokenData.data.gid,
      tokenData.access_token,
      tokenData.refresh_token,
      expiresAt
    ]
  );

  console.log("💾 Token saved for user:", tokenData.data.gid);
}

export default pool;
