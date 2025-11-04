import pgPromise from "pg-promise";

const pgp = pgPromise({});
const db = pgp(process.env.DATABASE_URL);

// Create table if it doesn't exist
export async function initDB() {
  await db.none(`
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      id SERIAL PRIMARY KEY,
      service TEXT NOT NULL,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      expires_at TIMESTAMP
    );
  `);
}

// Save or update token
export async function saveToken(service, { access_token, refresh_token, expires_at }) {
  return db.none(
    `
    INSERT INTO oauth_tokens (service, access_token, refresh_token, expires_at)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (service)
    DO UPDATE SET access_token = $2, refresh_token = $3, expires_at = $4;
  `,
    [service, access_token, refresh_token, expires_at]
  );
}

// Get stored token
export async function getToken(service) {
  return db.oneOrNone(
    `SELECT * FROM oauth_tokens WHERE service = $1`,
    [service]
  );
}

export default db;
