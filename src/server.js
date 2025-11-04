import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { saveToken } from "./db.js";
import { initDB } from "./db.js";

dotenv.config();

const app = express();
app.use(bodyParser.json());

// Health check route
app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running");
});

// ✅ Step 1: Redirect user to Asana OAuth screen
app.get("/connect/asana", (req, res) => {
  const clientId = process.env.ASANA_CLIENT_ID;
  const redirectUri = process.env.ASANA_REDIRECT_URI;

  const authUrl = `https://app.asana.com/-/oauth_authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(
    redirectUri
  )}&response_type=code`;

  res.redirect(authUrl);
});

// ✅ Step 2: OAuth callback → exchange code → store token in DB
app.get("/oauth/asana/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).send("Missing authorization code.");
  }

  try {
    const response = await fetch("https://app.asana.com/-/oauth_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.ASANA_CLIENT_ID,
        client_secret: process.env.ASANA_CLIENT_SECRET,
        redirect_uri: process.env.ASANA_REDIRECT_URI,
        code
      }),
    });

    const tokenData = await response.json();

    if (tokenData.error) {
      return res.status(400).send("Token exchange failed: " + tokenData.error);
    }

    // ✅ Save token to database
    await saveToken("asana", {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_at: new Date(Date.now() + tokenData.expires_in * 1000)
    });

    res.send("✅ Asana connected and token saved to database!");

  } catch (err) {
    console.error("OAuth error:", err);
    res.status(500).send("Server error exchanging token.");
  }
});

// ✅ Start server after DB is ready
const port = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(port, () => console.log(`Server running on port ${port}`));
});
