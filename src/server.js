import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { initDB, saveToken } from "./db.js";

dotenv.config();

const app = express();
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running");
});

// Step 1: Redirect user to Asana Auth Page
app.get("/connect/asana", (req, res) => {
  const authUrl = `https://app.asana.com/-/oauth_authorize?client_id=${process.env.ASANA_CLIENT_ID}&redirect_uri=${encodeURIComponent(process.env.ASANA_REDIRECT_URI)}&response_type=code`;
  res.redirect(authUrl);
});

// Step 2: Handle OAuth Callback + Exchange code for token
app.get("/oauth/callback/asana", async (req, res) => {
  const authCode = req.query.code;
  if (!authCode) return res.status(400).send("Missing authorization code");

  try {
    const response = await fetch("https://app.asana.com/-/oauth_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.ASANA_CLIENT_ID,
        client_secret: process.env.ASANA_CLIENT_SECRET,
        redirect_uri: process.env.ASANA_REDIRECT_URI,
        code: authCode,
      }),
    });

    const tokenData = await response.json();
    if (tokenData.error) return res.status(400).send("Token exchange failed: " + tokenData.error);

    await saveToken(tokenData);

    res.send(`
      <h2>✅ Asana Connected & Token Saved!</h2>
      <p>You can close this window.</p>
    `);
  } catch (err) {
    console.error("OAuth error:", err);
    res.status(500).send("Server error exchanging token.");
  }
});

// Start Server After DB Ready
const port = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
