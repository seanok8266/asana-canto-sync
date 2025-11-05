import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { initDB, saveToken } from "./db.js";

dotenv.config();
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// -------------------------
// Home Route
// -------------------------
app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running");
});


// =========================
// ASANA AUTH FLOW
// =========================
app.get("/connect/asana", (req, res) => {
  const authUrl = `https://app.asana.com/-/oauth_authorize?client_id=${process.env.ASANA_CLIENT_ID}&redirect_uri=${encodeURIComponent(
    process.env.ASANA_REDIRECT_URI
  )}&response_type=code`;
  res.redirect(authUrl);
});

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
    if (tokenData.error)
      return res.status(400).send("Token exchange failed: " + tokenData.error);

    await saveToken("asana", tokenData);
    res.send(`<h2>✅ Asana Connected & Token Saved!</h2>`);
  } catch (err) {
    console.error("OAuth error:", err);
    res.status(500).send("Server error exchanging token.");
  }
});


// =========================
// ✅ MULTI-TENANT CANTO FLOW
// =========================

// Step 1: Ask user for their specific Canto domain
app.get("/connect/canto", (req, res) => {
  res.send(`
    <h1>Connect to Canto</h1>
    <form action="/connect/canto/start" method="POST">
      <label>Enter your Canto domain:</label><br><br>
      <input type="text" name="domain" placeholder="example.canto.com" required style="width:300px;"><br><br>
      <button type="submit">Continue</button>
    </form>
  `);
});

// Step 2: Redirect to *tenant-specific* OAuth authorize endpoint
app.post("/connect/canto/start", (req, res) => {
  const userDomain = req.body.domain.trim(); // e.g., thedamconsultants.canto.com

  const authUrl =
    `https://${userDomain}/oauth/authorize?` +
    new URLSearchParams({
      client_id: process.env.CANTO_CLIENT_ID,
      redirect_uri: process.env.CANTO_REDIRECT_URI,
      response_type: "code",
      scope: "openapi",
    });

  res.redirect(authUrl);
});

// Step 3: OAuth callback → exchange token (also tenant-specific)
app.get("/oauth/callback/canto", async (req, res) => {
  const authCode = req.query.code;

  // We retrieve the original tenant domain from the redirect URI query parameter
  // Canto appends ?state=domain if we use state — so let's do that
  const userDomain = req.query.state;
  if (!authCode || !userDomain)
    return res.status(400).send("Missing authorization code or domain");

  try {
    const response = await fetch(`https://${userDomain}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.CANTO_CLIENT_ID,
        client_secret: process.env.CANTO_CLIENT_SECRET,
        redirect_uri: process.env.CANTO_REDIRECT_URI,
        code: authCode,
      }),
    });

    const tokenData = await response.json();
    if (tokenData.error)
      return res.status(400).send("Token exchange failed: " + tokenData.error);

    tokenData.domain = userDomain; // ✅ store the tenant domain for future API calls
    await saveToken("canto", tokenData);

    res.send(`<h2>✅ Canto Connected for <strong>${userDomain}</strong>!</h2>`);
  } catch (err) {
    console.error("Canto OAuth error:", err);
    res.status(500).send("Server error exchanging Canto token.");
  }
});


// -------------------------
// Start Server
// -------------------------
const port = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
