import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running");
});

app.get("/connect/asana", (req, res) => {
  const clientId = process.env.ASANA_CLIENT_ID;
  const redirectUri = process.env.ASANA_REDIRECT_URI;

  const authUrl = `https://app.asana.com/-/oauth_authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(
    redirectUri
  )}&response_type=code`;

  res.redirect(authUrl);
});

import fetch from "node-fetch"; // add this at the top if not already present

app.get("/oauth/callback/asana", async (req, res) => {
  const authCode = req.query.code;

  if (!authCode) {
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
        code: authCode,
      }),
    });

    const tokenData = await response.json();

    if (tokenData.error) {
      return res.status(400).send("Token exchange failed: " + tokenData.error);
    }

    // ✅ For now, show the access token (temporary). We will store it next.
    res.send(`
      <h2>✅ Asana Connected!</h2>
      <p>Access Token:</p>
      <pre>${JSON.stringify(tokenData, null, 2)}</pre>
      <p><strong>Copy this token — we will save it to your database next.</strong></p>
    `);

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error exchanging token.");
  }
});


const port = process.env.PORT || 3000;
import { initDB } from "./db.js";

initDB().then(() => {
  app.listen(port, () => console.log(`Server running on port ${port}`));
});
