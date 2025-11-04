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

app.get("/oauth/callback/asana", (req, res) => {
  const authCode = req.query.code;
  if (!authCode) return res.status(400).send("Missing authorization code.");
  res.send("Asana authorization successful! (We will exchange the code next.)");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
