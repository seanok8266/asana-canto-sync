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

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
