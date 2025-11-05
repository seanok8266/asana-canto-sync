import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { initDB, saveToken, getToken } from "./db.js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Optional in-memory cache (dev convenience)
const cantoTokens = {};

// -------------------------
// Home
// -------------------------
app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running");
});

/* ========================
   ASANA AUTH FLOW
======================== */
app.get("/connect/asana", (req, res) => {
  const authUrl =
    `https://app.asana.com/-/oauth_authorize?client_id=${process.env.ASANA_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.ASANA_REDIRECT_URI)}` +
    `&response_type=code`;
  res.redirect(authUrl);
});

app.get("/oauth/callback/asana", async (req, res) => {
  const authCode = req.query.code;
  if (!authCode) return res.status(400).send("Missing authorization code");

  try {
    
    const tokenResponse = await fetch("https://oauth.canto.com/oauth/api/oauth2/compatible/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://asana-canto-sync.onrender.com/oauth/callback/canto",
    app_id: process.env.CANTO_APP_ID,
    app_secret: process.env.CANTO_APP_SECRET,
  }),
});

    const tokenData = await tokenResponse.json();
    if (tokenData.error) return res.status(400).send("Token exchange failed: " + tokenData.error);

    await saveToken("asana", tokenData);

    // Re-register any stored webhooks (safe no-op if none)
    if (tokenData.access_token && tokenData.refresh_token) {
      try {
        const storedToken = await getToken("asana");
        if (storedToken?.asana_projects?.length) {
          console.log("🔁 Re-registering webhooks for projects:", storedToken.asana_projects);
          for (const projectId of storedToken.asana_projects) {
            try {
              const reReg = await fetch("https://app.asana.com/api/1.0/webhooks", {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${tokenData.access_token}`,
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  resource: projectId,
                  target: `${process.env.APP_BASE_URL}/webhook/asana`,
                }),
              });
              const reRegData = await reReg.json();
              if (reRegData.errors) {
                console.error(`⚠️ Webhook re-registration failed for ${projectId}:`, reRegData.errors);
              } else {
                console.log(`✅ Webhook re-registered for project ${projectId}`);
              }
            } catch (innerErr) {
              console.error(`❌ Failed webhook re-registration for ${projectId}:`, innerErr);
            }
          }
        }
      } catch (err) {
        console.error("Error during webhook auto-re-registration:", err);
      }
    }

    // Fetch projects for simple UI
    const projectResponse = await fetch("https://app.asana.com/api/1.0/projects", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const projectList = await projectResponse.json();
    if (!projectList.data?.length) return res.send("<h2>✅ Asana Connected, but no projects found.</h2>");

    res.send(`
      <h2>✅ Asana Connected!</h2>
      <h3>Select one or more projects to activate webhooks:</h3>
      <form action="/register/asana-webhooks" method="POST">
        ${projectList.data
          .map(
            (p) => `
          <label>
            <input type="checkbox" name="projectIds" value="${p.gid}">
            ${p.name} (ID: ${p.gid})
          </label><br>`
          )
          .join("")}
        <br>
        <button type="submit">Activate Webhooks</button>
      </form>
    `);
  } catch (err) {
    console.error("OAuth error:", err);
    res.status(500).send("Server error exchanging token.");
  }
});

app.post("/register/asana-webhooks", async (req, res) => {
  let projectIds = req.body.projectIds;
  if (!Array.isArray(projectIds)) projectIds = [projectIds];
  projectIds = projectIds.filter(Boolean);
  if (!projectIds?.length) return res.status(400).send("No projects selected.");

  try {
    const tokenRecord = await getToken("asana");
    if (!tokenRecord?.access_token) return res.status(400).send("Asana token not found. Please reconnect.");

    const results = [];
    const successfulProjects = [];

    for (const projectId of projectIds) {
      const response = await fetch("https://app.asana.com/api/1.0/webhooks", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tokenRecord.access_token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          resource: projectId.toString(),
          target: `${process.env.APP_BASE_URL}/webhook/asana`,
        }),
      });

      const data = await response.json();
      const success = !data.errors;
      results.push({ projectId, success, message: success ? "Webhook registered successfully." : JSON.stringify(data.errors) });
      if (success) successfulProjects.push(projectId);
    }

    if (successfulProjects.length) console.log("💾 Successfully registered webhooks for:", successfulProjects);

    res.send(`
      <h2>🪝 Webhook Setup Complete</h2>
      <ul>
        ${results
          .map(
            (r) =>
              `<li><strong>${r.projectId}</strong>: ${r.success ? "✅ Success" : "❌ Failed"} — ${r.message}</li>`
          )
          .join("")}
      </ul>
      <p>These projects are now stored and will auto-register on reconnect.</p>
    `);
  } catch (err) {
    console.error("Webhook registration error:", err);
    res.status(500).send("Server error registering webhooks.");
  }
});

app.post("/register/asana-webhook", async (req, res) => {
  const { projectId } = req.body;
  try {
    const tokenRecord = await getToken("asana");
    if (!tokenRecord?.access_token) return res.status(400).send("Asana token not found. Please connect Asana first.");

    const response = await fetch("https://app.asana.com/api/1.0/webhooks", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenRecord.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        resource: projectId,
        target: `${process.env.APP_BASE_URL}/webhook/asana`,
      }),
    });

    const data = await response.json();
    if (data.errors) return res.status(400).send("Failed to create webhook: " + JSON.stringify(data.errors));

    res.send(`<h3>✅ Webhook registered for project ${projectId}</h3>`);
  } catch (err) {
    console.error("Webhook registration error:", err);
    res.status(500).send("Server error registering webhook.");
  }
});

app.get("/list/asana-projects", async (req, res) => {
  try {
    const tokenRecord = await getToken("asana");
    if (!tokenRecord?.access_token) return res.status(400).send("Asana token not found. Please connect Asana first.");

    const response = await fetch("https://app.asana.com/api/1.0/projects", {
      method: "GET",
      headers: { Authorization: `Bearer ${tokenRecord.access_token}` },
    });

    const data = await response.json();
    if (data.errors) return res.status(400).send("Error fetching projects: " + JSON.stringify(data.errors));

    const projects = data.data.map((p) => ({ id: p.gid, name: p.name }));
    res.send(`
      <h2>🗂️ Your Asana Projects</h2>
      <ul>
        ${projects.map((p) => `<li>${p.name} (ID: ${p.id})</li>`).join("")}
      </ul>
      <p>Use one of these IDs when registering a webhook via POST /register/asana-webhook</p>
    `);
  } catch (err) {
    console.error("Error listing projects:", err);
    res.status(500).send("Server error fetching Asana projects.");
  }
});

/* ========================
   CANTO OAUTH (COMPATIBLE)
======================== */

// Step 1: simple domain form
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

// Step 2: redirect to Canto authorize
app.post("/connect/canto/start", (req, res) => {
  const userDomain = String(req.body.domain || "")
    .trim()
    .replace(/^https?:\/\//, "");
  console.log("🌍 Starting Canto OAuth for domain:", userDomain);

  const authUrl =
    "https://oauth.canto.com/oauth/api/oauth2/compatible/authorize?" +
    new URLSearchParams({
      response_type: "code",
      app_id: process.env.CANTO_APP_ID,              // <— standardized
      redirect_uri: process.env.CANTO_REDIRECT_URI,  // <— standardized
      state: userDomain,                              // carry tenant domain
    });

  res.redirect(authUrl);
});

// Step 3: callback — exchange code for token (SINGLE VERSION)
app.get("/oauth/callback/canto", async (req, res) => {
  const { code, state } = req.query; // state = user's Canto domain (e.g. acme.canto.com)
  console.log("🎯 Callback hit with query:", req.query);

  if (!code || !state) {
    return res.status(400).send("Missing authorization code or domain");
  }

  try {
    const tokenUrl = "https://oauth.canto.com/oauth/api/oauth2/compatible/token";
    console.log("🧩 Exchanging token at:", tokenUrl);

    // ✅ ADD THIS: log exactly what envs we’re sending (mask secret)
    console.log("🪪 Using Canto creds + redirect:", {
      app_id: process.env.CANTO_APP_ID,
      app_secret: process.env.CANTO_APP_SECRET ? "****" : "(missing)",
      redirect_uri: process.env.CANTO_REDIRECT_URI,
      state, // tenant domain
    });

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        app_id: process.env.CANTO_APP_ID,
        app_secret: process.env.CANTO_APP_SECRET,
        redirect_uri: process.env.CANTO_REDIRECT_URI, // must EXACT-match the app’s registered redirect
        code, // from req.query
      }),
    });

    const raw = await response.text();
    console.log("🔍 Raw token response:", raw);

    let tokenData;
    try {
      tokenData = JSON.parse(raw);
    } catch {
      return res.status(400).send("Canto token response was not JSON — check credentials or domain.");
    }

    if (tokenData.error) {
      return res.status(400).send("Token exchange failed: " + (tokenData.error_description || tokenData.error));
    }

    tokenData.domain = state;
    await saveToken(state, tokenData);

    console.log("🌍 Saved token for domain:", state);
    res.send(`<h2>✅ Canto Connected for <strong>${state}</strong>!</h2><p>You can close this window.</p>`);
  } catch (err) {
    console.error("Canto OAuth error:", err);
    res.status(500).send("Server error exchanging Canto token.");
  }
});



/* ========================
   UPLOAD TO CANTO
======================== */

app.post("/upload", async (req, res) => {
  const { attachmentUrl, domain, folder = "asana-sync" } = req.body;

  if (!domain) return res.status(400).json({ error: "Missing domain" });
  if (!attachmentUrl) return res.status(400).json({ error: "Missing attachmentUrl" });

  // DB first, fallback to memory
  let tokenData = await getToken(domain);
  if (!tokenData) tokenData = cantoTokens[domain];

  if (!tokenData?.access_token || !tokenData?.domain) {
    console.error("❌ No valid token found for domain:", domain);
    return res.status(400).json({ error: "Canto token not found or invalid for this domain" });
  }

  const uploadUrl = `https://${tokenData.domain}/api/v1/upload`;
  console.log("📤 Uploading to:", uploadUrl);
  console.log("🔑 Using token (first 10 chars):", tokenData.access_token.slice(0, 10));

  try {
    // If your Canto expects a URL-based upload:
    const response = await fetch(uploadUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: attachmentUrl, folder }),
    });

    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    if (!response.ok) {
      console.error("Canto upload error payload:", data);
      return res.status(400).json({ error: "Error uploading file to Canto", details: data });
    }

    res.json({ success: true, data });
  } catch (err) {
    console.error("Canto upload error:", err);
    res.status(500).json({ error: "Error uploading file to Canto" });
  }
});

// Simple manual test route (JSON body)
app.post("/test/upload-canto", async (req, res) => {
  try {
    // Parse domain
    const domain = req.body.domain;
    if (!domain) {
      return res.status(400).send("Missing domain field.");
    }

    const tokenRecord = await getToken("canto");
    if (!tokenRecord || !tokenRecord.access_token) {
      return res.status(400).send("Canto token not found. Please reconnect Canto first.");
    }

    const uploadUrl = `https://${domain}/api/v1/upload`;
    console.log("📤 Uploading to:", uploadUrl);
    console.log("🔑 Using token (first 10 chars):", tokenRecord.access_token.slice(0, 10) + "...");

    // Use multer to handle multipart file input
    const busboy = await import("busboy");
    const bb = busboy.default({ headers: req.headers });
    let fileBuffer, fileName;

    req.pipe(bb);

    bb.on("file", (name, file, info) => {
      fileName = info.filename;
      const chunks = [];
      file.on("data", (data) => chunks.push(data));
      file.on("end", () => {
        fileBuffer = Buffer.concat(chunks);
      });
    });

    bb.on("finish", async () => {
      if (!fileBuffer) {
        return res.status(400).send("No file uploaded.");
      }

      // Send to Canto
      const response = await fetch(uploadUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tokenRecord.access_token}`,
        },
        body: fileBuffer,
      });

      const text = await response.text();
      console.log("📩 Raw response from Canto:", text);

      let data;
      try {
        data = JSON.parse(text);
      } catch {
        data = { raw: text };
      }

      if (response.ok) {
        res.json({ success: true, file: fileName, data });
      } else {
        res.status(400).json({ success: false, file: fileName, error: data });
      }
    });
  } catch (err) {
    console.error("Canto upload error:", err);
    res.status(500).send("Error uploading file to Canto.");
  }
});


/* ========================
   ASANA WEBHOOK HANDLER
======================== */
app.post("/webhook/asana", (req, res) => {
  const challenge = req.headers["x-hook-secret"];
  if (challenge) {
    console.log("✅ Asana webhook verified");
    res.setHeader("X-Hook-Secret", challenge);
    return res.status(200).send();
  }
  console.log("📩 Asana webhook event:", JSON.stringify(req.body, null, 2));
  res.status(200).send("OK");
});

/* ========================
   START
======================== */
const port = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
