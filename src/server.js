import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { initDB, saveToken, getToken } from "./db.js"; // make sure getToken is imported too!

dotenv.config();

// ✅ Initialize app FIRST
const app = express();

// ✅ Then use middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


// -------------------------
// Home Route
// -------------------------
app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running");
});


// =========================
// 🟣 ASANA AUTH FLOW
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
    // 1️⃣ Exchange code for token
    const tokenResponse = await fetch("https://app.asana.com/-/oauth_token", {
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

    const tokenData = await tokenResponse.json();
    if (tokenData.error)
      return res.status(400).send("Token exchange failed: " + tokenData.error);

    await saveToken("asana", tokenData);
// ✅ Automatically re-register stored webhooks for existing projects
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
              "Authorization": `Bearer ${tokenData.access_token}`,
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
          console.error(`❌ Failed webhook re-registration for project ${projectId}:`, innerErr);
        }
      }
    }
  } catch (err) {
    console.error("Error during webhook auto-re-registration:", err);
  }
}

    // 2️⃣ Fetch all projects
    const projectResponse = await fetch("https://app.asana.com/api/1.0/projects", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const projectList = await projectResponse.json();
    if (!projectList.data?.length) {
      return res.send(`<h2>✅ Asana Connected, but no projects found.</h2>`);
    }

    // 3️⃣ Show project selection form
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

app.post("/register/asana-webhooks", express.urlencoded({ extended: true }), async (req, res) => {
  // 🧩 Normalize and sanitize project IDs
  let projectIds = req.body.projectIds;
  if (!Array.isArray(projectIds)) {
    projectIds = [projectIds];
  }
  projectIds = projectIds.filter(Boolean);

  if (!projectIds?.length) {
    return res.status(400).send("No projects selected.");
  }

  try {
    const tokenRecord = await getToken("asana");
    if (!tokenRecord || !tokenRecord.access_token) {
      return res.status(400).send("Asana token not found. Please reconnect.");
    }

    const results = [];
    const successfulProjects = [];

    console.log("🔍 Project IDs received from form:", projectIds);

    // 🔁 Loop through each selected project
    for (const projectId of projectIds) {
      console.log("🔧 Registering webhook for:", projectId);

      const response = await fetch("https://app.asana.com/api/1.0/webhooks", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tokenRecord.access_token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          resource: projectId.toString(), // ✅ Ensure string type
          target: "https://asana-canto-sync.onrender.com/webhook/asana", // ✅ Explicit URL
        }),
      });

      const data = await response.json();
      console.log("📡 Asana webhook response:", data);

      const success = !data.errors;
      results.push({
        projectId,
        success,
        message: success
          ? "Webhook registered successfully."
          : JSON.stringify(data.errors),
      });

      if (success) successfulProjects.push(projectId);
    }

    // 🧠 Store successfully registered project IDs in DB (optional, for persistence)
    if (successfulProjects.length) {
      console.log("💾 Successfully registered webhooks for:", successfulProjects);
    }

    // ✅ Display results to user
    res.send(`
      <h2>🪝 Webhook Setup Complete</h2>
      <ul>
        ${results
          .map(
            (r) =>
              `<li><strong>${r.projectId}</strong>: ${
                r.success ? "✅ Success" : "❌ Failed"
              } — ${r.message}</li>`
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




// =========================
// 🧠 DYNAMIC ASANA WEBHOOK REGISTRATION
// =========================
app.post("/register/asana-webhook", async (req, res) => {
  const { projectId } = req.body;

  try {
    const tokenRecord = await getToken("asana");
    if (!tokenRecord || !tokenRecord.access_token) {
      return res.status(400).send("Asana token not found. Please connect Asana first.");
    }

    const response = await fetch("https://app.asana.com/api/1.0/webhooks", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${tokenRecord.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        resource: projectId,
        target: "https://asana-canto-sync.onrender.com/webhook/asana",
      }),
    });

    const data = await response.json();
    console.log("🪝 Webhook registration response:", data);

    if (data.errors) {
      return res.status(400).send("Failed to create webhook: " + JSON.stringify(data.errors));
    }

    res.send(`<h3>✅ Webhook registered for project ${projectId}</h3>`);
  } catch (err) {
    console.error("Webhook registration error:", err);
    res.status(500).send("Server error registering webhook.");
  }
});

// =========================
// 📋 LIST ASANA PROJECTS (for multi-tenant selection)
// =========================
app.get("/list/asana-projects", async (req, res) => {
  try {
    const tokenRecord = await getToken("asana");
    if (!tokenRecord || !tokenRecord.access_token) {
      return res.status(400).send("Asana token not found. Please connect Asana first.");
    }

    const response = await fetch("https://app.asana.com/api/1.0/projects", {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${tokenRecord.access_token}`,
      },
    });

    const data = await response.json();
    if (data.errors) {
      console.error("❌ Asana API error:", data.errors);
      return res.status(400).send("Error fetching projects: " + JSON.stringify(data.errors));
    }

    const projects = data.data.map((p) => ({
      id: p.gid,
      name: p.name,
    }));

    console.log("📋 Projects fetched:", projects);

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


// =========================
// ✅ CANTO OAUTH2 (COMPATIBLE ENDPOINT)
// =========================

// Step 1: Show domain entry UI
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

// Step 2: Redirect user to Canto OAuth2 (compatible endpoint)
app.post("/connect/canto/start", (req, res) => {
  const authUrl =
    "https://oauth.canto.com/oauth/api/oauth2/compatible/authorize?" +
    new URLSearchParams({
      response_type: "code",
      app_id: process.env.CANTO_CLIENT_ID, // Canto uses `app_id` instead of `client_id`
      redirect_uri: process.env.CANTO_REDIRECT_URI,
    });

  console.log("Redirecting user to:", authUrl);
  res.redirect(authUrl);
});

// Step 3: Canto Callback → Exchange Code for Token
app.get("/oauth/callback/canto", async (req, res) => {
  console.log("🎯 Callback hit with query:", req.query);

  const authCode = req.query.code;
  if (!authCode) return res.status(400).send("Missing authorization code");

  try {
    const tokenUrl = "https://oauth.canto.com/oauth/api/oauth2/compatible/token";

    const response = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        app_id: process.env.CANTO_CLIENT_ID,
        app_secret: process.env.CANTO_CLIENT_SECRET,
        redirect_uri: process.env.CANTO_REDIRECT_URI,
        code: authCode,
      }),
    });

    const tokenData = await response.json();
    console.log("🔐 Token exchange response:", tokenData);

    if (tokenData.error)
      return res.status(400).send("Token exchange failed: " + tokenData.error_description || tokenData.error);

    await saveToken("canto", tokenData);

    res.send(`<h2>✅ Canto Connected & Token Saved!</h2>
              <p>You can close this window.</p>`);
  } catch (err) {
    console.error("Canto OAuth error:", err);
    res.status(500).send("Server error exchanging Canto token.");
  }
});

// =========================
// 🔔 ASANA WEBHOOK HANDLER
// =========================
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


// =========================
// 🚀 START SERVER
// =========================
const port = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
