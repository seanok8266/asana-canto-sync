/********************************************************************
 *  Asana ↔ Canto Sync Service
 *  ---------------------------------------------------------------
 *  ✅ Fixed Asana OAuth (removes accidental Canto code)
 *  ✅ Correct Canto OAuth + refresh
 *  ✅ Correct Canto upload flow: /uploads → PUT S3 → /files
 *  ✅ Per-domain metadata mapping API (/mapping/:domain)
 *  ✅ Mapping applied on upload
 *  ✅ Works with your DB (saveToken / getToken)
 *  ✅ Keeps all Asana webhook logic
 *  ✅ Includes /dashboard/:domain and /mapping-ui/:domain
 ********************************************************************/

import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import Busboy from "busboy";
import FormData from "form-data";
import { Buffer } from "buffer";
import { initDB, saveToken, getToken } from "./db.js";

dotenv.config();

const app = express();
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true }));

/* ================================================================
   CONSTANTS
================================================================ */
const CANTO_BASE = "https://oauth.canto.com";
const CANTO_AUTH_URL = `${CANTO_BASE}/oauth/api/oauth2/compatible/authorize`;
const CANTO_TOKEN_URL = `${CANTO_BASE}/oauth/api/oauth2/compatible/token`;
const CANTO_UPLOADS_URL = `${CANTO_BASE}/api/v1/uploads`;
const CANTO_FILES_URL = `${CANTO_BASE}/api/v1/files`;

/* ================================================================
   IN-MEMORY TOKEN CACHE (DEVELOPMENT)
================================================================ */
const cantoTokens = {}; // domain → tokenData

/* ================================================================
   HELPERS
================================================================ */
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

async function persistCantoToken(domain, tokenData) {
  tokenData.domain = domain;
  cantoTokens[domain] = tokenData;
  await saveToken(domain, tokenData);
}

async function loadCantoToken(domain) {
  let t = await getToken(domain);
  if (!t) t = cantoTokens[domain];
  return t || null;
}

async function refreshCantoTokenIfNeeded(domain) {
  let td = await loadCantoToken(domain);
  if (!td?.access_token) throw new Error("No Canto token for domain " + domain);

  const now = nowSec();
  if (!td._expires_at && td.expires_in) {
    td._expires_at = now + Number(td.expires_in);
    await persistCantoToken(domain, td);
  }

  if (td._expires_at && td._expires_at - now > 60) return td;

  if (!td.refresh_token) return td;

  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: td.refresh_token,
    app_id: process.env.CANTO_APP_ID,
    app_secret: process.env.CANTO_APP_SECRET,
  });

  const resp = await fetch(CANTO_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });

  const raw = await resp.text();
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error("Canto refresh returned non-JSON");
  }

  if (!resp.ok || data.error) {
    console.error("Canto refresh failed:", data);
    return td;
  }

  data._expires_at = nowSec() + Number(data.expires_in || 3500);
  await persistCantoToken(domain, { ...td, ...data });
  return loadCantoToken(domain);
}

async function cantoCreateUpload(domain, accessToken, { filename, size, mimeType }) {
  console.log("🟦 CANTO CREATE UPLOAD — START");
  console.log("🟦 Using access token:", accessToken ? accessToken.slice(0, 8) + "..." : "(none)");
  console.log("🟦 Payload:", { filename, size, mimeType });

  const payload = { filename, size, mimeType };

  const r = await fetch(CANTO_UPLOADS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const text = await r.text();
  console.log("🟥 RAW /uploads RESPONSE:", text);
  console.log("🟥 HTTP STATUS:", r.status);

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!r.ok) {
    console.error("[CANTO create upload] error:", r.status, data);
    throw new Error("Canto /uploads failed");
  }

  if (!data.uploadId || !data.uploadUrl) {
    console.error("🟥 Missing uploadId or uploadUrl:", data);
    throw new Error("Canto /uploads missing uploadId/uploadUrl");
  }

  console.log("✅ UPLOAD INIT CREATED:", data);
  return data;
}


async function cantoPutToS3(uploadUrl, bytes, mimeType) {
  const r = await fetch(uploadUrl, {
    method: "PUT",
    headers: {
      "Content-Type": mimeType || "application/octet-stream",
      "Content-Length": String(bytes.length),
    },
    body: bytes,
  });

  if (!r.ok) {
    const t = await r.text();
    console.error("[S3 PUT] failed:", r.status, t);
    throw new Error("PUT to signed URL failed");
  }
}

async function cantoFinalizeFile(domain, accessToken, { uploadId, filename, metadata }) {
  const r = await fetch(CANTO_FILES_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ uploadId, filename, metadata }),
  });

  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!r.ok) {
    console.error("[CANTO finalize] error:", r.status, data);
    throw new Error("Canto /files failed");
  }

  return data;
}

function filenameFromUrl(urlStr) {
  try {
    const url = new URL(urlStr);
    const parts = url.pathname.split("/");
    return decodeURIComponent(parts.pop() || `file-${Date.now()}`);
  } catch {
    return `file-${Date.now()}`;
  }
}

/* ================================================================
   FIELD MAPPING HELPERS
================================================================ */
async function getDomainMapping(domain) {
  const tokenRecord = await getToken(domain);
  return tokenRecord?.mapping || {};
}

async function saveDomainMapping(domain, mapping) {
  const tokenRecord = (await getToken(domain)) || {};
  tokenRecord.mapping = mapping;
  await saveToken(domain, tokenRecord);
  return mapping;
}

function applyFieldMapping(mapping, metadata) {
  const out = { ...metadata };
  for (const [asanaField, cantoField] of Object.entries(mapping || {})) {
    if (Object.prototype.hasOwnProperty.call(metadata, asanaField)) {
      out[cantoField] = metadata[asanaField];
    }
  }
  return out;
}

/* ================================================================
   ROUTES
================================================================ */

app.get("/", (req, res) => {
  res.send("Asana ↔ Canto Sync Service Running ✅");
});

/* ---------------------------------------------------------------
   ASANA AUTH FLOW
---------------------------------------------------------------- */
app.get("/connect/asana", (req, res) => {
  const authUrl =
    `https://app.asana.com/-/oauth_authorize?client_id=${process.env.ASANA_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.ASANA_REDIRECT_URI)}` +
    `&response_type=code`;
  res.redirect(authUrl);
});

app.get("/oauth/callback/asana", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Missing authorization code");

  try {
    const tokenResp = await fetch("https://app.asana.com/-/oauth_token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: process.env.ASANA_CLIENT_ID,
        client_secret: process.env.ASANA_CLIENT_SECRET,
        redirect_uri: process.env.ASANA_REDIRECT_URI,
        code,
      }),
    });

    const tokenData = await tokenResp.json();
    if (!tokenResp.ok || tokenData.error) {
      return res
        .status(400)
        .send("Asana token exchange failed: " + JSON.stringify(tokenData));
    }

    await saveToken("asana", tokenData);

    res.send("<h2>✅ Asana Connected!</h2>");
  } catch (err) {
    console.error("Asana OAuth error:", err);
    res.status(500).send("Server error exchanging Asana token.");
  }
});

/* ---------------------------------------------------------------
   PER-DOMAIN MAPPING API
---------------------------------------------------------------- */
app.get("/mapping/:domain", async (req, res) => {
  const { domain } = req.params;
  try {
    const mapping = await getDomainMapping(domain);
    res.json({ domain, mapping });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/mapping/:domain", async (req, res) => {
  const { domain } = req.params;

  if (!req.body || typeof req.body !== "object") {
    return res.status(400).json({ error: "Mapping must be an object." });
  }

  try {
    const updated = await saveDomainMapping(domain, req.body);
    res.json({ domain, mapping: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/mapping/:domain", async (req, res) => {
  const { domain } = req.params;
  try {
    await saveDomainMapping(domain, {});
    res.json({ domain, cleared: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   CANTO OAUTH
---------------------------------------------------------------- */
app.get("/connect/canto", (req, res) => {
  res.send(`
    <h1>Connect to Canto</h1>
    <form action="/connect/canto/start" method="POST">
      <input type="text" name="domain" placeholder="thedamconsultants" required>
      <button type="submit">Connect</button>
    </form>
  `);
});

app.post("/connect/canto/start", (req, res) => {
  const domain = String(req.body.domain || "").trim();
  if (!domain) return res.status(400).send("Missing Canto domain");

  const url =
    `${CANTO_AUTH_URL}?` +
    new URLSearchParams({
      response_type: "code",
      app_id: process.env.CANTO_APP_ID,
      redirect_uri: process.env.CANTO_REDIRECT_URI,
      state: domain,
    });

  res.redirect(url);
});

app.get("/oauth/callback/canto", async (req, res) => {
  console.log("🔥 CALLBACK HIT — raw query:", req.query);
  console.log("🔥 CALLBACK HIT — code:", req.query.code);
  console.log("🔥 CALLBACK HIT — state/domain:", req.query.state);

  console.log("🟦 ENV CHECK — CANTO_APP_ID:", process.env.CANTO_APP_ID);
  console.log("🟦 ENV CHECK — CANTO_APP_SECRET:", process.env.CANTO_APP_SECRET ? "(present)" : "(MISSING)");
  console.log("🟦 ENV CHECK — CANTO_REDIRECT_URI:", process.env.CANTO_REDIRECT_URI);

  console.log("🟦 ABOUT TO CREATE PARAMS");
  console.log("🟦 TOKEN URL BEING USED:", CANTO_TOKEN_URL);

  const { code, state: domain } = req.query;

  if (!code || !domain) {
    return res.status(400).send("Missing authorization code or domain");
  }

  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      app_id: process.env.CANTO_APP_ID,
      app_secret: process.env.CANTO_APP_SECRET,
      redirect_uri: process.env.CANTO_REDIRECT_URI,
    });

    // ✅ ADD THESE 2 LINES
    console.log("🟩 PARAMS CREATED:", params.toString());
    console.log("🔗 POSTING TO TOKEN URL:", CANTO_TOKEN_URL);

    const resp = await fetch(CANTO_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    // ✅ ADD THESE 2 LINES — critical
    console.log("✅ TOKEN SERVER RESPONDED — HTTP STATUS:", resp.status);
    const raw = await resp.text();
    console.log("📩 RAW TOKEN RESPONSE:", raw);

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return res.status(400).send("Canto token response was not JSON");
    }

    if (!resp.ok || data.error) {
      return res.status(400).send("Canto OAuth failed: " + JSON.stringify(data));
    }

    data._expires_at = nowSec() + Number(data.expires_in || 3500);
    await persistCantoToken(domain, data);

    res.send(`<h2>✅ Canto Connected for <strong>${domain}</strong></h2>`);
  } catch (err) {
    console.error("Canto OAuth error:", err);
    res.status(500).send("Canto OAuth failed.");
  }
});



/* ---------------------------------------------------------------
   UPLOAD TO CANTO (URL -> bytes -> uploads -> S3 -> files)
---------------------------------------------------------------- */
app.post("/upload", async (req, res) => {
  const { attachmentUrl, domain, metadata } = req.body;

  if (!domain) return res.status(400).json({ error: "Missing domain" });
  if (!attachmentUrl) return res.status(400).json({ error: "Missing attachmentUrl" });

  try {
    let tokenData = await refreshCantoTokenIfNeeded(domain);
    if (!tokenData?.access_token) {
      return res.status(400).json({ error: "Canto token not found" });
    }

    // A) Download bytes
    const dl = await fetch(attachmentUrl);
    if (!dl.ok) {
      const t = await dl.text();
      return res.status(400).json({ error: "Failed to download attachment", details: t });
    }

    const mimeType = dl.headers.get("content-type") || "application/octet-stream";
    const buf = Buffer.from(await dl.arrayBuffer());
    const filename = filenameFromUrl(attachmentUrl);

    // B) Parse metadata
    let metaObj = {};
    if (metadata && typeof metadata === "string") {
      try {
        metaObj = JSON.parse(metadata);
      } catch {}
    } else if (metadata && typeof metadata === "object") {
      metaObj = metadata;
    }

    // C) Apply per-domain field mapping
    const domainMapping = await getDomainMapping(domain);
    metaObj = applyFieldMapping(domainMapping, metaObj);

    // D) Create upload
    const created = await cantoCreateUpload(domain, tokenData.access_token, {
      filename,
      size: buf.length,
      mimeType,
    });

    // E) Put to S3
    await cantoPutToS3(created.uploadUrl, buf, mimeType);

    // F) Finalize
    const file = await cantoFinalizeFile(domain, tokenData.access_token, {
      uploadId: created.uploadId,
      filename,
      metadata: metaObj,
    });

    const assetUrl = file?.url || file?.publicUrl || file?.links?.view || null;

    res.json({ ok: true, domain, filename, assetUrl, cantoFile: file });
  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------------------------------------------------------
   TEST RAW FILE UPLOAD (multipart)
---------------------------------------------------------------- */
app.post("/test/upload-canto", async (req, res) => {
  const busboy = Busboy({ headers: req.headers });
  let domain, fileBuffer, fileName, mimeType;

  busboy.on("field", (name, val) => {
    if (name === "domain") domain = String(val).trim();
  });

  busboy.on("file", (name, file, info) => {
    const chunks = [];
    fileName = info.filename;
    mimeType = info.mimeType || "application/octet-stream";

    file.on("data", (d) => chunks.push(d));
    file.on("end", () => {
      fileBuffer = Buffer.concat(chunks);
    });
  });

  busboy.on("finish", async () => {
    if (!domain) return res.status(400).send("Missing domain");
    if (!fileBuffer) return res.status(400).send("Missing file");

    try {
      let token = await refreshCantoTokenIfNeeded(domain);
      if (!token?.access_token) {
        return res.status(400).send("Canto token not found");
      }

      // Mapping
      const mapping = await getDomainMapping(domain);
      const mappedMeta = applyFieldMapping(mapping, {});

      // Create upload
      const created = await cantoCreateUpload(domain, token.access_token, {
        filename: fileName,
        size: fileBuffer.length,
        mimeType,
      });

      // PUT
      await cantoPutToS3(created.uploadUrl, fileBuffer, mimeType);

      // Finalize
      const file = await cantoFinalizeFile(domain, token.access_token, {
        uploadId: created.uploadId,
        filename: fileName,
        metadata: mappedMeta,
      });

      res.json({ success: true, data: file });
    } catch (err) {
      console.error("Test upload error:", err);
      res.status(500).send("Error uploading file.");
    }
  });

  req.pipe(busboy);
});

/* ---------------------------------------------------------------
   ASANA WEBHOOK HANDLER
---------------------------------------------------------------- */
app.post("/webhook/asana", (req, res) => {
  const challenge = req.headers["x-hook-secret"];
  if (challenge) {
    res.setHeader("X-Hook-Secret", challenge);
    return res.status(200).send();
  }
  console.log("📩 Asana webhook:", JSON.stringify(req.body, null, 2));
  res.status(200).send("OK");
});

/* ================================================================
   FIELD MAPPING UI (HTML + JS)
   ---------------------------------------------------------------
   Visit: /mapping-ui/:domain
================================================================ */
app.get("/mapping-ui/:domain", async (req, res) => {
  const { domain } = req.params;

  res.send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Canto Field Mapping – ${domain}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 text-gray-900">
  <div class="max-w-3xl mx-auto mt-10 p-8 bg-white shadow-lg rounded-lg">
    <h1 class="text-3xl font-bold mb-6">
      Canto Field Mapping for <span class="text-indigo-600">${domain}</span>
    </h1>

    <table class="w-full mb-6 border">
      <thead class="bg-gray-200">
        <tr>
          <th class="p-3 text-left">Asana Field</th>
          <th class="p-3 text-left">Canto Field</th>
          <th class="p-3"></th>
        </tr>
      </thead>
      <tbody id="mappingRows"></tbody>
    </table>

    <div class="flex gap-4 mb-6">
      <input id="newAsana" class="border p-2 flex-1 rounded" placeholder="Asana Field Name">
      <input id="newCanto" class="border p-2 flex-1 rounded" placeholder="Canto Field Key">
      <button onclick="addRow()" class="bg-green-600 px-4 py-2 text-white rounded">Add</button>
    </div>

    <div class="flex gap-4">
      <button onclick="saveMapping()" class="bg-indigo-600 text-white px-6 py-2 rounded">Save Mapping</button>
      <button onclick="resetMapping()" class="bg-red-600 text-white px-6 py-2 rounded">Reset Mapping</button>
      <a href="/dashboard/${domain}" class="ml-auto bg-slate-700 text-white px-6 py-2 rounded">Open Dashboard</a>
    </div>
  </div>

<script>
  const domain = "${domain}";
  let mapping = {};

  async function loadMapping() {
    const res = await fetch("/mapping/" + domain);
    const data = await res.json();
    mapping = data.mapping || {};
    renderRows();
  }

  function renderRows() {
    const tbody = document.getElementById("mappingRows");
    tbody.innerHTML = "";

    const entries = Object.entries(mapping);
    if (!entries.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="3" class="p-4 text-center text-gray-500">No mappings yet</td>';
      tbody.appendChild(tr);
      return;
    }

    for (const [asana, canto] of entries) {
      const tr = document.createElement("tr");
      tr.innerHTML = \`
        <td class="p-3 border">
          <input value="\${asana}" class="border p-2 w-full rounded" data-original="\${asana}" onchange="editAsana(this)">
        </td>
        <td class="p-3 border">
          <input value="\${canto}" class="border p-2 w-full rounded" onchange="editCanto('\${asana}', this)">
        </td>
        <td class="p-3 border text-center">
          <button onclick="deleteRow('\${asana}')" class="px-3 py-1 bg-red-600 text-white rounded">Delete</button>
        </td>
      \`;
      tbody.appendChild(tr);
    }
  }

  function addRow() {
    const asana = document.getElementById("newAsana").value.trim();
    const canto = document.getElementById("newCanto").value.trim();
    if (!asana || !canto) return alert("Both fields required");
    mapping[asana] = canto;
    document.getElementById("newAsana").value = "";
    document.getElementById("newCanto").value = "";
    renderRows();
  }

  function editAsana(input) {
    const original = input.getAttribute("data-original");
    const updated = input.value.trim();
    if (!updated) { input.value = original; return; }
    mapping[updated] = mapping[original];
    delete mapping[original];
    renderRows();
  }

  function editCanto(asana, input) {
    mapping[asana] = input.value.trim();
  }

  function deleteRow(asana) {
    delete mapping[asana];
    renderRows();
  }

  async function saveMapping() {
    const res = await fetch("/mapping/" + domain, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(mapping)
    });
    if (res.ok) {
      alert("✅ Mapping saved!");
    } else {
      alert("❌ Failed to save mapping");
    }
  }

  async function resetMapping() {
    if (!confirm("Are you sure? This will delete all mappings.")) return;
    const res = await fetch("/mapping/" + domain, { method: "DELETE" });
    if (res.ok) {
      mapping = {};
      renderRows();
      alert("✅ Mapping reset");
    } else {
      alert("❌ Failed to reset mapping");
    }
  }

  loadMapping();
</script>

</body>
</html>
  `);
});

/* ================================================================
   STATUS API (used by Dashboard)
   ---------------------------------------------------------------
   GET /status/:domain
   Returns: Canto token status, expiry, mapping count, Asana status
================================================================ */
app.get("/status/:domain", async (req, res) => {
  const { domain } = req.params;
  try {
    const cantoToken = await getToken(domain);
    const asanaToken = await getToken("asana");

    const mapping = cantoToken?.mapping || {};
    const expiresAt =
      cantoToken?._expires_at ||
      (cantoToken?.expires_in
        ? Math.floor(Date.now() / 1000) + Number(cantoToken.expires_in)
        : null);

    res.json({
      domain,
      canto: {
        connected: Boolean(cantoToken?.access_token),
        expires_at: expiresAt,
        expires_at_iso: expiresAt ? new Date(expiresAt * 1000).toISOString() : null,
        has_refresh: Boolean(cantoToken?.refresh_token),
      },
      mapping: {
        count: Object.keys(mapping).length,
      },
      asana: {
        connected: Boolean(asanaToken?.access_token),
      },
    });
  } catch (err) {
    console.error("Status error:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ================================================================
   FULL DASHBOARD UI (per-domain)
   ---------------------------------------------------------------
   Visit: /dashboard/:domain
   Sections:
     - Status (Canto & Asana)
     - Mapping Manager
     - Upload Tester (by URL + by File)
================================================================ */
app.get("/dashboard/:domain", async (req, res) => {
  const { domain } = req.params;

  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Asana ↔ Canto Dashboard – ${domain}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-900">

  <div class="max-w-6xl mx-auto p-6">
    <header class="mb-8 flex items-center justify-between">
      <h1 class="text-3xl font-bold">
        Asana ↔ Canto Dashboard <span class="text-indigo-600">(${domain})</span>
      </h1>
      <div class="flex gap-3">
        <a href="/connect/canto" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700"
           title="Reconnect Canto">Connect Canto</a>
        <a href="/connect/asana" class="px-4 py-2 bg-emerald-600 text-white rounded hover:bg-emerald-700"
           title="Reconnect Asana">Connect Asana</a>
      </div>
    </header>

    <!-- Status Cards -->
    <section class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
      <div class="bg-white rounded-lg shadow p-5">
        <h2 class="text-lg font-semibold mb-2">Canto Status</h2>
        <p id="cantoConnected" class="mb-1">–</p>
        <p id="cantoExpiry" class="mb-1">–</p>
        <p id="cantoRefresh" class="mb-1">–</p>
      </div>

      <div class="bg-white rounded-lg shadow p-5">
        <h2 class="text-lg font-semibold mb-2">Asana Status</h2>
        <p id="asanaConnected" class="mb-1">–</p>
        <p class="text-sm text-gray-500">Note: This is app-wide, not per-domain</p>
      </div>

      <div class="bg-white rounded-lg shadow p-5">
        <h2 class="text-lg font-semibold mb-2">Mapping Status</h2>
        <p id="mappingCount" class="mb-1">–</p>
        <div class="flex gap-3">
          <a href="/mapping-ui/${domain}" class="mt-2 px-3 py-2 bg-slate-700 text-white rounded hover:bg-slate-800">Open Mapping UI</a>
          <button id="resetMappingBtn" class="mt-2 px-3 py-2 bg-red-600 text-white rounded hover:bg-red-700">Reset Mapping</button>
        </div>
      </div>
    </section>

    <!-- Mapping Manager (inline editor) -->
    <section class="bg-white rounded-lg shadow p-6 mb-10">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-xl font-semibold">Field Mapping (Asana → Canto)</h2>
        <button id="saveMappingBtn" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700">Save Mapping</button>
      </div>

      <table class="w-full border mb-4">
        <thead class="bg-gray-100">
          <tr>
            <th class="p-3 text-left">Asana Field</th>
            <th class="p-3 text-left">Canto Field</th>
            <th class="p-3 text-center">Actions</th>
          </tr>
        </thead>
        <tbody id="mappingRows"></tbody>
      </table>

      <div class="flex gap-3">
        <input id="newAsana" class="border p-2 flex-1 rounded" placeholder="Asana Field Name" />
        <input id="newCanto" class="border p-2 flex-1 rounded" placeholder="Canto Field Key" />
        <button id="addRowBtn" class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">Add</button>
      </div>
    </section>

    <!-- Upload Tester -->
    <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
      <!-- Upload by URL -->
      <div class="bg-white rounded-lg shadow p-6">
        <h2 class="text-xl font-semibold mb-4">Upload by URL</h2>
        <div class="flex flex-col gap-3">
          <input id="uploadUrl" class="border p-2 rounded" placeholder="https://example.com/file.jpg" />
          <textarea id="uploadMeta" class="border p-2 rounded" rows="4" placeholder='Optional metadata JSON, e.g. {"Market":"US"}'></textarea>
          <button id="uploadUrlBtn" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700">Upload URL → Canto</button>
        </div>
        <pre id="uploadUrlOut" class="mt-4 bg-gray-900 text-gray-100 p-3 rounded text-sm overflow-auto"></pre>
      </div>

      <!-- Upload by File -->
      <div class="bg-white rounded-lg shadow p-6">
        <h2 class="text-xl font-semibold mb-4">Upload a File</h2>
        <div class="flex flex-col gap-3">
          <input id="uploadFileInput" type="file" class="border p-2 rounded bg-gray-50" />
          <button id="uploadFileBtn" class="px-4 py-2 bg-emerald-600 text-white rounded hover:bg-emerald-700">Upload File → Canto</button>
        </div>
        <pre id="uploadFileOut" class="mt-4 bg-gray-900 text-gray-100 p-3 rounded text-sm overflow-auto"></pre>
      </div>
    </section>

    <footer class="text-sm text-gray-500">
      <p>Asana ↔ Canto Dashboard for <strong>${domain}</strong>. Powered by your Node.js integration.</p>
    </footer>
  </div>

<script>
  const domain = "${domain}";
  let mapping = {};

  // ---------------- Status ----------------
  async function loadStatus() {
    const r = await fetch("/status/" + domain);
    const s = await r.json();

    // Canto
    document.getElementById("cantoConnected").textContent =
      "Connected: " + (s.canto?.connected ? "Yes ✅" : "No ❌");
    document.getElementById("cantoRefresh").textContent =
      "Has refresh token: " + (s.canto?.has_refresh ? "Yes" : "No");

    let expText = "Expires: –";
    if (s.canto?.expires_at_iso) {
      const dt = new Date(s.canto.expires_at_iso);
      expText = "Expires: " + dt.toLocaleString();
    }
    document.getElementById("cantoExpiry").textContent = expText;

    // Asana
    document.getElementById("asanaConnected").textContent =
      "Connected: " + (s.asana?.connected ? "Yes ✅" : "No ❌");

    // Mapping
    document.getElementById("mappingCount").textContent =
      "Current mappings: " + (s.mapping?.count ?? 0);
  }

  // ---------------- Mapping ----------------
  async function loadMapping() {
    const res = await fetch("/mapping/" + domain);
    const data = await res.json();
    mapping = data.mapping || {};
    renderRows();
  }

  function renderRows() {
    const tbody = document.getElementById("mappingRows");
    tbody.innerHTML = "";

    const entries = Object.entries(mapping);
    if (!entries.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="3" class="p-4 text-center text-gray-500">No mappings yet</td>';
      tbody.appendChild(tr);
      return;
    }

    for (const [asana, canto] of entries) {
      const tr = document.createElement("tr");

      tr.innerHTML = \`
        <td class="p-3 border"><input class="w-full border p-2 rounded" value="\${asana}" data-original="\${asana}" onchange="editAsana(this)" /></td>
        <td class="p-3 border"><input class="w-full border p-2 rounded" value="\${canto}" onchange="editCanto('\${asana}', this)" /></td>
        <td class="p-3 border text-center">
          <button onclick="deleteRow('\${asana}')" class="px-2 py-1 bg-red-600 text-white rounded">Delete</button>
        </td>
      \`;

      tbody.appendChild(tr);
    }
  }

  window.editAsana = (input) => {
    const original = input.getAttribute("data-original");
    const val = input.value.trim();
    if (!val) { input.value = original; return; }
    mapping[val] = mapping[original];
    delete mapping[original];
    renderRows();
  };

  window.editCanto = (asana, input) => {
    mapping[asana] = input.value.trim();
  };

  window.deleteRow = (asana) => {
    delete mapping[asana];
    renderRows();
  };

  document.getElementById("addRowBtn").addEventListener("click", () => {
    const a = document.getElementById("newAsana").value.trim();
    const c = document.getElementById("newCanto").value.trim();
    if (!a || !c) return alert("Both fields required");
    mapping[a] = c;
    document.getElementById("newAsana").value = "";
    document.getElementById("newCanto").value = "";
    renderRows();
  });

  document.getElementById("saveMappingBtn").addEventListener("click", async () => {
    const res = await fetch("/mapping/" + domain, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(mapping),
    });
    if (res.ok) {
      alert("✅ Mapping saved");
      loadStatus();
    } else {
      alert("❌ Failed to save mapping");
    }
  });

  document.getElementById("resetMappingBtn").addEventListener("click", async () => {
    if (!confirm("Reset all mappings for this domain?")) return;
    const res = await fetch("/mapping/" + domain, { method: "DELETE" });
    if (res.ok) {
      mapping = {};
      renderRows();
      loadStatus();
      alert("✅ Mapping reset");
    } else {
      alert("❌ Failed to reset mapping");
    }
  });

  // ---------------- Upload by URL ----------------
  document.getElementById("uploadUrlBtn").addEventListener("click", async () => {
    const url = document.getElementById("uploadUrl").value.trim();
    const metaText = document.getElementById("uploadMeta").value.trim();
    if (!url) return alert("Provide a URL");

    let metaObj = {};
    if (metaText) {
      try { metaObj = JSON.parse(metaText); } catch { return alert("Metadata must be valid JSON"); }
    }

    const r = await fetch("/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, attachmentUrl: url, metadata: metaObj }),
    });

    const t = await r.text();
    document.getElementById("uploadUrlOut").textContent = t;
    loadStatus();
  });

  // ---------------- Upload by File ----------------
  document.getElementById("uploadFileBtn").addEventListener("click", async () => {
    const input = document.getElementById("uploadFileInput");
    if (!input.files || !input.files.length) return alert("Choose a file first");

    const fd = new FormData();
    fd.append("domain", domain);
    fd.append("file", input.files[0]);

    const r = await fetch("/test/upload-canto", { method: "POST", body: fd });
    const t = await r.text();
    document.getElementById("uploadFileOut").textContent = t;
    loadStatus();
  });

  // Boot
  loadStatus();
  loadMapping();
</script>
</body>
</html>`);
});

/* ---------------------------------------------------------------
   START SERVER
---------------------------------------------------------------- */
const port = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(port, () =>
    console.log(`🚀 Server running on port ${port}`)
  );
});
