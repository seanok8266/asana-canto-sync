/********************************************************************
 *  Asana ↔ Canto Sync Service (Clean rewrite, dual upload support)
 *  ---------------------------------------------------------------
 *  ✅ Asana OAuth
 *  ✅ Canto OAuth + refresh
 *  ✅ Auto-detect per-domain upload API: 'legacy' (v2) vs 'v3'
 *  ✅ Legacy flow: GET upload/setting → multipart S3 → poll → PATCH metadata
 *  ✅ V3 flow:     POST /uploads → PUT S3 → POST /files (+metadata)
 *  ✅ Per-domain metadata mapping API (/mapping/:domain)
 *  ✅ Dashboard (/dashboard/:domain) + Mapping UI
 *  ✅ Uses your db.js (initDB / getToken / saveToken), extras cached in-memory
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
const OAUTH_BASE = "https://oauth.canto.com"; // auth/token host
const CANTO_AUTH_URL  = `${OAUTH_BASE}/oauth/api/oauth2/compatible/authorize`;
const CANTO_TOKEN_URL = `${OAUTH_BASE}/oauth/api/oauth2/compatible/token`;
// v3-only endpoints (reside on oauth host):
const CANTO_UPLOADS_URL_V3 = `${OAUTH_BASE}/api/v1/uploads`;
const CANTO_FILES_URL_V3   = `${OAUTH_BASE}/api/v1/files`;

/* ================================================================
   IN-MEMORY CACHE
================================================================ */
const memory = {
  canto: {
    // domain -> token record (last seen)
  },
  uploadVersion: {
    // domain -> "legacy" | "v3"
  },
};

/* ================================================================
   HELPERS (generic)
================================================================ */
const nowSec = () => Math.floor(Date.now() / 1000);

function tenantBase(domain) {
  // accepts "thedamconsultants" or a full host
  const clean = String(domain)
    .replace(/^https?:\/\//, "")
    .replace(/\.canto\.com$/i, "");
  return `https://${clean}.canto.com`;
}

async function persistCantoToken(domain, tokenData) {
  const rec = {
    ...tokenData,
    domain,
    _expires_at: nowSec() + Number(tokenData.expires_in || 3500),
  };
  memory.canto[domain] = rec;
  await saveToken(domain, rec); // harmless if db.js ignores some fields
  return rec;
}

async function getCantoRecord(domain) {
  // merge DB + memory
  const fromDb = await getToken(domain);
  const inMem = memory.canto[domain];
  return { ...(fromDb || {}), ...(inMem || {}) };
}

async function refreshCantoTokenIfNeeded(domain) {
  const td = await getCantoRecord(domain);
  if (!td?.access_token) throw new Error("No Canto token for domain " + domain);

  const now = nowSec();
  const exp = td._expires_at || (td.expires_in ? now + Number(td.expires_in) : null);
  if (exp && exp - now > 60) return td; // still fresh

  if (!td.refresh_token) return td; // nothing we can do

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
  try { data = JSON.parse(raw); } catch { throw new Error("Canto refresh returned non-JSON"); }

  if (!resp.ok || data.error) {
    console.error("Canto refresh failed:", data);
    return td;
  }
  return persistCantoToken(domain, { ...td, ...data });
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
  // best-effort persistence via saveToken (extra fields may be ignored by your db.js)
  const current = (await getToken(domain)) || {};
  const patched = { ...current, mapping };
  await saveToken(domain, patched);
  // keep in-memory too:
  memory.canto[domain] = { ...(memory.canto[domain] || {}), ...patched, domain };
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
   UPLOAD VERSION DETECTION (per-domain)
   - Try legacy GET {tenant}/api/v1/upload/setting
   - If 200 + expected fields -> "legacy"
   - Else fallback to "v3"
================================================================ */
async function detectUploadVersion(domain, accessToken) {
  // prefer cached
  if (memory.uploadVersion[domain]) return memory.uploadVersion[domain];

  try {
    const url = new URL(`${tenantBase(domain)}/api/v1/upload/setting`);
    url.searchParams.set("fileName", "probe.txt"); // harmless hint

    const r = await fetch(url.toString(), {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    const text = await r.text();
    let data; try { data = JSON.parse(text); } catch { data = {}; }

    if (r.ok && (data.uploadUrl || data.fields || data.params)) {
      memory.uploadVersion[domain] = "legacy";
      // best-effort persist (ignored if db.js doesn't store it)
      await saveToken(domain, { ...(await getToken(domain)), uploadVersion: "legacy" });
      return "legacy";
    }
  } catch (_) { /* ignore */ }

  memory.uploadVersion[domain] = "v3";
  await saveToken(domain, { ...(await getToken(domain)), uploadVersion: "v3" });
  return "v3";
}

/* ================================================================
   LEGACY (v2) HELPERS
   1) GET {tenant}/api/v1/upload/setting
   2) POST multipart to S3 (uploadUrl + *fields*)
   3) Poll recent
   4) PATCH metadata
================================================================ */
async function cantoGetUploadSettingLegacy(domain, accessToken, { fileName }) {
  const url = new URL(`${tenantBase(domain)}/api/v1/upload/setting`);
  if (fileName) url.searchParams.set("fileName", fileName);

  const r = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });

  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = {}; }

  if (!r.ok) {
    console.error("[legacy upload/setting] HTTP", r.status, text);
    throw new Error("legacy upload/setting failed");
  }

  // Some tenants return { uploadUrl, fields: {...} }, older docs called it "params"
  const fields = data.fields || data.params;
  if (!data.uploadUrl || !fields) {
    console.error("[legacy upload/setting] missing uploadUrl/fields:", data);
    throw new Error("legacy upload/setting missing fields");
  }
  return { uploadUrl: data.uploadUrl, fields, key: fields.key || data.key || null };
}

async function s3MultipartPost(uploadUrl, fields, fileBuffer, fileName, mimeType) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) form.append(k, String(v));
  form.append("file", fileBuffer, { filename: fileName, contentType: mimeType });

  const r = await fetch(uploadUrl, { method: "POST", headers: form.getHeaders(), body: form });
  // S3 often returns 204/201
  if (![200, 201, 204].includes(r.status)) {
    const t = await r.text();
    console.error("[S3 multipart POST] failed:", r.status, t);
    throw new Error("S3 multipart POST failed");
  }
}

async function pollRecentForFile(domain, accessToken, { filename, tries = 8, delayMs = 800 }) {
  const recentUrl = `${tenantBase(domain)}/api/v1/files/recent`;

  for (let i = 0; i < tries; i++) {
    const r = await fetch(recentUrl, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    });

    const text = await r.text();
    let data; try { data = JSON.parse(text); } catch { data = {}; }
    if (Array.isArray(data?.items)) {
      const found = data.items.find(
        f => f.originalName === filename || f.name === filename
      );
      if (found) return found;
    }
    await new Promise(res => setTimeout(res, delayMs));
  }
  throw new Error("Uploaded file not found in recent list");
}

async function applyMetadataLegacy(domain, accessToken, fileId, metadata) {
  // Some tenants use PATCH /files/{id}, others /files/{id}/metadata
  // 1) Try PATCH /files/{id} with { metadata }
  const url1 = `${tenantBase(domain)}/api/v1/files/${encodeURIComponent(fileId)}`;
  let r = await fetch(url1, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ metadata: metadata || {} }),
  });

  if (r.status === 404 || r.status === 405) {
    // 2) Fall back to POST/PATCH /files/{id}/metadata
    const url2 = `${tenantBase(domain)}/api/v1/files/${encodeURIComponent(fileId)}/metadata`;
    r = await fetch(url2, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(metadata || {}),
    });
  }

  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = {}; }
  if (!r.ok) {
    console.error("[legacy metadata] HTTP", r.status, data);
    throw new Error("Metadata update failed (legacy)");
  }
  return data;
}

/* ================================================================
   V3 HELPERS
   POST /uploads → PUT S3 → POST /files (+metadata)
================================================================ */
async function v3CreateUpload(accessToken, { filename, size, mimeType }) {
  const r = await fetch(CANTO_UPLOADS_URL_V3, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ filename, size, mimeType }),
  });

  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = {}; }

  if (!r.ok || !data.uploadId || !data.uploadUrl) {
    console.error("[v3 /uploads] HTTP", r.status, data);
    throw new Error("Canto v3 /uploads failed");
  }
  return data; // { uploadId, uploadUrl }
}

async function s3Put(uploadUrl, bytes, mimeType) {
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

async function v3FinalizeFile(accessToken, { uploadId, filename, metadata }) {
  const r = await fetch(CANTO_FILES_URL_V3, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ uploadId, filename, metadata }),
  });

  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = {}; }

  if (!r.ok) {
    console.error("[v3 /files] HTTP", r.status, data);
    throw new Error("Canto v3 /files failed");
  }
  return data;
}

/* ================================================================
   UNIFIED UPLOAD
================================================================ */
async function uploadToCanto({ domain, accessToken, bytes, filename, mimeType, metadata }) {
  // detect & cache version
  const version = await detectUploadVersion(domain, accessToken);

  // apply mapping before hitting API
  const mapping = await getDomainMapping(domain);
  const mapped = applyFieldMapping(mapping, metadata || {});

  if (version === "legacy") {
    // 1) upload setting
    const setting = await cantoGetUploadSettingLegacy(domain, accessToken, { fileName: filename });
    // 2) S3 multipart
    await s3MultipartPost(setting.uploadUrl, setting.fields, bytes, filename, mimeType);
    // 3) find recent
    const found = await pollRecentForFile(domain, accessToken, { filename });
    // 4) metadata
    const patched = await applyMetadataLegacy(domain, accessToken, found.id, mapped);
    return { version, fileId: found.id, file: patched };
  }

  // v3 path
  const created = await v3CreateUpload(accessToken, { filename, size: bytes.length, mimeType });
  await s3Put(created.uploadUrl, bytes, mimeType);
  const finalized = await v3FinalizeFile(accessToken, {
    uploadId: created.uploadId,
    filename,
    metadata: mapped,
  });
  return { version, fileId: finalized?.id, file: finalized };
}

/* ================================================================
   ROUTES
================================================================ */

app.get("/", (_req, res) => res.send("Asana ↔ Canto Sync Service Running ✅"));

/* ---------------- Asana OAuth ---------------- */
app.get("/connect/asana", (_req, res) => {
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
      return res.status(400).send("Asana token exchange failed: " + JSON.stringify(tokenData));
    }
    await saveToken("asana", tokenData);
    res.send("<h2>✅ Asana Connected!</h2>");
  } catch (err) {
    console.error("Asana OAuth error:", err);
    res.status(500).send("Server error exchanging Asana token.");
  }
});

/* ---------------- Canto OAuth ---------------- */
app.get("/connect/canto", (_req, res) => {
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
  const url = `${CANTO_AUTH_URL}?` + new URLSearchParams({
    response_type: "code",
    app_id: process.env.CANTO_APP_ID,
    redirect_uri: process.env.CANTO_REDIRECT_URI,
    state: domain,
  });
  res.redirect(url);
});

app.get("/oauth/callback/canto", async (req, res) => {
  const { code, state: domain } = req.query;
  if (!code || !domain) return res.status(400).send("Missing authorization code or domain");

  try {
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      app_id: process.env.CANTO_APP_ID,
      app_secret: process.env.CANTO_APP_SECRET,
      redirect_uri: process.env.CANTO_REDIRECT_URI,
    });

    const resp = await fetch(CANTO_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); } catch { return res.status(400).send("Canto token response was not JSON"); }
    if (!resp.ok || data.error) {
      return res.status(400).send("Canto OAuth failed: " + JSON.stringify(data));
    }

    await persistCantoToken(domain, data);

    // best-effort detection/caching
    try {
      const ver = await detectUploadVersion(domain, data.access_token);
      console.log(`✅ cached uploadVersion='${ver}' for ${domain}`);
    } catch { /* ignore */ }

    res.send(`<h2>✅ Canto Connected for <strong>${domain}</strong></h2>`);
  } catch (err) {
    console.error("Canto OAuth error:", err);
    res.status(500).send("Canto OAuth failed.");
  }
});

/* ---------------- Mapping API ---------------- */
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
    const cleared = await saveDomainMapping(domain, {});
    res.json({ domain, cleared: true, mapping: cleared });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------------- Status API ---------------- */
app.get("/status/:domain", async (req, res) => {
  const { domain } = req.params;
  try {
    const cantoToken = await getCantoRecord(domain);
    const asanaToken = await getToken("asana");

    // expiry calc
    const now = nowSec();
    const expiresAt =
      cantoToken?._expires_at ||
      (cantoToken?.expires_in ? now + Number(cantoToken.expires_in) : null);

    // live probe for upload version (best-effort)
    let uploadVersion = memory.uploadVersion[domain] || null;
    if (cantoToken?.access_token && domain && !uploadVersion) {
      try {
        uploadVersion = await detectUploadVersion(domain, cantoToken.access_token);
      } catch { uploadVersion = null; }
    }

    const mapping = cantoToken?.mapping || {};
    res.json({
      domain,
      canto: {
        connected: Boolean(cantoToken?.access_token),
        expires_at: expiresAt || null,
        expires_at_iso: expiresAt ? new Date(expiresAt * 1000).toISOString() : null,
        has_refresh: Boolean(cantoToken?.refresh_token),
        uploadVersion,
      },
      mapping: { count: Object.keys(mapping).length },
      asana: { connected: Boolean(asanaToken?.access_token) },
    });
  } catch (err) {
    console.error("Status error:", err);
    res.status(500).json({ error: err.message });
  }
});

// dedicated Asana status for dashboard’s correctness
app.get("/status/asana", async (_req, res) => {
  try {
    const asanaToken = await getToken("asana");
    res.json({ domain: "asana", asana: { connected: Boolean(asanaToken?.access_token) } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------------- Unified Upload Route ----------------
Body: { domain, attachmentUrl, metadata? }
------------------------------------------------------- */
app.post("/upload", async (req, res) => {
  const { attachmentUrl, domain, metadata } = req.body;
  if (!domain) return res.status(400).json({ error: "Missing domain" });
  if (!attachmentUrl) return res.status(400).json({ error: "Missing attachmentUrl" });

  try {
    // refresh token
    const token = await refreshCantoTokenIfNeeded(domain);
    if (!token?.access_token) return res.status(400).json({ error: "Canto token not found" });

    // download
    const dl = await fetch(attachmentUrl);
    if (!dl.ok) {
      return res.status(400).json({
        error: "Failed to download attachment",
        status: dl.status,
        text: await dl.text(),
      });
    }
    const mimeType = dl.headers.get("content-type") || "application/octet-stream";
    const bytes = Buffer.from(await dl.arrayBuffer());
    const filename = filenameFromUrl(attachmentUrl);

    const metaObj =
      typeof metadata === "string"
        ? (JSON.parse(metadata || "{}"))
        : (metadata || {});

    const out = await uploadToCanto({
      domain,
      accessToken: token.access_token,
      bytes,
      filename,
      mimeType,
      metadata: metaObj,
    });

    res.json({ ok: true, domain, filename, version: out.version, cantoFileId: out.fileId, cantoFile: out.file });
  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

/* ---------------- Test Upload (multipart) ---------------
Form-data: domain, file
--------------------------------------------------------- */
app.post("/test/upload-canto", async (req, res) => {
  const busboy = Busboy({ headers: req.headers });
  let domain, fileBuffer, fileName, mimeType;

  busboy.on("field", (name, val) => {
    if (name === "domain") domain = String(val).trim();
  });

  busboy.on("file", (_name, file, info) => {
    const chunks = [];
    fileName = info.filename;
    mimeType = info.mimeType || "application/octet-stream";
    file.on("data", (d) => chunks.push(d));
    file.on("end", () => { fileBuffer = Buffer.concat(chunks); });
  });

  busboy.on("finish", async () => {
    if (!domain) return res.status(400).send("Missing domain");
    if (!fileBuffer) return res.status(400).send("Missing file");

    try {
      const token = await refreshCantoTokenIfNeeded(domain);
      if (!token?.access_token) return res.status(400).send("Canto token not found");

      const out = await uploadToCanto({
        domain,
        accessToken: token.access_token,
        bytes: fileBuffer,
        filename: fileName,
        mimeType,
        metadata: {}, // test route skips metadata (UI route handles)
      });

      res.json({ success: true, version: out.version, fileId: out.fileId, data: out.file });
    } catch (err) {
      console.error("Test upload error:", err);
      res.status(500).send("Error uploading file.");
    }
  });

  req.pipe(busboy);
});

/* ---------------- Asana Webhook ---------------- */
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
   MAPPING UI (simple)
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
    if (res.ok) alert("✅ Mapping saved!");
    else alert("❌ Failed to save mapping");
  }

  async function resetMapping() {
    if (!confirm("Are you sure? This will delete all mappings.")) return;
    const res = await fetch("/mapping/" + domain, { method: "DELETE" });
    if (res.ok) { mapping = {}; renderRows(); alert("✅ Mapping reset"); }
    else alert("❌ Failed to reset mapping");
  }

  loadMapping();
</script>
</body>
</html>
  `);
});

/* ================================================================
   DASHBOARD
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

    <!-- Mapping Manager -->
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
      <div class="bg-white rounded-lg shadow p-6">
        <h2 class="text-xl font-semibold mb-4">Upload by URL</h2>
        <div class="flex flex-col gap-3">
          <input id="uploadUrl" class="border p-2 rounded" placeholder="https://example.com/file.jpg" />
          <textarea id="uploadMeta" class="border p-2 rounded" rows="4" placeholder='Optional metadata JSON, e.g. {"Market":"US"}'></textarea>
          <button id="uploadUrlBtn" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700">Upload URL → Canto</button>
        </div>
        <pre id="uploadUrlOut" class="mt-4 bg-gray-900 text-gray-100 p-3 rounded text-sm overflow-auto"></pre>
      </div>

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

  async function loadStatus() {
    const rDomain = await fetch("/status/" + domain);
    const sDomain = await rDomain.json();

    const rAsana = await fetch("/status/asana");
    const sAsana = await rAsana.json();

    document.getElementById("cantoConnected").textContent =
      "Connected: " + (sDomain.canto?.connected ? "Yes ✅" : "No ❌");
    document.getElementById("cantoRefresh").textContent =
      "Has refresh token: " + (sDomain.canto?.has_refresh ? "Yes" : "No");

    let expText = "Expires: –";
    if (sDomain.canto?.expires_at_iso) {
      const dt = new Date(sDomain.canto.expires_at_iso);
      expText = "Expires: " + dt.toLocaleString();
    }
    document.getElementById("cantoExpiry").textContent = expText;

    document.getElementById("asanaConnected").textContent =
      "Connected: " + (sAsana.asana?.connected ? "Yes ✅" : "No ❌");

    document.getElementById("mappingCount").textContent =
      "Current mappings: " + (sDomain.mapping?.count ?? 0);
  }

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
    if (res.ok) { alert("✅ Mapping saved"); loadStatus(); }
    else { alert("❌ Failed to save mapping"); }
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

  // Upload by URL
  document.getElementById("uploadUrlBtn").addEventListener("click", async () => {
    const url = document.getElementById("uploadUrl").value.trim();
    const metaText = document.getElementById("uploadMeta").value.trim();
    if (!url) return alert("Provide a URL");
    let metaObj = {};
    if (metaText) { try { metaObj = JSON.parse(metaText); } catch { return alert("Metadata must be valid JSON"); } }

    const r = await fetch("/upload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, attachmentUrl: url, metadata: metaObj }),
    });
    const t = await r.text();
    document.getElementById("uploadUrlOut").textContent = t;
    loadStatus();
  });

  // Upload by File
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

  loadStatus();
  loadMapping();
</script>
</body>
</html>`);
});

/* ================================================================
   START SERVER
================================================================ */
const port = process.env.PORT || 3000;
initDB().then(() => {
  app.listen(port, () => console.log(`🚀 Server running on port ${port}`));
});
