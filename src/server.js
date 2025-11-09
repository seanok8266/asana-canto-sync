/********************************************************************
 *  Asana ↔ Canto Sync Service (Clean Unified Version)
 *  ---------------------------------------------------------------
 *  ✅ Asana OAuth
 *  ✅ Canto OAuth + Refresh
 *  ✅ Unified Upload Dispatcher (v2 + v3 auto-detect)
 *  ✅ Mapping UI + Dashboard
 *  ✅ Test Upload Endpoints
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
app.use(express.json({ limit: "30mb" }));
app.use(express.urlencoded({ extended: true }));

/* ================================================================
   CONSTANTS
================================================================ */
const CANTO_OAUTH_BASE = "https://oauth.canto.com";
const CANTO_AUTH_URL   = `${CANTO_OAUTH_BASE}/oauth/api/oauth2/compatible/authorize`;
const CANTO_TOKEN_URL  = `${CANTO_OAUTH_BASE}/oauth/api/oauth2/compatible/token`;

const CANTO_UPLOADS_URL_V3 = `${CANTO_OAUTH_BASE}/api/v1/uploads`;
const CANTO_FILES_URL_V3   = `${CANTO_OAUTH_BASE}/api/v1/files`;

/* ================================================================
   HELPERS — General
================================================================ */
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function tenantApiBase(domain) {
  const d = domain.replace(/^https?:\/\//, "").replace(/\.canto\.com$/, "");
  return `https://${d}.canto.com`;
}

function filenameFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    const parts = u.pathname.split("/");
    return decodeURIComponent(parts.pop()) || `file-${Date.now()}`;
  } catch {
    return `file-${Date.now()}`;
  }
}

/* ================================================================
   SAFE JSON PARSER — prevents HTML from breaking uploads
================================================================ */
async function safeJson(res) {
  const text = await res.text();
  if (text.trim().startsWith("<")) {
    return { __html: text };
  }
  try {
    return JSON.parse(text);
  } catch {
    return { __raw: text };
  }
}

/* ================================================================
   CLEANUP: Strip HTML responses from objects before JSON output
================================================================ */
function scrubHtml(input) {
  if (input == null) return input;

  if (typeof input === "string") {
    return input.trim().startsWith("<")
      ? "[HTML response omitted]"
      : input;
  }

  if (Array.isArray(input)) {
    return input.map(scrubHtml);
  }

  if (typeof input === "object") {
    const out = {};
    for (const [key, value] of Object.entries(input)) {
      out[key] = scrubHtml(value);
    }
    return out;
  }

  return input;
}

/* ================================================================
   TOKEN HELPERS
================================================================ */
async function persistCantoRecord(domain, patch) {
  const current = (await getToken(domain)) || {};
  const next = { ...current, ...patch, domain };
  await saveToken(domain, next);
  return next;
}

async function persistCantoToken(domain, tokenData) {
  tokenData.domain = domain;
  tokenData._expires_at = nowSec() + Number(tokenData.expires_in || 3500);
  await saveToken(domain, tokenData);
}

async function loadCantoToken(domain) {
  return await getToken(domain);
}

async function refreshCantoTokenIfNeeded(domain) {
  let td = await loadCantoToken(domain);
  if (!td?.access_token) throw new Error("No Canto token for " + domain);

  const now = nowSec();
  if (!td._expires_at && td.expires_in) {
    td._expires_at = now + Number(td.expires_in);
    await persistCantoRecord(domain, td);
  }

  if (td._expires_at - now > 60) return td;
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
    body: params
  });

  const raw = await resp.text();
  let data;
  try { data = JSON.parse(raw); } catch {
    throw new Error("Non-JSON refresh response");
  }

  if (!resp.ok || data.error) {
    console.error("Canto refresh failed:", data);
    return td;
  }

  const merged = {
    ...td,
    ...data,
    _expires_at: nowSec() + Number(data.expires_in || 3500)
  };

  await persistCantoRecord(domain, merged);
  return merged;
}

/* ================================================================
   FIELD MAPPING HELPERS
================================================================ */
async function getDomainMapping(domain) {
  const t = await getToken(domain);
  return t?.mapping || {};
}

async function saveDomainMapping(domain, mapping) {
  const t = (await getToken(domain)) || {};
  t.mapping = mapping;
  await saveToken(domain, t);
  return mapping;
}

function applyFieldMapping(mapping, metadata) {
  const out = { ...metadata };
  for (const [asanaKey, cantoKey] of Object.entries(mapping || {})) {
    if (metadata.hasOwnProperty(asanaKey)) {
      out[cantoKey] = metadata[asanaKey];
    }
  }
  return out;
}

/* ================================================================
   DETECT UPLOAD VERSION PER DOMAIN (v2 or v3)
================================================================ */
async function detectUploadVersion(domain, accessToken) {
  const existing = await getToken(domain);
  if (existing?.uploadVersion) return existing.uploadVersion;

  // Try v2 first (upload/setting)
  try {
    const url = `${tenantApiBase(domain)}/api/v1/upload/setting`;
    const r = await fetch(url, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (r.ok) {
      await persistCantoRecord(domain, { uploadVersion: "v2" });
      return "v2";
    }
  } catch {}

  // Otherwise assume v3
  await persistCantoRecord(domain, { uploadVersion: "v3" });
  return "v3";
}

/* ================================================================
   ASANA OAUTH
================================================================ */
app.get("/connect/asana", (req, res) => {
  const url =
    `https://app.asana.com/-/oauth_authorize?client_id=${process.env.ASANA_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.ASANA_REDIRECT_URI)}` +
    `&response_type=code`;

  res.redirect(url);
});

app.get("/oauth/callback/asana", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Missing code");

  try {
    const resp = await fetch("https://app.asana.com/-/oauth_token", {
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

    const data = await resp.json();
    if (!resp.ok || data.error) {
      return res.status(400).send("Asana OAuth failed: " + JSON.stringify(data));
    }

    await saveToken("asana", data);
    res.send("<h2>✅ Asana connected!</h2>");
  } catch (err) {
    res.status(500).send("Asana OAuth error");
  }
});

/* ================================================================
   CANTO OAUTH
================================================================ */
app.get("/connect/canto", (req, res) => {
  res.send(`
    <h1>Connect Canto</h1>
    <form method="POST" action="/connect/canto/start">
      <input name="domain" placeholder="thedamconsultants" />
      <button type="submit">Continue</button>
    </form>
  `);
});

app.post("/connect/canto/start", (req, res) => {
  const domain = String(req.body.domain || "").trim();
  if (!domain) return res.status(400).send("Missing domain");

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
  const { code, state: domain } = req.query;
  if (!code || !domain) return res.status(400).send("Missing code or state");

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
    try { data = JSON.parse(raw); } catch {
      return res.status(400).send("Token response not JSON");
    }

    if (!resp.ok || data.error) {
      return res.status(400).send("Canto OAuth failed: " + JSON.stringify(data));
    }

    await persistCantoToken(domain, data);

    try {
      const ver = await detectUploadVersion(domain, data.access_token);
      console.log(`✅ uploadVersion for ${domain} = ${ver}`);
    } catch {}

    res.send(`<h2>✅ Canto connected for <strong>${domain}</strong></h2>`);
  } catch (err) {
    res.status(500).send("Canto OAuth error");
  }
});

/* ================================================================
   DEBUG: raw tenant /upload/setting inspector
   Helps inspect the exact response shape from the tenant API
================================================================ */
app.get("/debug/upload-setting", async (req, res) => {
  try {
    const domain = (req.query.domain || "").toString().trim();
    const filename = (req.query.filename || "Probe.jpg").toString();

    if (!domain) {
      return res.status(400).json({ error: "Missing ?domain=" });
    }

    const token = await refreshCantoTokenIfNeeded(domain);
    if (!token?.access_token) {
      return res.status(400).json({ error: "No Canto access token for domain" });
    }

    const base = tenantApiBase(domain);
    const url = `${base}/api/v1/upload/setting?fileName=${encodeURIComponent(filename)}`;

    const r = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        Accept: "application/json"
      },
    });

    const text = await r.text();
    res.status(r.status).send(text);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ================================================================
   MAPPING API
================================================================ */
app.get("/mapping/:domain", async (req, res) => {
  const mapping = await getDomainMapping(req.params.domain);
  res.json({ domain: req.params.domain, mapping });
});

app.post("/mapping/:domain", async (req, res) => {
  if (typeof req.body !== "object") {
    return res.status(400).json({ error: "Mapping must be object" });
  }
  const updated = await saveDomainMapping(req.params.domain, req.body);
  res.json({ domain: req.params.domain, mapping: updated });
});

app.delete("/mapping/:domain", async (req, res) => {
  await saveDomainMapping(req.params.domain, {});
  res.json({ domain: req.params.domain, mapping: {} });
});

/* ================================================================
   CANTO v3 HELPERS
   Flow: POST /uploads → PUT (S3) → POST /files
================================================================ */
async function cantoCreateUploadV3(accessToken, { filename, size, mimeType }) {
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
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!r.ok) {
    console.error("[v3 /uploads] HTTP", r.status, data);
    throw new Error("Canto v3 /uploads failed");
  }

  if (!data.uploadId || !data.uploadUrl) {
    console.error("[v3 /uploads] missing uploadId/uploadUrl:", data);
    throw new Error("Canto v3 /uploads response incomplete");
  }
  return data; // { uploadId, uploadUrl, ... }
}

async function s3PutSignedUrl(uploadUrl, bytes, mimeType) {
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

async function cantoFinalizeFileV3(accessToken, { uploadId, filename, metadata }) {
  const r = await fetch(CANTO_FILES_URL_V3, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({ uploadId, filename, metadata: metadata || {} }),
  });

  const text = await r.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!r.ok) {
    console.error("[v3 /files] HTTP", r.status, data);
    throw new Error("Canto v3 /files failed");
  }
   return scrubHtml(data);
}

/* ============================================================
   CANTO UPLOAD (v2) – Integrated Full Pipeline
============================================================ */

/**
 * Step 1 – Request upload slot (S3 info)
 */
async function cantoRequestUploadSlot(domain, accessToken, filename) {
  const base = tenantApiBase(domain);

  const r = await fetch(`${base}/api/v1/upload/setting`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      uploadType: "file",
      fileName: filename
    }),
  });

  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Canto upload-setting failed: ${r.status} — ${text}`);
  }

  return r.json();
}

/**
 * Step 2 – Poll for uploaded file using filename + timestamp
 */
async function cantoFindUploadedFileV2(
  domain,
  accessToken,
  { filename, uploadStartMs },
  { tries = 10, delayMs = 1200 } = {}
) {
  const base = tenantApiBase(domain);

  const normalizedFilename = filename.toLowerCase().trim();
  const filenameStem = normalizedFilename.replace(/\.[^.]+$/, "");
  const fileExt = normalizedFilename.split(".").pop();

  function cantoTimeToMs(t) {
    if (!t) return 0;
    return +t.substring(0, 14);
  }

  function matches(item) {
    if (!item) return false;

    const name = (item.name || item.originalName || "").toLowerCase();
    const ext = (name.split(".").pop() || "").toLowerCase();
    if (ext !== fileExt) return false;
    if (!name.includes(filenameStem)) return false;

    const createdMs = cantoTimeToMs(item.time);
    if (createdMs && createdMs < uploadStartMs) return false;

    return true;
  }

  // Wrap search API with HTML-safe JSON
  async function searchByName() {
    try {
      const body = {
        search: {
          query: normalizedFilename,
          types: ["files"]
        }
      };

      const r = await fetch(`${base}/api/v1/search`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });

      const d = await safeJson(r);

      if (d.__html || d.__raw) {
        console.warn("⚠️ Canto returned HTML/non-JSON for search API");
        return [];
      }

      return d.results || d.items || [];
    } catch {
      return [];
    }
  }

  // Wrap recent-files API with HTML-safe JSON
  async function fetchRecent() {
    try {
      const r = await fetch(`${base}/api/v1/files/recent?count=50`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });

      const d = await safeJson(r);

      if (d.__html || d.__raw) {
        console.warn("⚠️ Canto returned HTML/non-JSON for recent API");
        return [];
      }

      return d.items || [];
    } catch {
      return [];
    }
  }

  // Wait for ingestion
  await new Promise(r => setTimeout(r, 1500));

  // Pass 1: search API
  for (let i = 0; i < tries; i++) {
    const list = await searchByName();
    const found = list.find(matches);
    if (found) return found;

    await new Promise(r => setTimeout(r, delayMs));
  }

  // Pass 2: recent files API
  for (let i = 0; i < tries; i++) {
    const list = await fetchRecent();
    const found = list.find(matches);
    if (found) return found;

    await new Promise(r => setTimeout(r, delayMs));
  }

  throw new Error("Uploaded file not found after polling");
}


/**
 * Step 3 – Patch metadata using batch edit
 * Auto-detects whether the tenant supports metadata write API.
 * If the tenant returns HTML (login page), metadata is skipped gracefully.
 */
async function cantoPatchMetadataV2(domain, accessToken, assetId, metadata = {}) {
  if (!metadata || Object.keys(metadata).length === 0) {
    return { ok: true, skipped: true };
  }

  const base = tenantApiBase(domain);

  const body = {
    fileIds: [assetId],
    metadata
  };

  const r = await fetch(`${base}/api/v1/files/batch/edit/apply`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const parsed = await safeJson(r);

  // HTML → metadata API disabled by tenant configuration
  if (parsed.__html) {
    console.warn(`⚠️ Metadata API disabled for ${domain}`);
    return {
      ok: true,
      skipped: true,
      reason: "metadata API disabled (HTML response)",
      raw: parsed.__html
    };
  }

  // Non-JSON → soft skip
  if (parsed.__raw) {
    return {
      ok: true,
      skipped: true,
      reason: "non-JSON metadata response",
      raw: parsed.__raw
    };
  }

  if (!r.ok) {
    return {
      ok: false,
      skipped: true,
      reason: "metadata API rejected request",
      error: parsed
    };
  }

  return { ok: true, patched: true, response: parsed };
}


/**
 * Step 4 – Combined: upload physical file + find it + patch metadata
 */
async function cantoUploadFileV2(domain, accessToken, file, metadata = {}) {
  const filename = file.originalname || file.name;

  // mark upload start time for ingestion filtering
  const uploadStartMs = Date.now();

  // 1) request upload slot
  const setting = await cantoRequestUploadSlot(domain, accessToken, filename);

  if (!setting?.uploadUrl || !setting?.fileKey) {
    throw new Error("Invalid Canto upload-setting response");
  }

  // 2) upload to S3 (putObject)
  const uploadR = await fetch(setting.uploadUrl, {
    method: "PUT",
    headers: {
      "Content-Type": file.mimetype || "application/octet-stream",
    },
    body: file.buffer
  });

  if (!uploadR.ok) {
    const t = await uploadR.text();
    throw new Error(`S3 upload failed: ${t}`);
  }

  // 3) find ingested asset
  const found = await cantoFindUploadedFileV2(
    domain,
    accessToken,
    { filename, uploadStartMs }
  );

  // 4) patch metadata
  const metaRes = await cantoPatchMetadataV2(domain, accessToken, found.id, metadata);

  return {
    ok: true,
    domain,
    version: "v2",
    filename,
    found,
    metadataStatus: metaRes
  };
}

/* ================================================================
   Unified Upload Dispatcher — uploadToCanto()
   Chooses v2 or v3 depending on domain
================================================================ */
async function uploadToCanto(domain, accessToken, { buffer, filename, mimeType, metadata }) {
  // Detect version first
  const version = await detectUploadVersion(domain, accessToken);

  if (version === "v2") {
    // v2 upload pipeline
    return await cantoUploadFileV2(
      domain,
      accessToken,
      {
        buffer,
        name: filename,
        originalname: filename,
        mimetype: mimeType
      },
      metadata
    );
  }

  // v3 pipeline
  const created = await cantoCreateUploadV3(accessToken, {
    filename,
    size: buffer.length,
    mimeType
  });

  await s3PutSignedUrl(created.uploadUrl, buffer, mimeType);

  const file = await cantoFinalizeFileV3(accessToken, {
    uploadId: created.uploadId,
    filename,
    metadata
  });

  return {
    ok: true,
    version: "v3",
    file
  };
}


/* ================================================================
   ROUTE: POST /upload
   Body: { domain, attachmentUrl, metadata? }
================================================================ */
app.post("/upload", async (req, res) => {
  const { domain, attachmentUrl, metadata } = req.body || {};
  if (!domain) return res.status(400).json({ error: "Missing domain" });
  if (!attachmentUrl) return res.status(400).json({ error: "Missing attachmentUrl" });

  try {
    // refresh canto token for this domain
    const token = await refreshCantoTokenIfNeeded(domain);
    if (!token?.access_token) return res.status(400).json({ error: "Canto token not found" });

    // fetch file bytes
    const dl = await fetch(attachmentUrl);
    if (!dl.ok) {
      return res.status(400).json({
        error: "Failed to download attachment",
        status: dl.status,
        text: await dl.text()
      });
    }
    const mimeType = dl.headers.get("content-type") || "application/octet-stream";
    const buffer = Buffer.from(await dl.arrayBuffer());
    const filename = filenameFromUrl(attachmentUrl);

    // mapping
    let meta = {};
    if (metadata) {
      try {
        meta = typeof metadata === "string" ? JSON.parse(metadata) : (metadata || {});
      } catch { meta = {}; }
    }
    const mapping = await getDomainMapping(domain);
    const mapped = applyFieldMapping(mapping, meta);

    // do upload
    const out = await uploadToCanto(domain, token.access_token, {
      buffer, filename, mimeType, metadata: mapped
    });

    // try to surface a view URL if present
    const assetUrl =
      out?.file?.url ||
      out?.file?.publicUrl ||
      out?.file?.links?.view ||
      out?.found?.links?.view ||
      null;

   res.json(
  scrubHtml({
    ok: true,
    version: out.version,
    domain,
    filename,
    assetUrl,
    cantoFile: out.file,
    found: out.found || null,
    metadataStatus: out.metadataStatus
  })
);

} catch (err) {
  console.error("UPLOAD ERROR:", err);

  return res.status(500).json(
    scrubHtml({
      ok: false,
      error: err && err.message ? err.message : String(err),
      stack: err && err.stack ? err.stack : null
    })
  );
}

});

/* ================================================================
   ROUTE: POST /test/upload-canto
   multipart: fields { domain }, file part { file }
================================================================ */
app.post("/test/upload-canto", async (req, res) => {
  const busboy = Busboy({ headers: req.headers });

  let domain, fileBuffer, fileName, mimeType;

  busboy.on("field", (name, val) => {
    if (name === "domain") domain = String(val || "").trim();
  });

  busboy.on("file", (name, file, info) => {
    const chunks = [];
    fileName = info.filename;
    mimeType = info.mimeType || "application/octet-stream";

    file.on("data", d => chunks.push(d));
    file.on("end", () => { fileBuffer = Buffer.concat(chunks); });
  });

  busboy.on("finish", async () => {
    if (!domain) return res.status(400).send("Missing domain");
    if (!fileBuffer) return res.status(400).send("Missing file");

    try {
      const token = await refreshCantoTokenIfNeeded(domain);
      if (!token?.access_token) {
        return res.status(400).json({ error: "Canto token not found" });
      }

      const out = await uploadToCanto(domain, token.access_token, {
        buffer: fileBuffer,
        filename: fileName,
        mimeType,
        metadata: {}
      });

      // ✅ WRAP response to prevent <html> exploding Express JSON
      return res.json(
        scrubHtml({
          ok: true,
          version: out.version,
          result: out
        })
      );

   } catch (err) {
  console.error("Test upload error:", err);

  return res.status(500).json(
    scrubHtml({
      ok: false,
      error: err && err.message ? err.message : String(err),
      stack: err && err.stack ? err.stack : null
    })
  );
}
 });

  req.pipe(busboy);
});

/* ================================================================
   STATUS API — ASANA (Dashboard uses this to avoid domain=asana)
================================================================ */
app.get("/status/asana", async (req, res) => {
  try {
    const t = await getToken("asana");

    if (!t) {
      return res.json({
        asana: { connected: false },
      });
    }

    // Always prefer DB-stored expires_at
    const expiresAt =
      t.expires_at ||
      (t.expires_in ? nowSec() + Number(t.expires_in) : null);

    res.json({
      asana: {
        connected: Boolean(t.access_token),
        expires_at: expiresAt,
        expires_at_iso: expiresAt ? new Date(expiresAt * 1000).toISOString() : null,
      },
    });
  } catch (err) {
    console.error("Asana status error:", err);
    res.status(500).json({ error: err.message });
  }
});


/* ================================================================
   STATUS API (full dashboard)
================================================================ */
app.get("/status/:domain", async (req, res) => {
  const { domain } = req.params;

  try {
    const cantoToken = await getToken(domain);
    const asanaToken = await getToken("asana");

    const mapping = cantoToken?.mapping || {};

    // ✅ ALWAYS use expires_at (no _expires_at)
    const expiresAt =
      cantoToken?.expires_at ||
      (cantoToken?.expires_in
        ? nowSec() + Number(cantoToken.expires_in)
        : null);

    // Upload version detection (cached or ping)
    let uploadVersion = cantoToken?.uploadVersion || null;

    if (!uploadVersion && cantoToken?.access_token) {
      const url = `https://${domain}.canto.com/api/v1/upload/setting`;

      try {
        const resp = await fetch(url, {
          headers: { Authorization: `Bearer ${cantoToken.access_token}` },
        });

        uploadVersion = resp.ok ? "v2" : "v3";
      } catch {
        uploadVersion = "v3";
      }

      await persistCantoRecord(domain, { uploadVersion });
    }

    res.json({
      domain,
      canto: {
        connected: Boolean(cantoToken?.access_token),
        expires_at: expiresAt,
        expires_at_iso: expiresAt ? new Date(expiresAt * 1000).toISOString() : null,
        has_refresh: Boolean(cantoToken?.refresh_token),
        uploadVersion,
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
        <p id="cantoUploadVer" class="mb-1">–</p>
      </div>

      <div class="bg-white rounded-lg shadow p-5">
        <h2 class="text-lg font-semibold mb-2">Asana Status</h2>
        <p id="asanaConnected" class="mb-1">–</p>
        <p id="asanaExpiry" class="mb-1">–</p>
      </div>

      <div class="bg-white rounded-lg shadow p-5">
        <h2 class="text-lg font-semibold mb-2">Mapping Status</h2>
        <p id="mappingCount" class="mb-1">–</p>
        <div class="flex gap-3">
          <a href="/mapping-ui/${domain}" class="mt-2 px-3 py-2 bg-slate-700 text-white rounded hover:bg-slate-800">
            Open Mapping UI
          </a>
          <button id="resetMappingBtn" class="mt-2 px-3 py-2 bg-red-600 text-white rounded hover:bg-red-700">
            Reset Mapping
          </button>
        </div>
      </div>
    </section>

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

    <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
      <div class="bg-white rounded-lg shadow p-6">
        <h2 class="text-xl font-semibold mb-4">Upload by URL</h2>
        <div class="flex flex-col gap-3">
          <input id="uploadUrl" class="border p-2 rounded" placeholder="https://example.com/file.jpg" />
          <textarea id="uploadMeta" class="border p-2 rounded" rows="4" placeholder='Optional metadata JSON'></textarea>
          <button id="uploadUrlBtn" class="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700">
            Upload URL → Canto
          </button>
        </div>
        <pre id="uploadUrlOut" class="mt-4 bg-gray-900 text-gray-100 p-3 rounded text-sm overflow-auto"></pre>
      </div>

      <div class="bg-white rounded-lg shadow p-6">
        <h2 class="text-xl font-semibold mb-4">Upload a File</h2>
        <div class="flex flex-col gap-3">
          <input id="uploadFileInput" type="file" class="border p-2 rounded bg-gray-50" />
          <button id="uploadFileBtn" class="px-4 py-2 bg-emerald-600 text-white rounded hover:bg-emerald-700">
            Upload File → Canto
          </button>
        </div>
        <pre id="uploadFileOut" class="mt-4 bg-gray-900 text-gray-100 p-3 rounded text-sm overflow-auto"></pre>
      </div>
    </section>

    <footer class="text-sm text-gray-500">
      <p>Asana ↔ Canto Integration for <strong>${domain}</strong>.</p>
    </footer>
  </div>

<script>
  const domain = "${domain}";
  let mapping = {};

  async function loadStatus() {
    const r1 = await fetch("/status/" + domain);
    const s1 = await r1.json();

    const r2 = await fetch("/status/asana");
    const s2 = await r2.json();

    document.getElementById("cantoConnected").textContent =
      "Connected: " + (s1.canto && s1.canto.connected ? "Yes ✅" : "No ❌");

    document.getElementById("cantoRefresh").textContent =
      "Refresh token: " + (s1.canto && s1.canto.has_refresh ? "Yes" : "No");

    document.getElementById("cantoUploadVer").textContent =
      "Upload API: " + ((s1.canto && s1.canto.uploadVersion) || "unknown");

    document.getElementById("cantoExpiry").textContent =
      (s1.canto && s1.canto.expires_at_iso)
        ? "Expires: " + new Date(s1.canto.expires_at_iso).toLocaleString()
        : "Expires: –";

    document.getElementById("asanaConnected").textContent =
      "Connected: " + (s2.asana && s2.asana.connected ? "Yes ✅" : "No ❌");

    document.getElementById("asanaExpiry").textContent =
      (s2.asana && s2.asana.expires_at_iso)
        ? "Expires: " + new Date(s2.asana.expires_at_iso).toLocaleString()
        : "Expires: –";

    document.getElementById("mappingCount").textContent =
      "Mappings: " + ((s1.mapping && s1.mapping.count) || 0);
  }

  async function loadMapping() {
    const r = await fetch("/mapping/" + domain);
    const d = await r.json();
    mapping = d.mapping || {};
    renderRows();
  }

  function renderRows() {
    const tbody = document.getElementById("mappingRows");
    tbody.innerHTML = "";

    const entries = Object.entries(mapping);
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="text-center p-3 text-gray-500">No mappings</td></tr>';
      return;
    }

    for (const [asana, canto] of entries) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        '<td class="p-3 border">' + asana + '</td>' +
        '<td class="p-3 border">' + canto + '</td>' +
        '<td class="p-3 border text-center">' +
          '<button type="button" class="px-2 py-1 bg-red-600 text-white rounded" onclick="removeMapping(\\'' + asana.replace(/'/g, "\\'") + '\\')">Delete</button>' +
        '</td>';
      tbody.appendChild(tr);
    }
  }

  window.removeMapping = function(asanaField) {
    delete mapping[asanaField];
    renderRows();
  };

  document.getElementById("addRowBtn").onclick = function() {
    const a = document.getElementById("newAsana").value.trim();
    const c = document.getElementById("newCanto").value.trim();
    if (!a || !c) { alert("Both fields required"); return; }
    mapping[a] = c;
    document.getElementById("newAsana").value = "";
    document.getElementById("newCanto").value = "";
    renderRows();
  };

  document.getElementById("saveMappingBtn").onclick = async function() {
    try {
      const r = await fetch("/mapping/" + domain, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(mapping),
      });
      if (!r.ok) throw new Error("Save failed: " + r.status);
      alert("✅ Mapping saved");
    } catch (e) {
      alert("❌ " + (e && e.message ? e.message : "Failed to save mapping"));
    }
  };

  document.getElementById("resetMappingBtn").onclick = async function() {
    if (!confirm("Reset all mappings?")) return;
    try {
      const r = await fetch("/mapping/" + domain, { method: "DELETE" });
      if (!r.ok) throw new Error("Reset failed: " + r.status);
      mapping = {};
      renderRows();
      alert("✅ Mapping reset");
    } catch (e) {
      alert("❌ " + (e && e.message ? e.message : "Failed to reset mapping"));
    }
  };

  document.getElementById("uploadUrlBtn").onclick = async function() {
    const url = document.getElementById("uploadUrl").value.trim();
    const meta = document.getElementById("uploadMeta").value.trim();

    if (!url) { alert("Provide a URL"); return; }

    let metadata = {};
    if (meta) {
      try { metadata = JSON.parse(meta); }
      catch { alert("Metadata must be valid JSON"); return; }
    }

    try {
      const r = await fetch("/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain, attachmentUrl: url, metadata: metadata }),
      });
      const txt = await r.text();
document.getElementById("uploadUrlOut").textContent =
  txt && txt.trim() !== "" ? txt : "✅ Upload completed successfully (no body returned)";

      loadStatus();
    } catch {
      document.getElementById("uploadUrlOut").textContent = "Request failed.";
    }
  };

  document.getElementById("uploadFileBtn").onclick = async function() {
    const input = document.getElementById("uploadFileInput");
    if (!input.files.length) { alert("Select a file"); return; }

    const fd = new FormData();
    fd.append("domain", domain);
    fd.append("file", input.files[0]);

    try {
      const r = await fetch("/test/upload-canto", { method: "POST", body: fd });
      const txt = await r.text();
document.getElementById("uploadFileOut").textContent =
  txt && txt.trim() !== "" ? txt : "✅ File upload completed successfully (no body returned)";

      loadStatus();
    } catch {
      document.getElementById("uploadFileOut").textContent = "Upload failed.";
    }
  };

  loadStatus();
  loadMapping();
</script>
</body>
</html>`);
});



/* ================================================================
   ASANA WEBHOOK HANDLER
================================================================ */
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
   START SERVER
================================================================ */
const port = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
  });
});
