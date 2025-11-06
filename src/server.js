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
const CANTO_AUTH_URL =
  `${CANTO_BASE}/oauth/api/oauth2/compatible/authorize`;
const CANTO_TOKEN_URL =
  `${CANTO_BASE}/oauth/api/oauth2/token`;
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
  try { data = JSON.parse(raw); }
  catch { throw new Error("Canto refresh returned non-JSON"); }

  if (!resp.ok || data.error) {
    console.error("Canto refresh failed:", data);
    return td;
  }

  data._expires_at = nowSec() + Number(data.expires_in || 3500);
  await persistCantoToken(domain, { ...td, ...data });
  return loadCantoToken(domain);
}

async function cantoCreateUpload(domain, accessToken, { filename, size, mimeType }) {
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
  let data;
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

  if (!r.ok) {
    console.error("[CANTO create upload] error:", r.status, data);
    throw new Error("Canto /uploads failed");
  }

  if (!data.uploadId || !data.uploadUrl) {
    throw new Error("Canto /uploads missing uploadId/uploadUrl");
  }

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
  try { data = JSON.parse(text); } catch { data = { raw: text }; }

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
  const tokenRecord = await getToken(domain) || {};
  tokenRecord.mapping = mapping;
  await saveToken(domain, tokenRecord);
  return mapping;
}

function applyFieldMapping(mapping, metadata) {
  const out = { ...metadata };

  for (const [asanaField, cantoField] of Object.entries(mapping || {})) {
    if (metadata.hasOwnProperty(asanaField)) {
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
      return res.status(400).send("Asana token exchange failed: " + JSON.stringify(tokenData));
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

    const resp = await fetch(CANTO_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    const raw = await resp.text();
    let data;
    try { data = JSON.parse(raw); }
    catch { return res.status(400).send("Canto token response was not JSON"); }

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
      try { metaObj = JSON.parse(metadata); } catch {}
    } else if (metadata && typeof metadata === "object") {
      metaObj = metadata;
    }

    // C) Apply per-domain field mapping
    const domainMapping = await getDomainMapping(domain);
    metaObj = applyFieldMapping(domainMapping, metaObj);

    // D) Create upload
    const created = await cantoCreateUpload(domain, tokenData.access_token, {
      filename, size: buf.length, mimeType,
    });

    // E) Put to S3
    await cantoPutToS3(created.uploadUrl, buf, mimeType);

    // F) Finalize
    const file = await cantoFinalizeFile(domain, tokenData.access_token, {
      uploadId: created.uploadId,
      filename,
      metadata: metaObj,
    });

    const assetUrl =
      file?.url || file?.publicUrl || file?.links?.view || null;

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

/* ---------------------------------------------------------------
   START SERVER
---------------------------------------------------------------- */
const port = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(port, () =>
    console.log(`🚀 Server running on port ${port}`)
  );
});
