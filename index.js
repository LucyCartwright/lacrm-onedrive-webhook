import express from "express";
import crypto from "crypto";
import { Firestore } from "@google-cloud/firestore";

/**
 * Cloud Run service that does two jobs:
 * 1) LACRM webhook receiver (POST /) -> create OneDrive folder + write URL back to LACRM contact
 * 2) TidyCal polling endpoint (POST /tidycal-sync) -> create/update LACRM contact + pipeline item
 *
 * Notes:
 * - We keep RAW bodies because LACRM signs the webhook payload and we must hash the exact bytes.
 * - /tidycal-sync is protected by a shared header token (X-Job-Token) so only Cloud Scheduler (or you) can call it.
 */

const app = express();
app.use(express.raw({ type: "*/*" })); // raw body required for HMAC signature verification

const db = new Firestore();

// -----------------------------------------------------------------------------
// Small utilities
// -----------------------------------------------------------------------------

function timingSafeEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function safeIso(d) {
  return new Date(d).toISOString();
}

function safeFolderName(name) {
  // Avoid characters that can cause trouble in OneDrive names
  return (name || "New Contact")
    .replace(/[\\\/:\*\?"<>\|#%]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 100);
}

/**
 * Format booking time as "HH:mm dd/mm/yy" in the booking's timezone (or Europe/London fallback).
 */
function formatBookingDateTime(startsAtIso, timeZone) {
  if (!startsAtIso) return "";
  const dt = new Date(startsAtIso);
  const tz = timeZone || "Europe/London";

  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: tz,
    hour: "2-digit",
    minute: "2-digit",
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
    hour12: false,
  }).formatToParts(dt);

  const get = (type) => parts.find((p) => p.type === type)?.value || "";
  return `${get("hour")}:${get("minute")} ${get("day")}/${get("month")}/${get("year")}`;
}

/**
 * Parse TidyCal questions for your specific two-question setup.
 *
 * We assume:
 * - Mailing-list question contains "mailing" in its title and answer is "Yes please" or "No thank you"
 * - Meeting-prep question contains "meeting" in its title and answer is long text
 *
 * Order is unpredictable; we match by keywords only.
 */
function parseTidycalQuestions(questions) {
  let blogAnswer = ""; // "Yes please" or "No thank you"
  let userMessage = ""; // long text

  if (!Array.isArray(questions)) return { blogAnswer, userMessage };

  const getQText = (qa) =>
    (qa?.question ?? qa?.label ?? qa?.text ?? qa?.name ?? "").toString();

  const getAnswer = (qa) => (qa?.answer ?? "").toString().trim();

  for (const qa of questions) {
    const qText = getQText(qa).toLowerCase();
    const answer = getAnswer(qa);
    if (!answer) continue;

    if (qText.includes("mailing")) {
      const a = answer.toLowerCase();
      if (a === "yes please" || a === "no thank you") {
        blogAnswer = answer;
      }
      continue;
    }

    if (qText.includes("meeting")) {
      userMessage = answer;
      continue;
    }
  }

  return { blogAnswer, userMessage };
}

// -----------------------------------------------------------------------------
// Simple auth for the scheduler-triggered endpoint
// -----------------------------------------------------------------------------

function requireJobToken(req, res) {
  const expected = process.env.JOB_TOKEN;
  if (!expected) return res.status(500).send("Missing JOB_TOKEN env var");
  const got = req.header("X-Job-Token") || "";
  if (got !== expected) return res.status(403).send("Forbidden");
  return null;
}

// -----------------------------------------------------------------------------
// External API helpers: LACRM, TidyCal, Microsoft Graph (OneDrive)
// -----------------------------------------------------------------------------

async function lacrmCall(functionName, parameters) {
  const res = await fetch("https://api.lessannoyingcrm.com/v2/", {
    method: "POST",
    headers: {
      Authorization: process.env.LACRM_API_TOKEN,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ Function: functionName, Parameters: parameters }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`LACRM HTTP ${res.status}: ${JSON.stringify(data)}`);
  if (data.ErrorCode) throw new Error(`LACRM ${data.ErrorCode}: ${data.ErrorDescription}`);
  return data;
}

async function tidycalFetchBookings() {
  const res = await fetch("https://tidycal.com/api/bookings", {
    method: "GET",
    headers: { Authorization: `Bearer ${process.env.TIDYCAL_API_KEY}` },
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`TidyCal HTTP ${res.status}: ${text.slice(0, 300)}`);

  const data = JSON.parse(text);
  if (Array.isArray(data)) return data;
  if (Array.isArray(data.data)) return data.data;
  if (Array.isArray(data.bookings)) return data.bookings;
  throw new Error("Unexpected TidyCal response shape");
}

async function getMsAccessToken() {
  const tokenUrl = `https://login.microsoftonline.com/${process.env.MS_TENANT_ID}/oauth2/v2.0/token`;

  const form = new URLSearchParams();
  form.set("client_id", process.env.MS_CLIENT_ID);
  form.set("client_secret", process.env.MS_CLIENT_SECRET);
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", process.env.MS_REFRESH_TOKEN);

  // Delegated flow: ask for delegated scopes (offline_access included for refresh-token longevity)
  form.set("scope", "offline_access https://graph.microsoft.com/Files.ReadWrite.All");

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  const data = await res.json();
  if (!res.ok || data.error) throw new Error(`MS token error: ${JSON.stringify(data)}`);
  return data.access_token;
}

async function createOneDriveFolder(folderName) {
  const accessToken = await getMsAccessToken();

  const url = `https://graph.microsoft.com/v1.0/me/drive/items/${process.env.ONEDRIVE_CLIENTS_FOLDER_ID}/children`;
  const body = {
    name: safeFolderName(folderName),
    folder: {},
    "@microsoft.graph.conflictBehavior": "rename",
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const data = await res.json();
  if (!res.ok || data.error) throw new Error(`Graph error: ${JSON.stringify(data)}`);

  return { webUrl: data.webUrl, id: data.id, name: data.name };
}

// -----------------------------------------------------------------------------
// Firestore state for polling dedupe
// -----------------------------------------------------------------------------

async function getLastSyncIso() {
  const snap = await db.doc("syncState/tidycal").get();
  return snap.exists ? snap.data()?.lastSyncIso : null;
}

async function setLastSyncIso(iso) {
  await db.doc("syncState/tidycal").set({ lastSyncIso: iso }, { merge: true });
}

async function wasProcessed(bookingId) {
  const snap = await db.doc(`processedBookings/${bookingId}`).get();
  return snap.exists;
}

async function markProcessed(bookingId, createdAtIso) {
  await db.doc(`processedBookings/${bookingId}`).set({
    createdAtIso,
    processedAtIso: new Date().toISOString(),
  });
}

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

// Health check
app.get("/", (req, res) => res.status(200).send("alive"));

/**
 * LACRM Webhook receiver
 * - Handshake: echo X-Hook-Secret header
 * - Verify payload signature: X-Hook-Signature = HMAC-SHA256(rawBody, hookSecret)
 * - On Contact.Create: create OneDrive folder & update contact field with URL
 */
app.post("/", async (req, res) => {
  // Handshake
  const hookSecret = req.header("X-Hook-Secret");
  if (hookSecret) {
    console.log("LACRM handshake hook secret received");
    res.set("X-Hook-Secret", hookSecret);
    return res.status(200).send("ok");
  }

  // Verify signature
  const storedSecret = process.env.LACRM_HOOK_SECRET;
  if (!storedSecret) return res.status(500).send("Missing LACRM_HOOK_SECRET env var");

  const sigHeader = req.header("X-Hook-Signature") || "";
  const rawBody = req.body; // Buffer
  const computed = crypto.createHmac("sha256", storedSecret).update(rawBody).digest("hex");

  if (!timingSafeEq(computed, sigHeader)) return res.status(401).send("Bad signature");

  // Parse JSON payload
  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return res.status(400).send("Invalid JSON");
  }

  // Only handle Contact.Create
  if (payload.TriggeringEvent !== "Contact.Create" || !payload.Contacts?.length) {
    return res.status(200).send("ignored");
  }

  try {
    const contactId = payload.Contacts[0].ContactId;

    const contact = await lacrmCall("GetContact", { ContactId: contactId });

    // Build a sensible folder name from contact fields
    const nameObj = contact?.Name;
    const displayName =
      typeof nameObj === "string"
        ? nameObj
        : nameObj?.FirstName || nameObj?.LastName
          ? `${nameObj?.FirstName || ""} ${nameObj?.LastName || ""}`.trim()
          : contact?.CompanyName || "New Contact";

    const folder = await createOneDriveFolder(displayName);

    const fieldKey = process.env.LACRM_ONEDRIVE_FIELD; // e.g. "OneDrive"
    await lacrmCall("EditContact", { ContactId: contactId, [fieldKey]: folder.webUrl });

    console.log("Webhook success:", { contactId, folderUrl: folder.webUrl });
    return res.status(200).send("ok");
  } catch (err) {
    console.error("Webhook handler error:", err?.message || err);
    return res.status(500).send("error");
  }
});

/**
 * TidyCal polling sync
 * - Protected by X-Job-Token
 * - Fetch bookings, filter by created_at after last sync (with overlap)
 * - Strong idempotency by bookingId stored in Firestore
 * - Create/update LACRM contact and pipeline item
 * - Set Blog field based on mailing-list question ("Yes please"/"No thank you")
 */
app.post("/tidycal-sync", async (req, res) => {
  const authErr = requireJobToken(req, res);
  if (authErr) return;

  const nowIso = new Date().toISOString();
  const overlapMs = 2 * 60 * 1000; // 2 minute overlap to avoid edge misses

  try {
    const lastSyncIso = await getLastSyncIso();
    const lastSyncDate = lastSyncIso ? new Date(lastSyncIso) : new Date(Date.now() - 60 * 60 * 1000);
    const cutoff = new Date(lastSyncDate.getTime() - overlapMs);

    const bookings = await tidycalFetchBookings();

    // Filter: recent and not cancelled
    const candidates = bookings.filter((b) => {
      if (!b?.id || !b?.created_at) return false;
      if (b.cancelled_at) return false;
      return new Date(b.created_at) > cutoff;
    });

    let createdContacts = 0,
      updatedContacts = 0,
      pipelineItems = 0,
      skipped = 0;

    const blogFieldKey = process.env.LACRM_BLOG_FIELD || "Blog";

    for (const booking of candidates) {
      const bookingId = String(booking.id);

      // Strong idempotency: never process the same booking twice
      if (await wasProcessed(bookingId)) {
        skipped++;
        continue;
      }

      const contact = booking.contact || {};
      const email = (contact.email || "").trim();
      const name = (contact.name || "").trim();

      if (!email) {
        // Mark as processed so it doesn't loop forever
        await markProcessed(bookingId, safeIso(booking.created_at));
        skipped++;
        continue;
      }

      // Parse the two questions (order doesn't matter)
      const { blogAnswer, userMessage } = parseTidycalQuestions(booking.questions);

      // Find existing contact by email
      const search = await lacrmCall("GetContacts", { SearchTerms: email });
      const results = search?.Results || [];
      const match = results.find(
        (c) =>
          Array.isArray(c.Email) &&
          c.Email.some((e) => (e.Text || "").toLowerCase() === email.toLowerCase())
      );

      let contactId;

      if (match?.ContactId) {
        contactId = match.ContactId;
        updatedContacts++;

        // Update Blog field if we have an answer
        if (blogAnswer) {
          await lacrmCall("EditContact", { ContactId: contactId, [blogFieldKey]: blogAnswer });
        }
      } else {
        // Create contact, including Blog field if present
        const createParams = {
          IsCompany: false,
          AssignedTo: process.env.LACRM_ASSIGNED_TO,
          Name: name || email,
          Email: email,
        };
        if (blogAnswer) createParams[blogFieldKey] = blogAnswer;

        const created = await lacrmCall("CreateContact", createParams);
        contactId = created.ContactId;
        createdContacts++;
      }

      // Build user-friendly booking info
      const formatted = formatBookingDateTime(booking.starts_at, booking.timezone);

      const infoLines = [
        `Date & Time: ${formatted}`,
        `Booking ID: ${bookingId}`,
        booking.timezone ? `Timezone: ${booking.timezone}` : null,
        booking.meeting_url ? `Meeting URL: ${booking.meeting_url}` : null,
      ]
        .filter(Boolean)
        .join("\n");

      // Create pipeline item
      const piped = await lacrmCall("CreatePipelineItem", {
        ContactId: contactId,
        PipelineId: process.env.LACRM_PIPELINE_ID,
        StatusId: process.env.LACRM_STATUS_ID,
        Note: `TidyCal booking - ${formatted}`,
        Info: infoLines,
        Message: userMessage || "",
      });

      if (piped?.PipelineItemId) pipelineItems++;

      // Mark processed for idempotency
      await markProcessed(bookingId, safeIso(booking.created_at));
    }

    // Update last sync at end (only after successful processing)
    await setLastSyncIso(nowIso);

    return res.status(200).json({
      ok: true,
      lastSyncWas: lastSyncIso,
      nowIso,
      fetched: bookings.length,
      candidates: candidates.length,
      createdContacts,
      updatedContacts,
      pipelineItems,
      skipped,
    });
  } catch (err) {
    console.error("tidycal-sync error:", err?.message || err);
    return res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

// IMPORTANT: listen after routes are registered
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Listening on ${port}`));
