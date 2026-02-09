import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.raw({ type: "*/*" })); // keep raw body for signature verification

function timingSafeEq(a, b) {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

app.get("/", (req, res) => res.status(200).send("alive"));

app.post("/", async (req, res) => {
  // Handshake: echo X-Hook-Secret header back
  const hookSecret = req.header("X-Hook-Secret");
  if (hookSecret) {
    console.log("LACRM handshake hook secret:", hookSecret);
    res.set("X-Hook-Secret", hookSecret);
    return res.status(200).send("ok");
  }

  // Verify signature for real events
  const storedSecret = process.env.LACRM_HOOK_SECRET;
  if (!storedSecret) return res.status(500).send("Missing LACRM_HOOK_SECRET env var");

  const sigHeader = req.header("X-Hook-Signature") || "";
  const rawBody = req.body; // Buffer
  const computed = crypto.createHmac("sha256", storedSecret).update(rawBody).digest("hex");

  if (!timingSafeEq(computed, sigHeader)) return res.status(401).send("Bad signature");

  // Parse JSON
  let payload;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return res.status(400).send("Invalid JSON");
  }

  // Only handle contact creation
  if (payload.TriggeringEvent !== "Contact.Create" || !payload.Contacts?.length) {
    console.log("Ignored event:", payload.TriggeringEvent);
    return res.status(200).send("ignored");
  }

  const contactId = payload.Contacts[0].ContactId;

  // Fetch full contact so we can name folder properly
  const contact = await lacrmCall("GetContact", { ContactId: contactId });

  // LACRM returns contact shape with Name; handle common cases
  const nameObj = contact?.Name;
  const displayName =
    typeof nameObj === "string" ? nameObj :
    nameObj?.FirstName || nameObj?.LastName ? `${nameObj?.FirstName || ""} ${nameObj?.LastName || ""}`.trim() :
    contact?.CompanyName || "New Contact";

  console.log("Creating folder for", contactId, displayName);

  // Create folder in OneDrive
  const folder = await createOneDriveFolder(displayName);
  console.log("Folder created", folder);

  // Update contact field in LACRM
  const fieldKey = process.env.LACRM_ONEDRIVE_FIELD; // e.g. "OneDrive"
  await lacrmCall("EditContact", { ContactId: contactId, [fieldKey]: folder.webUrl });

  console.log("Updated contact", contactId, "with", folder.webUrl);
  return res.status(200).send("ok");

});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Listening on ${port}`));

async function lacrmCall(functionName, parameters) {
  const res = await fetch("https://api.lessannoyingcrm.com/v2/", {
    method: "POST",
    headers: {
      "Authorization": process.env.LACRM_API_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ Function: functionName, Parameters: parameters })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`LACRM HTTP ${res.status}: ${JSON.stringify(data)}`);
  if (data.ErrorCode) throw new Error(`LACRM ${data.ErrorCode}: ${data.ErrorDescription}`);
  return data;
}

async function getMsAccessToken() {
  const tokenUrl = `https://login.microsoftonline.com/${process.env.MS_TENANT_ID}/oauth2/v2.0/token`;

  const form = new URLSearchParams();
  form.set("client_id", process.env.MS_CLIENT_ID);
  form.set("client_secret", process.env.MS_CLIENT_SECRET);
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", process.env.MS_REFRESH_TOKEN);
  form.set("scope", "https://graph.microsoft.com/.default offline_access");

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString()
  });

  const data = await res.json();
  if (!res.ok || data.error) throw new Error(`MS token error: ${JSON.stringify(data)}`);

  // If Microsoft returns a new refresh_token, you’d ideally update it.
  // For now we just use access_token; keep refresh token stable unless it changes.
  return data.access_token;
}

function safeFolderName(name) {
  return (name || "New Contact")
    .replace(/[\\\/:\*\?"<>\|#%]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 100);
}

async function createOneDriveFolder(folderName) {
  const accessToken = await getMsAccessToken();

  const url = `https://graph.microsoft.com/v1.0/me/drive/items/${process.env.ONEDRIVE_CLIENTS_FOLDER_ID}/children`;
  const body = {
    name: safeFolderName(folderName),
    folder: {},
    "@microsoft.graph.conflictBehavior": "rename"
  };

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  const data = await res.json();
  if (!res.ok || data.error) throw new Error(`Graph error: ${JSON.stringify(data)}`);

  return { webUrl: data.webUrl, id: data.id, name: data.name };
}
