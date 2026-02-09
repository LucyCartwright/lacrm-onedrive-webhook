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

  console.log("Webhook payload:", payload);
  return res.status(200).send("ok");
});

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Listening on ${port}`));
