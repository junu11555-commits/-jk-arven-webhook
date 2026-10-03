// JK ARVEN - Messenger Webhook (receive + log only)
// This server does NOT send any messages to customers.
// It does NOT log message text or postback payloads.

const express = require("express");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
// REQUIRED for receiving events. POST /webhook is rejected without it.
const APP_SECRET = process.env.APP_SECRET;

if (!VERIFY_TOKEN) {
  console.warn("WARNING: VERIFY_TOKEN is not set. Webhook verification will fail.");
}
if (!APP_SECRET) {
  console.warn(
    "WARNING: APP_SECRET is not set. POST /webhook will reject ALL events until it is set."
  );
}

// Parse JSON, but keep the raw bytes (needed for signature validation).
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Check Meta's signature header against the raw request body.
function isValidSignature(req) {
  const header = req.get("X-Hub-Signature-256");
  if (!header || !req.rawBody) return false;
  const expected =
    "sha256=" +
    crypto.createHmac("sha256", APP_SECRET).update(req.rawBody).digest("hex");
  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Build a safe summary of one messaging event.
// Only these fields are ever logged: type, senderId, recipientId,
// timestamp, mid (message ID), attachmentCount.
function summarizeEvent(event) {
  const summary = {
    type: "other",
    senderId: event.sender && event.sender.id,
    recipientId: event.recipient && event.recipient.id,
    timestamp: event.timestamp,
  };

  if (event.message) {
    summary.type = event.message.is_echo ? "echo" : "message";
    summary.mid = event.message.mid;
    summary.attachmentCount = Array.isArray(event.message.attachments)
      ? event.message.attachments.length
      : 0;
  } else if (event.postback) {
    summary.type = "postback"; // payload is intentionally NOT logged
  } else if (event.read) {
    summary.type = "read";
  } else if (event.delivery) {
    summary.type = "delivery";
  }
  return summary;
}

// Health check
app.get("/", (req, res) => {
  res.status(200).send("JK ARVEN webhook is running.");
});

// Webhook VERIFICATION (Meta calls this once when you save the webhook)
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (VERIFY_TOKEN && mode === "subscribe" && token === VERIFY_TOKEN) {
    console.log("Webhook verified successfully.");
    return res.status(200).send(challenge);
  }
  console.warn("Webhook verification failed.");
  return res.sendStatus(403);
});

// Webhook RECEIVING (Meta sends events here)
app.post("/webhook", (req, res) => {
  // 1. Refuse to run without a configured App Secret.
  if (!APP_SECRET) {
    console.error("Rejected POST: APP_SECRET is not configured on the server.");
    return res.sendStatus(503);
  }

  // 2. Reject anything that is not correctly signed by Meta.
  if (!isValidSignature(req)) {
    console.warn("Rejected POST: missing or invalid signature.");
    return res.sendStatus(403);
  }

  // 3. Basic shape check.
  const body = req.body;
  if (!body || body.object !== "page" || !Array.isArray(body.entry)) {
    return res.sendStatus(404);
  }

  // Reply to Meta immediately, then process.
  res.status(200).send("EVENT_RECEIVED");

  try {
    for (const entry of body.entry) {
      const events = Array.isArray(entry.messaging) ? entry.messaging : [];
      for (const event of events) {
        console.log("Messenger event:", JSON.stringify(summarizeEvent(event)));
      }
    }
  } catch (err) {
    console.error("Error while processing event:", err.name);
  }
});

// Malformed JSON and other errors must not crash the server.
// Only the error type is logged, because parser messages can echo request content.
app.use((err, req, res, next) => {
  console.error("Request error:", err.type || err.name || "unknown");
  if (res.headersSent) return next(err);
  res.status(400).json({ error: "Bad request" });
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
