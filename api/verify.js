import crypto from "crypto";
import fetch from "node-fetch";
import { kv } from "@vercel/kv";

export default async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({ status: "method_not_allowed" });
  }

  const BOT_TOKEN = process.env.BOT_TOKEN;

  if (!BOT_TOKEN) {
    return res.status(500).json({ status: "bot_token_missing" });
  }

  const { initData, deviceId } = req.body;

  if (!initData || !deviceId) {
    return res.status(400).json({ status: "missing_data" });
  }

  // ---------------- TELEGRAM SIGNATURE VERIFY ----------------
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort()
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = crypto.createHash("sha256")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto.createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (calculatedHash !== hash) {
    return res.status(403).json({ status: "invalid_signature" });
  }

  const user = JSON.parse(params.get("user"));
  const userId = user.id;

  // ---------------- AUTH DATE CHECK ----------------
  const authDate = parseInt(params.get("auth_date"));
  const now = Math.floor(Date.now() / 1000);

  if (now - authDate > 300) {
    return res.status(403).json({ status: "expired" });
  }

  // ---------------- VPN CHECK ----------------
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  try {
    const vpnRes = await fetch(`https://ipapi.co/${ip}/json/`);
    const vpnData = await vpnRes.json();

    if (vpnData.proxy === true || vpnData.security?.vpn === true) {
      return res.status(403).json({ status: "vpn_blocked" });
    }

  } catch (err) {
    return res.status(500).json({ status: "vpn_check_failed" });
  }

  // ---------------- DEVICE BINDING ----------------
  const existing = await kv.get(`user:${userId}`);

  if (existing) {

    if (existing.deviceId !== deviceId) {

      await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: userId,
          text: "⚠️ Device change detected.\nAccess blocked."
        })
      });

      return res.status(403).json({ status: "device_changed_blocked" });
    }

  } else {

    await kv.set(`user:${userId}`, {
      verified: true,
      deviceId: deviceId,
      ip: ip,
      createdAt: Date.now()
    });

  }

  // ---------------- SEND VERIFIED SIGNAL ----------------
  await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: userId,
      text: "✅ Network Verified Successfully.\nYou can now use the bot."
    })
  });

  return res.status(200).json({ status: "success" });
    }
