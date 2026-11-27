import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
// Prices are fixed here on the server. The website can never change them.
const PLANS: Record<string, { amount: number; days: number; label: string }> = {
  "3m": { amount: 149900, days: 92, label: "MarryCAindia 3 months" },
  "1y": { amount: 499900, days: 365, label: "MarryCAindia 1 year" },
};
const out = (o: unknown) =>
  new Response(JSON.stringify(o), { status: 200, headers: { ...cors, "Content-Type": "application/json" } });

async function hmacHex(secret: string, msg: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function same(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const keyId = Deno.env.get("RAZORPAY_KEY_ID")!;
    const keySecret = Deno.env.get("RAZORPAY_KEY_SECRET")!;
    if (!keyId || !keySecret) return out({ error: "Payments are not set up yet." });

    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const { data: u, error: ue } = await admin.auth.getUser(token);
    if (ue || !u?.user) return out({ error: "Please log in again." });
    const uid = u.user.id;
    const body = await req.json();

    if (body.action === "order") {
      const plan = PLANS[body.plan];
      if (!plan) return out({ error: "Unknown plan." });
      const r = await fetch("https://api.razorpay.com/v1/orders", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Basic " + btoa(keyId + ":" + keySecret) },
        body: JSON.stringify({
          amount: plan.amount,
          currency: "INR",
          receipt: "mci_" + uid.slice(0, 8) + "_" + Date.now(),
          notes: { user_id: uid, plan: body.plan },
        }),
      });
      const o = await r.json();
      if (!r.ok || !o.id) return out({ error: "Could not start payment. Please try again." });
      const ins = await admin.from("payments").insert({ user_id: uid, plan: body.plan, amount: plan.amount, order_id: o.id });
      if (ins.error) return out({ error: "Could not save the order. Please try again." });
      return out({ order_id: o.id, amount: plan.amount, currency: "INR", key: keyId, label: plan.label });
    }

    if (body.action === "verify") {
      const oid = String(body.razorpay_order_id || "");
      const pid = String(body.razorpay_payment_id || "");
      const sig = String(body.razorpay_signature || "");
      const expect = await hmacHex(keySecret, oid + "|" + pid);
      if (!oid || !pid || !same(expect, sig)) return out({ error: "Payment could not be verified." });

      const { data: row } = await admin.from("payments").select("*").eq("order_id", oid).eq("user_id", uid).maybeSingle();
      if (!row) return out({ error: "Order not found." });
      const { data: prof } = await admin.from("profiles").select("paid_until").eq("id", uid).maybeSingle();
      if (row.status === "paid") return out({ ok: true, paid_until: prof?.paid_until || null });

      const upd = await admin.from("payments")
        .update({ status: "paid", payment_id: pid, paid_at: new Date().toISOString() })
        .eq("id", row.id).eq("status", "created");
      if (upd.error) return out({ error: "Could not save the payment." });

      const days = PLANS[row.plan].days;
      const now = Date.now();
      const cur = prof?.paid_until ? new Date(prof.paid_until).getTime() : 0;
      const until = new Date(Math.max(now, cur) + days * 86400000).toISOString();
      const pu = await admin.from("profiles").update({ paid_until: until }).eq("id", uid);
      if (pu.error) return out({ error: "Payment received but activation failed. Please contact support." });
      return out({ ok: true, paid_until: until });
    }
    return out({ error: "Bad request." });
  } catch (_e) {
    return out({ error: "Something went wrong. Please try again." });
  }
});
