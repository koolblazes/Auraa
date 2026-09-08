
function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default async (req, _context) => {
  if (req.method !== "POST") return json(405, { error: "Method not allowed" });

  const supabaseUrl = Netlify.env.get("SUPABASE_URL");
  const serviceKey = Netlify.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const flwSecret = Netlify.env.get("FLW_SECRET_KEY");

  if (!supabaseUrl || !serviceKey || !flwSecret) {
    return json(500, { error: "Pilot payment service is not configured" });
  }

  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return json(401, { error: "Authentication required" });

  const body = await req.json().catch(() => null) as any;
  const tripId = String(body?.trip_id || "");
  const txRef = String(body?.tx_ref || "");
  const transactionId = String(body?.transaction_id || "");
  if (!tripId || !txRef || !transactionId) return json(400, { error: "trip_id, tx_ref and transaction_id are required" });

  // Verify the caller's Supabase session.
  const userResp = await fetch(`${supabaseUrl}/auth/v1/user`, {
    headers: { apikey: serviceKey, Authorization: auth },
  });
  if (!userResp.ok) return json(401, { error: "Invalid session" });
  const user = await userResp.json() as any;

  const tripResp = await fetch(`${supabaseUrl}/rest/v1/pilot_trips?id=eq.${encodeURIComponent(tripId)}&select=id,rider_user_id,rider_email,fare,currency,payment_status,status,payment_tx_ref`, {
    headers: { apikey: serviceKey, Authorization: `Bearer ${serviceKey}` },
  });
  const trips = await tripResp.json() as any[];
  const trip = trips?.[0];
  if (!trip) return json(404, { error: "Pilot trip not found" });
  if (String(trip.rider_user_id) !== String(user.id)) return json(403, { error: "Trip does not belong to this user" });
  if (trip.status !== "searching") return json(409, { error: "Trip is no longer awaiting payment" });
  if (trip.payment_status === "verified") return json(200, { verified: true, idempotent: true });

  const flwResp = await fetch(`https://api.flutterwave.com/v3/transactions/${encodeURIComponent(transactionId)}/verify`, {
    headers: { Authorization: `Bearer ${flwSecret}`, "Content-Type": "application/json" },
  });
  const flw = await flwResp.json().catch(() => null) as any;
  const data = flw?.data;
  const expectedAmount = Number(trip.fare);
  const paidAmount = Number(data?.amount ?? data?.charged_amount ?? 0);

  const ok =
    flwResp.ok &&
    flw?.status === "success" &&
    data?.status === "successful" &&
    String(data?.tx_ref || "") === txRef &&
    String(data?.currency || "").toUpperCase() === String(trip.currency || "NGN").toUpperCase() &&
    paidAmount >= expectedAmount;

  if (!ok) return json(402, { verified: false, error: "Flutterwave verification failed" });

  const rpcResp = await fetch(`${supabaseUrl}/rest/v1/rpc/pilot_mark_payment_verified`, {
    method: "POST",
    headers: {
      apikey: serviceKey,
      Authorization: `Bearer ${serviceKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      p_trip_id: tripId,
      p_tx_ref: txRef,
      p_transaction_id: transactionId,
      p_provider: "flutterwave",
    }),
  });
  const verified = await rpcResp.json().catch(() => false);

  if (!rpcResp.ok || verified !== true) {
    return json(409, { verified: false, error: "Payment was verified but could not be attached to the pilot trip" });
  }

  return json(200, {
    verified: true,
    trip_id: tripId,
    transaction_id: transactionId,
    tx_ref: txRef,
  });
};

export const config = {
  path: "/.netlify/functions/pilot-verify-payment",
};
