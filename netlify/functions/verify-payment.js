// ═══════════════════════════════════════════════════════════════
// AURAA — Flutterwave Payment Verification (Netlify Function)
// ═══════════════════════════════════════════════════════════════
//
// PURPOSE:
//   When a Flutterwave checkout completes on the client, we MUST NOT
//   trust the client's word for it. The browser callback can be
//   spoofed. Real payment confirmation requires a server-side call
//   to Flutterwave's GET /transactions/:id/verify endpoint, signed
//   with our SECRET key (which never touches the browser).
//
// FLOW:
//   1. Browser completes FlutterwaveCheckout → calls back with txn_id
//   2. Browser POSTs to this function: { tx_ref, transaction_id, expected_amount_kobo, ... }
//   3. We GET https://api.flutterwave.com/v3/transactions/{id}/verify
//      with Authorization: Bearer FLW_SECRET_KEY
//   4. We assert: status==='successful', currency==='NGN',
//      amount_kobo === expected_amount_kobo, tx_ref matches
//   5. Return { verified: true/false, ... } — browser only credits
//      the wallet when verified === true.
//
// SETUP REQUIRED IN NETLIFY DASHBOARD:
//   Site → Configuration → Environment variables → Add a variable:
//     Key:   FLW_SECRET_KEY
//     Value: <your Flutterwave LIVE secret key — starts FLWSECK-...>
//     Scope: All scopes (Functions, Builds, Runtime)
//   Then redeploy the site to load the env var.
//
// SECURITY:
//   - Secret key NEVER appears in client code, repo, or logs.
//   - Amount verified server-side prevents amount-tampering attacks.
//   - tx_ref verified server-side prevents transaction-replay attacks.
//   - On any verification failure, we return verified:false and an
//     error code. Client must NOT credit anything in that case.
// ═══════════════════════════════════════════════════════════════

exports.handler = async function(event, context) {
  // CORS / method guard
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'method_not_allowed' })
    };
  }

  const SECRET = process.env.FLW_SECRET_KEY;
  if (!SECRET) {
    console.error('[verify-payment] FLW_SECRET_KEY env var not set');
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'server_misconfigured' })
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (e) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'invalid_json' })
    };
  }

  const { tx_ref, transaction_id, expected_amount_kobo, user_email, user_fu_number, purpose } = payload;

  if (!tx_ref || !transaction_id || !expected_amount_kobo) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'missing_required_fields' })
    };
  }

  // Call Flutterwave's official verify endpoint.
  const verifyUrl = `https://api.flutterwave.com/v3/transactions/${encodeURIComponent(transaction_id)}/verify`;

  let flwResponse;
  try {
    const r = await fetch(verifyUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${SECRET}`,
        'Content-Type': 'application/json'
      }
    });
    flwResponse = await r.json();
  } catch (e) {
    console.error('[verify-payment] Flutterwave API call failed:', e);
    return {
      statusCode: 502,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'flutterwave_unreachable' })
    };
  }

  // Flutterwave's verify response shape:
  //   { status:'success', message:'...', data:{ status:'successful', amount: 5000, currency:'NGN', tx_ref:'...', id:12345, ... } }
  const data = flwResponse && flwResponse.data;

  if (!flwResponse || flwResponse.status !== 'success' || !data) {
    console.warn('[verify-payment] Flutterwave returned non-success:', flwResponse);
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verified: false,
        error: 'flutterwave_status_not_success',
        flw_message: flwResponse && flwResponse.message
      })
    };
  }

  // ─── Five hard assertions ────────────────────────────────────
  // 1. Transaction status must be 'successful'
  if (data.status !== 'successful') {
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verified: false,
        error: 'transaction_not_successful',
        flw_status: data.status
      })
    };
  }

  // 2. Currency must be NGN
  if (data.currency !== 'NGN') {
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'currency_mismatch', got: data.currency })
    };
  }

  // 3. tx_ref must match what client claimed
  if (data.tx_ref !== tx_ref) {
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verified: false, error: 'tx_ref_mismatch' })
    };
  }

  // 4. Amount must match (Flutterwave returns NGN amount; we compare in kobo)
  const flwAmountKobo = Math.round(Number(data.amount) * 100);
  const expectedKobo = Math.round(Number(expected_amount_kobo));
  if (flwAmountKobo !== expectedKobo) {
    console.warn('[verify-payment] Amount mismatch — possible tampering attempt', {
      tx_ref, expected: expectedKobo, actual: flwAmountKobo, user_email
    });
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verified: false,
        error: 'amount_mismatch',
        expected_kobo: expectedKobo,
        actual_kobo: flwAmountKobo
      })
    };
  }

  // 5. (Optional but recommended) Customer email matches what we expect
  // We log the discrepancy but don't fail verification on it, since
  // a guest checkout may not always pass the same email.
  if (user_email && data.customer && data.customer.email && data.customer.email.toLowerCase() !== user_email.toLowerCase()) {
    console.info('[verify-payment] Customer email differs from claimed user_email:', {
      claimed: user_email, on_transaction: data.customer.email
    });
  }

  // ─── All assertions passed — payment is real ──────────────────
  console.log('[verify-payment] ✅ Verified', {
    tx_ref,
    flw_tx_id: data.id,
    amount_ngn: data.amount,
    user_email,
    user_fu_number,
    purpose
  });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      verified: true,
      flw_tx_id: data.id,
      amount: data.amount,
      currency: data.currency,
      tx_ref: data.tx_ref,
      payment_type: data.payment_type,
      charged_at: data.created_at
    })
  };
};
