-- ════════════════════════════════════════════════════════════════════
-- AURAA Pilot — Real Payment Audit Schema (v1.0)
-- Run this ONCE in: Supabase Dashboard → SQL Editor → New query → Run
-- 
-- Creates: wallet_transactions table (Flutterwave verified payments)
-- Locks:   RLS enabled with no policies = service role access only
--          (Netlify functions use service_role key; publishable key from
--           the frontend cannot read or write these rows.)
-- 
-- Safe to re-run: uses CREATE TABLE IF NOT EXISTS.
-- ════════════════════════════════════════════════════════════════════

-- ── 1. Table ─────────────────────────────────────────────────────────
create table if not exists public.wallet_transactions (
  id                    uuid primary key default gen_random_uuid(),

  -- Identity
  user_email            text not null,
  user_fu_number        int,                          -- denormalized for convenience

  -- Money (kobo for precision; ₦5,000 = 500000 kobo)
  amount_kobo           bigint not null check (amount_kobo > 0),
  currency              text not null default 'NGN',

  -- Flutterwave linkage
  flw_tx_ref            text not null unique,         -- our reference (idempotency key)
  flw_tx_id             bigint,                       -- Flutterwave's transaction id (post-verify)
  flw_status            text,                         -- 'successful' | 'failed' | 'pending'
  flw_payment_type      text,                         -- 'card' | 'ussd' | 'banktransfer' | etc.

  -- Audit
  raw_verify_response   jsonb,                        -- full FW verify response for forensics
  verified_at           timestamptz,
  created_at            timestamptz not null default now()
);

create index if not exists wallet_tx_email_idx  on public.wallet_transactions(user_email);
create index if not exists wallet_tx_status_idx on public.wallet_transactions(flw_status);
create index if not exists wallet_tx_created_idx on public.wallet_transactions(created_at desc);

-- ── 2. RLS lockdown ──────────────────────────────────────────────────
-- Enable RLS with NO policies. This means:
--   • Publishable key (used in frontend)  → cannot read or write
--   • Service role key (Netlify only)     → full access (bypasses RLS)
--
-- This is intentional. All wallet_transactions writes happen server-side
-- via /netlify/functions/verify-payment.js. The frontend never touches
-- this table directly — it only sees verification results in JSON form.

alter table public.wallet_transactions enable row level security;

-- ── 3. Sanity check ──────────────────────────────────────────────────
-- After running, verify:
--   select * from public.wallet_transactions limit 1;   -- should return 0 rows, no error
--   select count(*) from public.wallet_transactions;    -- should return 0
