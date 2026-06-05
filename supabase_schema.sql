-- Supabase SQL: create users and scan_history tables
-- Run these statements in the Supabase SQL Editor (SQL -> New Query)

-- 1) Users table
CREATE TABLE IF NOT EXISTS public.users (
  user_uuid uuid PRIMARY KEY,
  display_email text NOT NULL UNIQUE,
  encrypted_refresh_token text NOT NULL,
  active_monitoring boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- 2) Scan history table
CREATE TABLE IF NOT EXISTS public.scan_history (
  id bigserial PRIMARY KEY,
  user_uuid uuid NOT NULL REFERENCES public.users(user_uuid) ON DELETE CASCADE,
  message_id text NOT NULL,
  thread_id text,
  source text NOT NULL,
  sender text NOT NULL,
  subject text NOT NULL,
  risk_score integer NOT NULL DEFAULT 0,
  timestamp timestamptz NOT NULL DEFAULT now(),
  triggered_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'clean',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_uuid, message_id)
);

-- Helpful index for querying a user's recent scans quickly
CREATE INDEX IF NOT EXISTS idx_scan_history_user_timestamp ON public.scan_history (user_uuid, timestamp DESC);
