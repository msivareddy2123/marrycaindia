-- Payments (Razorpay). Run once in the Supabase SQL Editor.
do $mig$ begin
execute $f$
create table if not exists public.payments (
  id bigserial primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  plan text not null check (plan in ('3m','1y')),
  amount integer not null,
  order_id text not null unique,
  payment_id text unique,
  status text not null default 'created' check (status in ('created','paid','failed')),
  created_at timestamptz not null default now(),
  paid_at timestamptz
)
$f$;
execute $f$ alter table public.payments enable row level security $f$;
execute $f$ revoke all on public.payments from anon, authenticated $f$;
execute $f$ grant select on public.payments to authenticated $f$;
execute $f$ drop policy if exists payments_own on public.payments $f$;
execute $f$ create policy payments_own on public.payments for select to authenticated using (user_id = auth.uid()) $f$;
end $mig$;
