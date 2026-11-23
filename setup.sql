-- =====================================================
-- PAANI SUPPLY APP : Supabase database setup
-- Supabase > SQL Editor mein yeh poora paste kar ke RUN karein (sirf ek dafa)
-- =====================================================

create table if not exists public.shops (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text default '',
  modules jsonb not null default '{"bottle":true,"tank":false,"plant":false}',
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  name text default '',
  role text not null check (role in ('admin','owner','worker')),
  shop_id uuid references public.shops(id) on delete cascade,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Har cheez (customer, delivery, payment, kharcha, plant) isi ek table mein
create table if not exists public.records (
  id uuid primary key default gen_random_uuid(),
  shop_id uuid not null references public.shops(id) on delete cascade,
  kind text not null,
  day date not null default current_date,
  data jsonb not null default '{}',
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);
create index if not exists records_shop_kind on public.records (shop_id, kind, day);

-- ---------- helper functions ----------
create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as
$$ select role from profiles where id = auth.uid() and active $$;

create or replace function public.my_shop() returns uuid
language sql stable security definer set search_path = public as
$$ select p.shop_id from profiles p join shops s on s.id = p.shop_id
   where p.id = auth.uid() and p.active and s.active $$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as
$$ select coalesce((select role = 'admin' from profiles where id = auth.uid() and active), false) $$;

-- ---------- security (RLS) ----------
alter table public.shops enable row level security;
alter table public.profiles enable row level security;
alter table public.records enable row level security;

drop policy if exists shops_read on public.shops;
create policy shops_read on public.shops for select to authenticated
  using (is_admin() or id = (select shop_id from profiles where id = auth.uid()));
drop policy if exists shops_admin on public.shops;
create policy shops_admin on public.shops for all to authenticated
  using (is_admin()) with check (is_admin());

drop policy if exists prof_read on public.profiles;
create policy prof_read on public.profiles for select to authenticated
  using (id = auth.uid() or is_admin() or (my_role() = 'owner' and shop_id = my_shop()));
drop policy if exists prof_admin on public.profiles;
create policy prof_admin on public.profiles for all to authenticated
  using (is_admin()) with check (is_admin());
-- Malik apne ladkon (worker) ka login bana / band kar sakta hai
drop policy if exists prof_owner_ins on public.profiles;
create policy prof_owner_ins on public.profiles for insert to authenticated
  with check (my_role() = 'owner' and role = 'worker' and shop_id = my_shop());
drop policy if exists prof_owner_upd on public.profiles;
create policy prof_owner_upd on public.profiles for update to authenticated
  using (my_role() = 'owner' and role = 'worker' and shop_id = my_shop())
  with check (role = 'worker' and shop_id = my_shop());

-- Records: sirf apni shop ka data. Ladka kharcha aur plant ka hisaab nahi dekh sakta.
drop policy if exists rec_read on public.records;
create policy rec_read on public.records for select to authenticated
  using (shop_id = my_shop() and (my_role() = 'owner' or kind not in ('expense','plant','sale')));
drop policy if exists rec_ins on public.records;
create policy rec_ins on public.records for insert to authenticated
  with check (shop_id = my_shop() and (my_role() = 'owner' or kind in ('customer','delivery','payment')));
drop policy if exists rec_upd on public.records;
create policy rec_upd on public.records for update to authenticated
  using (shop_id = my_shop() and (my_role() = 'owner' or (kind = 'customer')))
  with check (shop_id = my_shop());
drop policy if exists rec_del on public.records;
create policy rec_del on public.records for delete to authenticated
  using (shop_id = my_shop() and (my_role() = 'owner' or (created_by = auth.uid() and day = current_date)));

-- =====================================================
-- AAKHRI QADAM: apne aap ko ADMIN banana
-- 1) Supabase > Authentication > Users > "Add user" se apni email + password banayein
-- 2) Neeche APNI-EMAIL ki jagah wohi email likh kar yeh line alag se RUN karein:
--
-- insert into public.profiles (id, email, name, role)
-- select id, email, 'Admin', 'admin' from auth.users where email = 'APNI-EMAIL@gmail.com';
-- =====================================================

-- =====================================================
-- UPDATE 2: delete ki jagah chhupana (soft delete) + admin backup
-- =====================================================
alter table public.records add column if not exists deleted_at timestamptz;
alter table public.records add column if not exists deleted_by uuid;
alter policy rec_read on public.records
  using (deleted_at is null and shop_id = my_shop() and (my_role() = 'owner' or kind not in ('expense','plant','sale')));
alter policy rec_del on public.records using (false);
drop policy if exists rec_admin_read on public.records;
create policy rec_admin_read on public.records for select to authenticated using (is_admin());

create or replace function public.soft_delete(rec uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  update records set deleted_at = now(), deleted_by = auth.uid()
   where id = rec and deleted_at is null and shop_id = my_shop()
     and (my_role() = 'owner' or (created_by = auth.uid() and day = current_date and kind in ('delivery','payment')));
  get diagnostics n = row_count;
  return n > 0;
end $$;

create or replace function public.restore_record(rec uuid) returns boolean
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not is_admin() then return false; end if;
  update records set deleted_at = null, deleted_by = null where id = rec;
  get diagnostics n = row_count;
  return n > 0;
end $$;
revoke execute on function public.soft_delete(uuid) from anon, public;
revoke execute on function public.restore_record(uuid) from anon, public;
grant execute on function public.soft_delete(uuid) to authenticated;
grant execute on function public.restore_record(uuid) to authenticated;

-- =====================================================
-- UPDATE 3: malik PIN / settings / ladkay ka cash jama (sirf malik dekh sakta hai)
-- =====================================================
alter policy rec_read on public.records
  using (deleted_at is null and shop_id = my_shop()
         and (my_role() = 'owner' or kind not in ('expense','plant','sale','setting','handover')));

create or replace function public.clear_pin(shop uuid) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then return false; end if;
  update records set data = data - 'pin' where shop_id = shop and kind = 'setting';
  return true;
end $$;
revoke execute on function public.clear_pin(uuid) from anon, public;
grant execute on function public.clear_pin(uuid) to authenticated;

-- =====================================================
-- UPDATE 4: grahak ka order link (bina login)
-- =====================================================
alter policy rec_upd on public.records
  using (shop_id = my_shop() and (my_role() = 'owner' or kind in ('customer','order')))
  with check (shop_id = my_shop());
create index if not exists records_cust_tok on public.records ((data->>'tok')) where kind = 'customer';
-- cust_portal(tok) aur cust_order(tok, qty, note): poori definition Supabase migration "customer_order_links" mein hai
