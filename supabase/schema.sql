-- Users profiles (extends Supabase auth.users)
create table public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text,
  full_name text,
  role text default 'user', -- 'admin' or 'user'
  subscription_status text default 'trial', -- 'trial', 'active', 'expired'
  subscription_expires_at timestamptz,
  created_at timestamptz default now()
);

-- Trades
create table public.trades (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users on delete cascade not null,
  date timestamptz default now(),
  direction text not null, -- 'sell' or 'buy'
  type text not null, -- 'bank_pro', 'bank_perso', 'cash', 'skrill', 'paypal', 'other'
  client text not null,
  recv_orig numeric,
  recv_cur text,
  recv_usdt numeric,
  sent_orig numeric,
  sent_cur text,
  sent_usdt numeric,
  profit numeric,
  status text default 'pending', -- 'pending', 'done'
  note text,
  created_at timestamptz default now()
);

-- RLS Policies
alter table public.profiles enable row level security;
alter table public.trades enable row level security;

-- Profiles: users can read/update their own profile, admins can read all
create policy "Users can view own profile" on public.profiles
  for select using (auth.uid() = id);

create policy "Users can update own profile" on public.profiles
  for update using (auth.uid() = id);

create policy "Admins can view all profiles" on public.profiles
  for select using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and role = 'admin'
    )
  );

create policy "Admins can update all profiles" on public.profiles
  for update using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and role = 'admin'
    )
  );

-- Trades: users can only see their own trades
create policy "Users can view own trades" on public.trades
  for select using (auth.uid() = user_id);

create policy "Users can insert own trades" on public.trades
  for insert with check (auth.uid() = user_id);

create policy "Users can update own trades" on public.trades
  for update using (auth.uid() = user_id);

create policy "Users can delete own trades" on public.trades
  for delete using (auth.uid() = user_id);

create policy "Admins can view all trades" on public.trades
  for select using (
    exists (
      select 1 from public.profiles
      where id = auth.uid() and role = 'admin'
    )
  );

-- Auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email);
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
