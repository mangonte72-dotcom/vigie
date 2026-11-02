-- =====================================================================
-- VIGIE – base de données Supabase
-- À coller dans Supabase > SQL Editor > New query, puis « Run ».
-- Le script peut être relancé sans risque.
-- =====================================================================

-- 1. Tables ------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  nom        text,
  email      text,
  role       text not null default 'operateur' check (role in ('operateur', 'hse')),
  active     boolean not null default false,
  created_at timestamptz not null default now()
);

-- Toutes les données de l'application : déclarations, risques, SOS, permis,
-- équipements, réglages, photos. Une ligne = un élément (format JSON).
create table if not exists public.docs (
  collection text not null,
  id         text not null,
  data       jsonb not null,
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now(),
  primary key (collection, id)
);
alter table public.docs replica identity full;

-- 2. Fonctions de contrôle d'accès -----------------------------------------
create or replace function public.is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and active)
$$;

create or replace function public.is_hse() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and active and role = 'hse')
$$;

-- Création automatique du profil à la première connexion (en attente de validation)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, email) values (new.id, new.email) on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Validation des comptes et attribution du rôle HSE (réservé au service HSE)
create or replace function public.set_member(target uuid, p_active boolean, p_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_hse() then raise exception 'Réservé au service HSE'; end if;
  if p_role not in ('operateur', 'hse') then raise exception 'Rôle inconnu'; end if;
  if target = auth.uid() then raise exception 'Vous ne pouvez pas modifier votre propre compte'; end if;
  update profiles set active = p_active, role = p_role where id = target;
end $$;
revoke execute on function public.set_member(uuid, boolean, text) from public, anon;
grant  execute on function public.set_member(uuid, boolean, text) to authenticated;

-- 3. Règles d'accès (Row Level Security) -------------------------------------
alter table public.profiles enable row level security;
alter table public.docs     enable row level security;

revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant update (nom) on public.profiles to authenticated;   -- chacun ne peut changer que son nom

drop policy if exists profiles_read       on public.profiles;
drop policy if exists profiles_update_own on public.profiles;
create policy profiles_read       on public.profiles for select to authenticated using (id = auth.uid() or is_active());
create policy profiles_update_own on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

revoke all on public.docs from anon;
grant select, insert, update, delete on public.docs to authenticated;

drop policy if exists docs_read   on public.docs;
drop policy if exists docs_insert on public.docs;
drop policy if exists docs_update on public.docs;
drop policy if exists docs_delete on public.docs;
-- Lecture : comptes validés uniquement
create policy docs_read on public.docs for select to authenticated using (is_active());
-- Écriture : comptes validés ; réglages et équipements réservés au service HSE
create policy docs_insert on public.docs for insert to authenticated
  with check (is_active() and (collection not in ('config', 'equip') or is_hse()));
create policy docs_update on public.docs for update to authenticated
  using (is_active() and (collection not in ('config', 'equip') or is_hse()))
  with check (is_active() and (collection not in ('config', 'equip') or is_hse()));
-- Suppression : service HSE uniquement
create policy docs_delete on public.docs for delete to authenticated using (is_hse());

-- 3 bis. Contrôles d'écriture : auteur, champs protégés, historique --------
-- Champs qu'un opérateur peut changer sur un élément existant (le reste est réservé au service HSE).
create or replace function public.docs_editable(p_collection text) returns text[]
language sql immutable set search_path = '' as $$
  select case p_collection
    when 'sos'       then array['status', 'takenBy', 'takenAt', 'closedBy', 'closedAt']
    when 'incidents' then array['status', 'statusBy', 'statusAt']
    when 'risks'     then array['done', 'doneBy', 'doneAt']
    when 'permits'   then array['status', 'closedBy', 'closedAt']
    when 'stops'     then array['step', 'status', 'log']
    when 'formation' then array['module', 'score', 'total']
    else array[]::text[] end
$$;

-- L'auteur (by), les dates (at, …At) et les signataires (…By) sont fixés par la base,
-- jamais par le téléphone : impossible de déclarer ou de valider au nom d'un autre.
create or replace function public.docs_guard() returns trigger
language plpgsql set search_path = public as $$
declare
  uid  text  := auth.uid()::text;
  hse  boolean;
  stamp jsonb := to_jsonb(to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
  k text; n int; i int; e jsonb; lg jsonb;
begin
  if uid is null then return new; end if;   -- SQL Editor / clé service : pas de contrôle
  hse := is_hse();
  new.updated_by := auth.uid();
  new.updated_at := now();

  if tg_op = 'INSERT' then
    if not hse and new.collection not in ('sos', 'incidents', 'risks', 'permits', 'stops', 'formation', 'photos') then
      raise exception 'Réservé au service HSE' using errcode = '42501';
    end if;
    if new.collection = 'formation' and new.id <> uid and not hse then
      raise exception 'Formation : uniquement la vôtre' using errcode = '42501';
    end if;
    if new.collection in ('sos', 'incidents', 'risks', 'permits', 'stops', 'formation') then
      new.data := new.data || jsonb_build_object('by', uid, 'at', stamp);
      if jsonb_typeof(new.data->'log') = 'array' then
        select coalesce(jsonb_agg(x || jsonb_build_object('by', uid, 'at', stamp)), '[]') into lg
        from jsonb_array_elements(new.data->'log') x;
        new.data := jsonb_set(new.data, '{log}', lg);
      end if;
    end if;
    return new;
  end if;

  -- UPDATE
  if new.collection <> old.collection or new.id <> old.id then
    raise exception 'Identifiant non modifiable' using errcode = '42501';
  end if;
  new.data := (new.data - 'by' - 'at') || jsonb_strip_nulls(jsonb_build_object('by', old.data->'by', 'at', old.data->'at'));
  if new.collection = 'formation' then new.data := new.data || jsonb_build_object('at', stamp); end if;
  if hse then return new; end if;
  if new.collection = 'formation' and new.id <> uid then
    raise exception 'Formation : uniquement la vôtre' using errcode = '42501';
  end if;

  for k in select jsonb_object_keys(old.data) union select jsonb_object_keys(new.data) loop
    continue when k in ('by', 'at') or (old.data->k) is not distinct from (new.data->k);
    if not (k = any(docs_editable(new.collection))) then
      raise exception 'Champ « % » réservé au service HSE', k using errcode = '42501';
    end if;
    if k like '%By' then new.data := jsonb_set(new.data, array[k], to_jsonb(uid)); end if;
    if k like '%At' then new.data := jsonb_set(new.data, array[k], stamp); end if;
  end loop;

  -- Arrêts de travail : on ajoute des étapes à l'historique, on ne le réécrit jamais
  if new.collection = 'stops' and (old.data->'log') is distinct from (new.data->'log') then
    n := coalesce(jsonb_array_length(case when jsonb_typeof(old.data->'log') = 'array' then old.data->'log' end), 0);
    if coalesce(jsonb_typeof(new.data->'log'), '') <> 'array' or jsonb_array_length(new.data->'log') < n then
      raise exception 'L''historique de l''arrêt ne peut pas être modifié' using errcode = '42501';
    end if;
    lg := '[]';
    for i in 0 .. jsonb_array_length(new.data->'log') - 1 loop
      e := new.data->'log'->i;
      if i < n then
        if e is distinct from old.data->'log'->i then
          raise exception 'L''historique de l''arrêt ne peut pas être modifié' using errcode = '42501';
        end if;
      else
        e := e || jsonb_build_object('by', uid, 'at', stamp);
      end if;
      lg := lg || jsonb_build_array(e);
    end loop;
    new.data := jsonb_set(new.data, '{log}', lg);
  end if;
  return new;
end $$;
drop trigger if exists docs_guard on public.docs;
create trigger docs_guard before insert or update on public.docs
  for each row execute function public.docs_guard();

-- Mise à jour atomique : fusionne les champs sur la version en base (deux personnes
-- qui agissent en même temps ne s'écrasent plus). p_append ajoute à une liste,
-- p_expect refuse la modification si l'élément a changé entre-temps (« conflit »).
create or replace function public.doc_patch(p_collection text, p_id text, p_patch jsonb,
  p_append jsonb default null, p_expect jsonb default null) returns jsonb
language plpgsql set search_path = public as $$
declare cur jsonb; k text; v jsonb;
begin
  select data into cur from docs where collection = p_collection and id = p_id for update;
  if not found then raise exception 'Élément introuvable ou non autorisé' using errcode = '42501'; end if;
  if p_expect is not null and not (cur @> p_expect) then raise exception 'conflit'; end if;
  cur := cur || coalesce(p_patch, '{}');
  for k, v in select * from jsonb_each(coalesce(p_append, '{}')) loop
    cur := jsonb_set(cur, array[k], coalesce(case when jsonb_typeof(cur->k) = 'array' then cur->k end, '[]') || jsonb_build_array(v));
  end loop;
  update docs set data = cur where collection = p_collection and id = p_id returning data into cur;
  if not found then raise exception 'Élément introuvable ou non autorisé' using errcode = '42501'; end if;
  return cur;
end $$;
revoke execute on function public.doc_patch(text, text, jsonb, jsonb, jsonb) from public, anon;
grant  execute on function public.doc_patch(text, text, jsonb, jsonb, jsonb) to authenticated;

-- 4. Temps réel (SOS et déclarations visibles instantanément) ----------------
do $$ begin
  alter publication supabase_realtime add table public.docs;
exception when duplicate_object then null; end $$;

-- 5. Vues pour les bilans HSE (Supabase > Table Editor, ou export CSV) -------
create or replace view public.v_evenements with (security_invoker = true) as
select id,
       (data->>'at')::timestamptz        as date,
       data->>'type'                     as type,
       (data->>'niv')::int               as gravite,
       data->>'vic'                      as victime,
       (data->>'ind')::boolean           as fuite_feu_rejet,
       data->>'lieu'                     as lieu,
       data->>'desc'                     as description,
       data->>'status'                   as statut,
       (select nom from profiles p where p.id::text = d.data->>'by') as declare_par
from docs d where collection = 'incidents';

create or replace view public.v_risques with (security_invoker = true) as
select id, data->>'zone' as zone, data->>'danger' as danger,
       (data->>'p')::int as probabilite, (data->>'g')::int as gravite,
       (data->>'p')::int * (data->>'g')::int as criticite,
       (data->>'done')::boolean as traite, data->>'equip' as equipement
from docs where collection = 'risks';

create or replace view public.v_sos with (security_invoker = true) as
select id, (data->>'at')::timestamptz as date, data->>'type' as type, data->>'equipName' as equipement,
       data->>'lieu' as lieu, data->>'status' as statut,
       (select nom from profiles p where p.id::text = d.data->>'by') as declenche_par
from docs d where collection = 'sos';

create or replace view public.v_permis with (security_invoker = true) as
select id, (data->>'at')::timestamptz as date, data->>'kind' as type, data->>'equipName' as equipement,
       data->>'status' as statut,
       (select nom from profiles p where p.id::text = d.data->>'by') as emis_par
from docs d where collection = 'permits';

-- 5 bis. Alertes SOS sur les téléphones, même application fermée (Web Push) ---
-- Chaque SOS (création, prise en charge, clôture) appelle la fonction serveur
-- « sos-push » (dossier supabase/functions), qui notifie tous les comptes validés.
create extension if not exists pg_net;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- Clés de notification (créées par la fonction à son premier appel) et secret partagé
create table if not exists private.push_config (
  id            int primary key default 1 check (id = 1),
  vapid_public  text,
  vapid_private text,
  hook_secret   text not null default encode(extensions.gen_random_bytes(24), 'hex'),
  function_url  text
);
insert into private.push_config (id) values (1) on conflict (id) do nothing;
-- Adresse de la fonction : https://<référence du projet>.supabase.co/functions/v1/sos-push
update private.push_config set function_url = 'https://uyocsoicjercilcxvxcg.supabase.co/functions/v1/sos-push' where function_url is null;

-- Téléphones inscrits (accessibles uniquement par les fonctions ci-dessous et le serveur)
create table if not exists public.push_subscriptions (
  endpoint   text primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  p256dh     text not null,
  auth       text not null,
  created_at timestamptz not null default now()
);
alter table public.push_subscriptions enable row level security;
revoke all on public.push_subscriptions from anon, authenticated;

create or replace function public.vapid_public_key() returns text
language sql stable security definer set search_path = '' as $$
  select vapid_public from private.push_config where id = 1
$$;
revoke execute on function public.vapid_public_key() from public, anon;
grant  execute on function public.vapid_public_key() to authenticated;

-- Seuls les services de notification des navigateurs sont acceptés comme adresse
create or replace function public.push_subscribe(p_endpoint text, p_p256dh text, p_auth text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then raise exception 'Connexion requise' using errcode = '42501'; end if;
  if length(p_endpoint) > 1000 or p_endpoint !~ '^https://([a-z0-9-]+\.)*(fcm\.googleapis\.com|push\.apple\.com|push\.services\.mozilla\.com|notify\.windows\.com)/' then
    raise exception 'Adresse de notification non reconnue';
  end if;
  insert into public.push_subscriptions (endpoint, user_id, p256dh, auth) values (p_endpoint, auth.uid(), p_p256dh, p_auth)
  on conflict (endpoint) do update set user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, created_at = now();
end $$;
create or replace function public.push_unsubscribe(p_endpoint text) returns void
language sql security definer set search_path = '' as $$
  delete from public.push_subscriptions where endpoint = p_endpoint and user_id = auth.uid()
$$;
revoke execute on function public.push_subscribe(text, text, text) from public, anon;
revoke execute on function public.push_unsubscribe(text) from public, anon;
grant  execute on function public.push_subscribe(text, text, text) to authenticated;
grant  execute on function public.push_unsubscribe(text) to authenticated;

-- Réservées à la fonction serveur (clé service_role)
create or replace function public.push_config_get() returns jsonb
language sql stable security definer set search_path = '' as $$
  select to_jsonb(c) from private.push_config c where id = 1
$$;
create or replace function public.push_set_vapid(p_public text, p_private text) returns void
language sql security definer set search_path = '' as $$
  update private.push_config set vapid_public = p_public, vapid_private = p_private where id = 1 and vapid_public is null
$$;
revoke execute on function public.push_config_get() from public, anon, authenticated;
revoke execute on function public.push_set_vapid(text, text) from public, anon, authenticated;
grant  execute on function public.push_config_get() to service_role;
grant  execute on function public.push_set_vapid(text, text) to service_role;

create or replace function public.sos_push_hook() returns trigger
language plpgsql security definer set search_path = '' as $$
declare c private.push_config; kind text;
begin
  if tg_op = 'INSERT' then kind := 'new';
  elsif (old.data->>'status') is distinct from (new.data->>'status') then kind := new.data->>'status';
  else return null; end if;
  select * into c from private.push_config where id = 1;
  if c.function_url is null then return null; end if;
  perform net.http_post(url := c.function_url, body := jsonb_build_object('id', new.id, 'kind', kind),
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-vigie-hook', c.hook_secret), timeout_milliseconds := 5000);
  return null;
end $$;
revoke execute on function public.sos_push_hook() from public, anon, authenticated;
drop trigger if exists sos_push on public.docs;
create trigger sos_push after insert or update on public.docs
  for each row when (new.collection = 'sos') execute function public.sos_push_hook();

-- 6. Données d'exemple (à remplacer par les vrais équipements du site) -------
insert into public.docs (collection, id, data) values
('equip','B12','{"code":"B12","nom":"Bac B12","zone":"Parc de stockage","produit":"Brut léger","tags":["Zone ATEX 1","H₂S possible","Espace confiné"],"consignes":["Permis de pénétrer + bon de consignation","Isolement par joints pleins sur toutes les lignes","Mesure d’atmosphère en continu (O₂, explosivité, H₂S)","Surveillant extérieur et trépied de sauvetage en place"],"permis":"Permis de pénétrer + bon de consignation","exemple":true}'),
('equip','P204','{"code":"P204","nom":"Pompe P-204","zone":"Unité de distillation","produit":"Naphta","tags":["Zone ATEX 2","Pression / vapeur"],"consignes":["Consigner la pompe et ses vannes d’isolement","Purger et décompresser avant ouverture","Explosimétrie si travail par point chaud"],"permis":"Bon de consignation + permis de travail","exemple":true}'),
('equip','CH03','{"code":"CH03","nom":"Poste de chargement 3","zone":"Expéditions","produit":"Gazole","tags":["Citernes","Zone ATEX 1"],"consignes":["Protocole de sécurité signé par le transporteur","Mise à la terre de la citerne avant chargement"],"permis":"Protocole de sécurité chargement / déchargement","exemple":true}'),
('risks','ex1','{"zone":"Bac B12 – nettoyage intérieur","danger":"confine","p":3,"g":4,"equip":"B12","done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}'),
('risks','ex2','{"zone":"Grand arrêt – coactivité de plusieurs entreprises","danger":"coact","p":3,"g":3,"equip":null,"done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}'),
('risks','ex3','{"zone":"Pompe P-204 – soudure sur ligne","danger":"atex","p":2,"g":4,"equip":"P204","done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}'),
('risks','ex4','{"zone":"Désulfuration – échantillonnage","danger":"h2s","p":2,"g":4,"equip":null,"done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}'),
('risks','ex5','{"zone":"Poste de chargement 3 – citernes","danger":"citerne","p":2,"g":3,"equip":"CH03","done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}'),
('risks','ex6','{"zone":"Travaux extérieurs en été","danger":"chaleur","p":3,"g":2,"equip":null,"done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}'),
('risks','ex7','{"zone":"Bac B12 – accès au toit","danger":"hauteur","p":2,"g":3,"equip":"B12","done":false,"exemple":true,"at":"2026-10-29T12:00:00Z"}')
on conflict (collection, id) do nothing;

-- 7. PREMIER RESPONSABLE HSE ---------------------------------------------
-- Après VOTRE première connexion dans l'application, remplacez l'adresse
-- ci-dessous par la vôtre, retirez les deux tirets en début de ligne et exécutez :
-- update public.profiles set active = true, role = 'hse' where email = 'votre.email@exemple.fr';
