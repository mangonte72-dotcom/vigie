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
