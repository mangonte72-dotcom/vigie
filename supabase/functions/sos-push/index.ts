// Vigie – envoi des alertes SOS sur les téléphones (Web Push), même application fermée.
// Appelée par la base (déclencheur sos_push) à chaque SOS créé, pris en charge ou clôturé.
// Déploiement : Supabase > Edge Functions, nom « sos-push », vérification JWT désactivée
// (l'appel est authentifié par le secret partagé x-vigie-hook).
import webpush from 'npm:web-push@3.6.7';
import { createClient } from 'npm:@supabase/supabase-js@2.45.4';

const sb = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } });
const TYPES: Record<string, string> = { blesse: 'Personne blessée', feu: 'Incendie', gaz: 'Fuite de gaz', malaise: 'Malaise', autre: 'Autre danger' };

Deno.serve(async req => {
  if (req.method !== 'POST') return new Response('Méthode non autorisée', { status: 405 });
  const { data: cfg, error } = await sb.rpc('push_config_get');
  if (error || !cfg) return new Response('Configuration absente', { status: 500 });
  if (!cfg.hook_secret || req.headers.get('x-vigie-hook') !== cfg.hook_secret) return new Response('Accès refusé', { status: 401 });

  // Clés de notification : créées une seule fois, au premier appel
  let pub: string = cfg.vapid_public, priv: string = cfg.vapid_private;
  if (!pub || !priv) {
    const k = webpush.generateVAPIDKeys();
    await sb.rpc('push_set_vapid', { p_public: k.publicKey, p_private: k.privateKey });
    const { data: again } = await sb.rpc('push_config_get');
    pub = again.vapid_public; priv = again.vapid_private;
  }
  const { id, kind } = await req.json().catch(() => ({}));
  if (kind === 'init' || !id) return Response.json({ ok: true, ready: !!pub });
  webpush.setVapidDetails('https://mangonte72-dotcom.github.io/vigie/', pub, priv);

  const { data: row } = await sb.from('docs').select('data').eq('collection', 'sos').eq('id', id).maybeSingle();
  if (!row) return Response.json({ ok: false, reason: 'introuvable' });
  const s = row.data;
  const { data: people } = await sb.from('profiles').select('id,nom,active');
  const name = (u: string) => (people || []).find(p => p.id === u)?.nom || 'un collègue';
  const active = new Set((people || []).filter(p => p.active).map(p => p.id));
  const where = s.equipName || s.lieu || 'position non précisée', label = TYPES[s.type] || 'Alerte';

  let title: string, body: string, actor: string, urgent = false;
  if (kind === 'new') { title = `🚨 SOS : ${label}`; body = `${where} · déclenché par ${name(s.by)}. Ouvrez Vigie.`; actor = s.by; urgent = true; }
  else if (kind === 'prise') { title = `SOS pris en charge : ${label}`; body = `${name(s.takenBy)} s’en occupe · ${where}`; actor = s.takenBy; }
  else if (kind === 'close') { title = `SOS clôturé : ${label}`; body = `Clôturé par ${name(s.closedBy)} · ${where}`; actor = s.closedBy; }
  else return Response.json({ ok: true, skipped: kind });

  const { data: subs } = await sb.from('push_subscriptions').select('endpoint,user_id,p256dh,auth');
  const targets = (subs || []).filter(x => active.has(x.user_id) && x.user_id !== actor);
  const payload = JSON.stringify({ title, body, tag: 'sos-' + id, urgent, url: './index.html#accueil' });
  let sent = 0, removed = 0;
  await Promise.all(targets.map(async x => {
    try {
      await webpush.sendNotification({ endpoint: x.endpoint, keys: { p256dh: x.p256dh, auth: x.auth } }, payload, { TTL: 3600, urgency: 'high' });
      sent++;
    } catch (e) {
      // Téléphone désinscrit ou application désinstallée : on le retire
      if (e?.statusCode === 404 || e?.statusCode === 410) { await sb.from('push_subscriptions').delete().eq('endpoint', x.endpoint); removed++; }
    }
  }));
  return Response.json({ ok: true, targets: targets.length, sent, removed });
});
