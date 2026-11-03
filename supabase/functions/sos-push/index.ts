// Vigie – notifications sur les téléphones (Web Push), même application fermée.
// Appelée par la base :
//   - déclencheur sos_push : à chaque SOS créé, pris en charge ou clôturé → tous les comptes actifs ;
//   - déclencheur incident_push : à chaque nouvelle déclaration d'événement → les comptes HSE.
// Déploiement : Supabase > Edge Functions, nom « sos-push », vérification JWT désactivée
// (l'appel est authentifié par le secret partagé x-vigie-hook).
import webpush from 'npm:web-push@3.6.7';
import { createClient } from 'npm:@supabase/supabase-js@2.45.4';

const sb = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } });
const TYPES: Record<string, string> = { blesse: 'Personne blessée', feu: 'Incendie', gaz: 'Fuite de gaz', malaise: 'Malaise', autre: 'Autre danger' };
const INC_TYPES: Record<string, string> = {
  atex: 'Incendie / ATEX', h2s: 'Gaz toxique (H₂S)', cmr: 'Produit CMR', confine: 'Espace confiné', pression: 'Pression / vapeur',
  elec: 'Électrique', hauteur: 'Travaux en hauteur', coact: 'Coactivité', citerne: 'Citernes / engins', chaleur: 'Chaleur', chute: 'Chute / manutention'
};
const NIV: Record<string, string> = { '1': 'Presque-accident', '2': 'Accident sans arrêt', '3': 'Accident avec arrêt', '4': 'Accident grave', '5': 'Accident mortel' };

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
  const { id, kind, collection } = await req.json().catch(() => ({}));
  if (kind === 'init' || !id) return Response.json({ ok: true, ready: !!pub });
  webpush.setVapidDetails('https://mangonte72-dotcom.github.io/vigie/', pub, priv);

  const col = collection === 'incidents' ? 'incidents' : 'sos';
  const { data: row } = await sb.from('docs').select('data').eq('collection', col).eq('id', id).maybeSingle();
  if (!row) return Response.json({ ok: false, reason: 'introuvable' });
  const s = row.data;
  const { data: people } = await sb.from('profiles').select('id,nom,active,role');
  const name = (u: string) => (people || []).find(p => p.id === u)?.nom || 'un collègue';

  let title: string, body: string, actor: string, url: string, tag: string, urgent = false;
  let allowed: Set<string>;
  if (col === 'incidents') {
    // Nouvelle déclaration → service HSE uniquement
    if (kind !== 'new') return Response.json({ ok: true, skipped: kind });
    const niv = String(s.niv ?? '1');
    const where = s.lieu || 'lieu non précisé';
    title = `📋 Déclaration : ${INC_TYPES[s.type] || 'Événement'} · ${NIV[niv] || 'Événement'}`;
    body = `${where} · déclaré par ${name(s.by)}${s.photoDoc || s.photoId ? ' · 📷 photo jointe' : ''}. Touchez pour ouvrir.`;
    actor = s.by; urgent = Number(niv) >= 3; tag = 'inc-' + id; url = './index.html#inc=' + encodeURIComponent(id);
    allowed = new Set((people || []).filter(p => p.active && p.role === 'hse').map(p => p.id));
  } else {
    const where = s.equipName || s.lieu || 'position non précisée', label = TYPES[s.type] || 'Alerte';
    if (kind === 'new') { title = `🚨 SOS : ${label}`; body = `${where} · déclenché par ${name(s.by)}. Ouvrez Vigie.`; actor = s.by; urgent = true; }
    else if (kind === 'prise') { title = `SOS pris en charge : ${label}`; body = `${name(s.takenBy)} s’en occupe · ${where}`; actor = s.takenBy; }
    else if (kind === 'close') { title = `SOS clôturé : ${label}`; body = `Clôturé par ${name(s.closedBy)} · ${where}`; actor = s.closedBy; }
    else return Response.json({ ok: true, skipped: kind });
    tag = 'sos-' + id; url = './index.html#accueil';
    allowed = new Set((people || []).filter(p => p.active).map(p => p.id));
  }

  const { data: subs } = await sb.from('push_subscriptions').select('endpoint,user_id,p256dh,auth');
  const targets = (subs || []).filter(x => allowed.has(x.user_id) && x.user_id !== actor);
  const payload = JSON.stringify({ title, body, tag, urgent, url });
  let sent = 0, removed = 0;
  await Promise.all(targets.map(async x => {
    try {
      await webpush.sendNotification({ endpoint: x.endpoint, keys: { p256dh: x.p256dh, auth: x.auth } }, payload, { TTL: 3600, urgency: urgent ? 'high' : 'normal' });
      sent++;
    } catch (e) {
      // Téléphone désinscrit ou application désinstallée : on le retire
      if (e?.statusCode === 404 || e?.statusCode === 410) { await sb.from('push_subscriptions').delete().eq('endpoint', x.endpoint); removed++; }
    }
  }));
  return Response.json({ ok: true, collection: col, targets: targets.length, sent, removed });
});
