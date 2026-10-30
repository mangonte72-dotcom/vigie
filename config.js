/* Vigie – configuration
   1. supabaseUrl et supabaseAnonKey : Supabase > Project Settings > API
      (Project URL, et la clé « anon public »). Ne mettez JAMAIS la clé « service_role » ici.
   2. posteGarde : numéro affiché dès l'écran de connexion, pour les urgences.
   Laissez supabaseUrl vide pour le mode hors ligne (données gardées sur chaque téléphone). */
window.VIGIE_CONFIG = {
  supabaseUrl: 'https://uyocsoicjercilcxvxcg.supabase.co',
  supabaseAnonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV5b2Nzb2ljamVyY2lsY3h2eGNnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTMyODEzODksImV4cCI6MjEwODg1NzM4OX0.Eo1DjKH5itSmpi2JebP_w4NZOWga_B8Bbo92zo5f_CU',
  posteGarde: ''          // ex. '04 42 00 00 00'
};
