import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// Même projet Supabase que l'app Android — même cercle, mêmes comptes.
const SUPABASE_URL = 'https://yywirxlbbydwsbviansf.supabase.co';
const SUPABASE_KEY = 'sb_publishable_v2LhzpWPrzh7fonZ16d5uQ_IGyxk89H';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const app = document.getElementById('app');

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  });
}

let state = {
  screen: 'loading', // loading | auth | main
  authMode: 'signin', // signin | signup | join
  user: null,
  members: [],
  conversations: [],
  error: null,
  busy: false,
  passwordVisible: false,
  joinSent: false,
};

function set(patch) {
  state = { ...state, ...patch };
  render();
}

function escapeHtml(s) {
  return (s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function friendlyAuthError(message, isSignUp) {
  const m = (message || '').toLowerCase();
  if (m.includes('invalid login credentials')) return 'E-mail ou mot de passe incorrect.';
  if (m.includes('already registered')) return 'Un compte existe déjà avec cet e-mail.';
  if (m.includes('password should be at least')) return 'Mot de passe trop court (6 caractères minimum).';
  if (m.includes('unable to validate email') || m.includes('invalid email')) return 'Adresse e-mail invalide.';
  if (isSignUp) return "Inscription refusée : cet e-mail n'est pas invité au cercle Breeze.";
  return 'Connexion impossible. Vérifie ta connexion Internet et réessaie.';
}

// ---------- Rendu ----------

function render() {
  if (state.screen === 'loading') return renderLoading();
  if (state.screen === 'auth') return renderAuth();
  return renderMain();
}

function renderLoading() {
  app.innerHTML = `
    <div class="screen center">
      <div class="spinner"></div>
      <div class="tagline">Chargement…</div>
    </div>
  `;
}

function renderAuth() {
  const m = state.authMode;
  app.innerHTML = `
    <div class="screen center">
      <h1 class="logo">Breeze</h1>
      <div class="tagline">Messagerie du cercle privé</div>

      <div class="tabs">
        <button class="tab ${m === 'signin' ? 'active' : ''}" data-mode="signin">Se connecter</button>
        <button class="tab ${m === 'signup' ? 'active' : ''}" data-mode="signup">Créer un compte</button>
        <button class="tab ${m === 'join' ? 'active' : ''}" data-mode="join">Demande d'ajout</button>
      </div>

      ${m === 'join' ? renderJoinForm() : renderAuthForm(m)}
    </div>
  `;
  wireAuthEvents();
}

function renderAuthForm(m) {
  const isSignUp = m === 'signup';
  return `
    <form id="authForm" style="width:100%;max-width:380px;">
      <div class="field-group">
        <label for="email">E-mail</label>
        <input type="email" id="email" autocomplete="email" required />
      </div>
      <div class="field-group">
        <label for="password">Mot de passe</label>
        <div class="input-wrap">
          <input type="${state.passwordVisible ? 'text' : 'password'}" id="password"
                 autocomplete="${isSignUp ? 'new-password' : 'current-password'}" required />
          <button type="button" class="pw-toggle" id="pwToggle">${state.passwordVisible ? '🙈' : '👁'}</button>
        </div>
      </div>
      ${isSignUp ? `
      <div class="field-group">
        <label for="confirm">Confirmer le mot de passe</label>
        <div class="input-wrap">
          <input type="${state.passwordVisible ? 'text' : 'password'}" id="confirm" autocomplete="new-password" required />
        </div>
      </div>` : ''}
      ${state.error ? `<div class="error">${escapeHtml(state.error)}</div>` : ''}
      <button type="submit" class="primary" ${state.busy ? 'disabled' : ''}>
        ${state.busy ? '…' : (isSignUp ? 'Créer un compte' : 'Se connecter')}
      </button>
    </form>
    <div class="foot-note">Seuls les e-mails invités au cercle peuvent créer un compte.</div>
  `;
}

function renderJoinForm() {
  return `
    <form id="joinForm" style="width:100%;max-width:380px;">
      <div class="foot-note" style="margin-top:0;margin-bottom:14px;">
        Tu as ouvert Breeze sans y être encore invité ? Envoie une demande, un membre du cercle te répondra.
      </div>
      <div class="field-group">
        <label for="joinName">Ton nom</label>
        <input type="text" id="joinName" required />
      </div>
      <div class="field-group">
        <label for="joinEmail">E-mail</label>
        <input type="email" id="joinEmail" required />
      </div>
      <div class="field-group">
        <label for="joinMessage">Message (qui es-tu, qui t'invite…)</label>
        <textarea id="joinMessage"></textarea>
      </div>
      ${state.error ? `<div class="error">${escapeHtml(state.error)}</div>` : ''}
      ${state.joinSent ? `<div class="success">Demande envoyée. Un membre du cercle va l'examiner.</div>` : ''}
      <button type="submit" class="primary" ${state.busy ? 'disabled' : ''}>
        ${state.busy ? '…' : 'Envoyer la demande'}
      </button>
    </form>
  `;
}

function wireAuthEvents() {
  document.querySelectorAll('.tab').forEach((el) => {
    el.addEventListener('click', () => set({ authMode: el.dataset.mode, error: null, joinSent: false }));
  });

  const pwToggle = document.getElementById('pwToggle');
  if (pwToggle) pwToggle.addEventListener('click', () => set({ passwordVisible: !state.passwordVisible }));

  const authForm = document.getElementById('authForm');
  if (authForm) {
    authForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value;
      const isSignUp = state.authMode === 'signup';
      if (isSignUp) {
        const confirm = document.getElementById('confirm').value;
        if (password !== confirm) {
          set({ error: 'Les mots de passe ne correspondent pas.' });
          return;
        }
      }
      set({ busy: true, error: null });
      try {
        const { error } = isSignUp
          ? await supabase.auth.signUp({ email, password })
          : await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        // onAuthStateChange gère la suite (chargement de l'écran principal).
        set({ busy: false });
      } catch (err) {
        set({ busy: false, error: friendlyAuthError(err.message, isSignUp) });
      }
    });
  }

  const joinForm = document.getElementById('joinForm');
  if (joinForm) {
    joinForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('joinName').value.trim();
      const contact = document.getElementById('joinEmail').value.trim();
      const message = document.getElementById('joinMessage').value.trim();
      set({ busy: true, error: null, joinSent: false });
      try {
        const { error } = await supabase.from('join_requests').insert({ name, contact, message });
        if (error) throw error;
        set({ busy: false, joinSent: true });
        joinForm.reset();
      } catch (err) {
        set({ busy: false, error: "Envoi impossible. Vérifie ta connexion Internet et réessaie." });
      }
    });
  }
}

// ---------- Écran principal ----------

async function loadMainData() {
  try {
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', state.user.id)
      .maybeSingle();
    const { data: members } = await supabase.from('profiles').select('*');
    set({ profile: profile || null, members: members || [] });
  } catch (_) {
    set({ members: [] });
  }
}

function initialsFor(name) {
  return (name || '?').trim().charAt(0).toUpperCase();
}

function renderMain() {
  const email = state.user?.email || '—';
  const profile = state.profile;
  const displayName = profile?.display_name?.trim() || email;
  const members = (state.members || []).filter((m) => m.id !== state.user?.id && m.status === 'active');

  app.innerHTML = `
    <div class="topbar">
      Breeze
      <span class="sub">Phase 1 — web</span>
    </div>
    <div class="banner">Version web en construction : messagerie chiffrée pas encore disponible ici.</div>
    <div class="profile-row">
      <div class="avatar">${escapeHtml(initialsFor(displayName))}</div>
      <div>
        <div class="profile-name">${escapeHtml(displayName)}</div>
        <div class="profile-email">${escapeHtml(email)}</div>
      </div>
      <button class="signout" id="signOutBtn">Se déconnecter</button>
    </div>
    <div style="padding:14px 20px 4px;font-size:13px;font-weight:700;color:var(--green);">
      Membres du cercle (${members.length})
    </div>
    ${members.length === 0
      ? `<div class="empty">Aucun membre.</div>`
      : members.map((m) => `
        <div class="list-item">
          <div class="avatar" style="width:36px;height:36px;font-size:14px;">${escapeHtml(initialsFor(m.display_name || m.email))}</div>
          <div>
            <div class="name">${escapeHtml(m.display_name?.trim() || m.email || m.id.slice(0, 8))}</div>
            ${m.display_name?.trim() && m.email ? `<div class="preview">${escapeHtml(m.email)}</div>` : ''}
          </div>
        </div>
      `).join('')}
  `;

  document.getElementById('signOutBtn').addEventListener('click', async () => {
    await supabase.auth.signOut();
  });
}

// ---------- Démarrage ----------

supabase.auth.onAuthStateChange((_event, session) => {
  if (session?.user) {
    set({ screen: 'main', user: session.user });
    loadMainData();
  } else {
    set({ screen: 'auth', user: null, members: [] });
  }
});

render();
