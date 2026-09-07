import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { restoreIdentityFromBackup, unwrapConversationKey, decryptMessage, encryptMessage } from './tink-hpke.js';

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
  profile: null,
  members: [],
  error: null,
  busy: false,
  passwordVisible: false,
  joinSent: false,

  // Identité de chiffrement (clé privée HPKE, en mémoire seulement — jamais persistée en clair).
  identity: null, // { keyId, rawPrivateKey, rawPublicKey }
  unlockBusy: false,
  unlockError: null,

  // Conversations
  conversations: null, // liste brute (metadata + clé chiffrée), null = pas encore chargée
  previews: {},         // conversationId -> texte d'aperçu déchiffré
  convKeysCache: {},    // conversationId -> { keyId, rawKey } (clé de conversation déchiffrée, en mémoire)

  // Conversation ouverte
  openConv: null,       // résumé de la conversation ouverte
  messages: null,       // messages déchiffrés de la conversation ouverte
  messageInput: '',
  sendBusy: false,
  sendError: null,
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
  if (state.openConv) return renderConversation();
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

// ---------- Chargement des données ----------

async function loadMainData() {
  try {
    const { data: profile } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', state.user.id)
      .maybeSingle();
    const { data: members } = await supabase.from('profiles').select('*');
    set({ profile: profile || null, members: members || [] });
    loadConversations();
  } catch (_) {
    set({ members: [] });
  }
}

async function loadConversations() {
  const me = state.user.id;
  try {
    const { data: memberships } = await supabase
      .from('conversation_members')
      .select('conversation_id, encrypted_key, muted, archived')
      .eq('user_id', me);

    const list = [];
    for (const row of memberships || []) {
      if (row.archived || !row.encrypted_key) continue;
      const { data: conv } = await supabase.from('conversations').select('*').eq('id', row.conversation_id).maybeSingle();
      if (!conv || conv.archived) continue;
      const isGroup = conv.type === 'group';
      let label = conv.name || 'Groupe';
      if (!isGroup) {
        const { data: others } = await supabase.from('conversation_members').select('user_id').eq('conversation_id', row.conversation_id);
        const otherId = (others || []).map((o) => o.user_id).find((id) => id !== me);
        const other = (state.members || []).find((m) => m.id === otherId);
        label = other?.display_name?.trim() || other?.email || otherId?.slice(0, 8) || 'Membre';
      }
      const { data: lastRows } = await supabase
        .from('messages')
        .select('*')
        .eq('conversation_id', row.conversation_id)
        .order('sent_at', { ascending: false })
        .limit(1);
      const last = (lastRows || [])[0] || null;
      list.push({ id: row.conversation_id, encryptedKey: row.encrypted_key, isGroup, label, lastMessage: last, lastAt: last?.sent_at || null });
    }
    list.sort((a, b) => (b.lastAt || '').localeCompare(a.lastAt || ''));
    set({ conversations: list });
    if (state.identity) decryptAllPreviews(list);
  } catch (_) {
    set({ conversations: [] });
  }
}

async function getConvKey(conv) {
  if (state.convKeysCache[conv.id]) return state.convKeysCache[conv.id];
  const key = await unwrapConversationKey(state.identity.rawPrivateKey, state.identity.keyId, conv.encryptedKey);
  state.convKeysCache[conv.id] = key;
  return key;
}

function previewLabelFor(msg) {
  if (!msg) return 'Nouvelle conversation';
  if (msg.type === 'image') return '📷 Photo';
  if (msg.type === 'video') return '🎥 Vidéo';
  if (msg.type === 'voice') return '🎙️ Mémo vocal';
  if (msg.type === 'file') return '📎 Fichier';
  return null; // texte : à déchiffrer
}

async function decryptAllPreviews(list) {
  const previews = { ...state.previews };
  for (const conv of list) {
    const fixed = previewLabelFor(conv.lastMessage);
    if (fixed !== null) { previews[conv.id] = fixed; continue; }
    if (!conv.lastMessage?.ciphertext) { previews[conv.id] = '…'; continue; }
    try {
      const key = await getConvKey(conv);
      previews[conv.id] = await decryptMessage(key, conv.lastMessage.ciphertext);
    } catch (_) {
      previews[conv.id] = '🔒 (indéchiffrable)';
    }
  }
  set({ previews });
}

// ---------- Déverrouillage de l'identité (phrase secrète) ----------

function renderUnlockCard() {
  return `
    <div style="padding:16px 20px;border-bottom:1px solid #e5e0d5;background:#fdf6ec;">
      <div style="font-weight:700;font-size:14px;color:var(--forest);margin-bottom:4px;">🔒 Débloquer mes messages</div>
      <div class="hint" style="margin:0 0 10px;">
        Entre la phrase secrète utilisée pour sauvegarder ta clé sur Android (Réglages → Sauvegarder ma clé).
      </div>
      <form id="unlockForm" style="display:flex;gap:8px;max-width:420px;">
        <input type="password" id="passphrase" placeholder="Phrase secrète" required style="flex:1;" />
        <button type="submit" class="primary" style="width:auto;max-width:none;margin-top:0;padding:12px 18px;" ${state.unlockBusy ? 'disabled' : ''}>
          ${state.unlockBusy ? '…' : 'Déverrouiller'}
        </button>
      </form>
      ${state.unlockError ? `<div class="error">${escapeHtml(state.unlockError)}</div>` : ''}
    </div>
  `;
}

function wireUnlockEvents() {
  const form = document.getElementById('unlockForm');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const passphrase = document.getElementById('passphrase').value;
    if (!state.profile?.encrypted_private_key) {
      set({ unlockError: "Aucune sauvegarde de clé trouvée pour ce compte (fais-la d'abord depuis l'app Android)." });
      return;
    }
    set({ unlockBusy: true, unlockError: null });
    try {
      const identity = await restoreIdentityFromBackup(passphrase, state.profile.encrypted_private_key);
      set({ unlockBusy: false, identity });
      if (state.conversations) decryptAllPreviews(state.conversations);
    } catch (err) {
      set({ unlockBusy: false, unlockError: err.message || 'Déverrouillage impossible.' });
    }
  });
}

// ---------- Écran principal ----------

function initialsFor(name) {
  return (name || '?').trim().charAt(0).toUpperCase();
}

function timeLabel(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' }) + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  } catch (_) { return ''; }
}

function renderMain() {
  const email = state.user?.email || '—';
  const profile = state.profile;
  const displayName = profile?.display_name?.trim() || email;
  const members = (state.members || []).filter((m) => m.id !== state.user?.id && m.status === 'active');
  const convs = state.conversations;

  app.innerHTML = `
    <div class="topbar">
      Breeze
      <span class="sub">Phase 2 — web</span>
    </div>
    <div class="profile-row">
      <div class="avatar">${escapeHtml(initialsFor(displayName))}</div>
      <div>
        <div class="profile-name">${escapeHtml(displayName)}</div>
        <div class="profile-email">${escapeHtml(email)}</div>
      </div>
      <button class="signout" id="signOutBtn">Se déconnecter</button>
    </div>

    ${!state.identity ? renderUnlockCard() : ''}

    <div style="padding:14px 20px 4px;font-size:13px;font-weight:700;color:var(--green);">
      Conversations ${convs ? `(${convs.length})` : ''}
    </div>
    ${convs === null
      ? `<div class="empty">Chargement…</div>`
      : convs.length === 0
        ? `<div class="empty">Aucune conversation.</div>`
        : convs.map((c) => `
          <div class="list-item" data-conv="${c.id}" style="cursor:pointer;">
            <div class="avatar" style="width:40px;height:40px;">${escapeHtml(initialsFor(c.label))}</div>
            <div style="flex:1;min-width:0;">
              <div class="name">${escapeHtml(c.label)}${c.isGroup ? ' 👥' : ''}</div>
              <div class="preview">${escapeHtml(state.identity ? (state.previews[c.id] ?? '…') : '🔒 verrouillé')}</div>
            </div>
          </div>
        `).join('')}

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
  wireUnlockEvents();
  document.querySelectorAll('[data-conv]').forEach((el) => {
    el.addEventListener('click', () => openConversation(el.dataset.conv));
  });
}

// ---------- Conversation ouverte ----------

async function openConversation(convId) {
  const conv = (state.conversations || []).find((c) => c.id === convId);
  if (!conv) return;
  set({ openConv: conv, messages: null, sendError: null });
  try {
    const key = await getConvKey(conv);
    const { data: rows } = await supabase
      .from('messages')
      .select('*')
      .eq('conversation_id', convId)
      .order('sent_at', { ascending: true });
    const messages = [];
    for (const m of rows || []) {
      messages.push(await toDisplayMessage(m, key));
    }
    set({ messages });
    subscribeToConversation(convId, key);
  } catch (err) {
    set({ messages: [], sendError: 'Impossible de déchiffrer cette conversation : ' + (err.message || err) });
  }
}

async function toDisplayMessage(m, key) {
  const mine = m.sender_id === state.user.id;
  if (m.type !== 'text') {
    return { id: m.id, mine, sentAt: m.sent_at, text: previewLabelFor(m) + ' (non affiché sur le web pour l’instant)' };
  }
  try {
    const text = m.ciphertext ? await decryptMessage(key, m.ciphertext) : '';
    return { id: m.id, mine, sentAt: m.sent_at, text };
  } catch (_) {
    return { id: m.id, mine, sentAt: m.sent_at, text: '🔒 (indéchiffrable)' };
  }
}

let currentChannel = null;

function subscribeToConversation(convId, key) {
  if (currentChannel) { supabase.removeChannel(currentChannel); currentChannel = null; }
  currentChannel = supabase
    .channel('web-conv-' + convId)
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'messages', filter: `conversation_id=eq.${convId}` }, async (payload) => {
      if (!state.openConv || state.openConv.id !== convId) return;
      if ((state.messages || []).some((m) => m.id === payload.new.id)) return;
      const disp = await toDisplayMessage(payload.new, key);
      set({ messages: [...(state.messages || []), disp] });
    })
    .subscribe();
}

function closeConversation() {
  if (currentChannel) { supabase.removeChannel(currentChannel); currentChannel = null; }
  set({ openConv: null, messages: null, messageInput: '' });
  loadConversations();
}

function renderConversation() {
  const conv = state.openConv;
  const msgs = state.messages;
  app.innerHTML = `
    <div class="topbar">
      <button id="backBtn" style="background:none;border:none;color:#fff;font-size:20px;cursor:pointer;padding:0 6px 0 0;">‹</button>
      ${escapeHtml(conv.label)}${conv.isGroup ? ' 👥' : ''}
    </div>
    <div style="flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:8px;">
      ${msgs === null ? `<div class="spinner"></div>` :
        msgs.length === 0 ? `<div class="empty">Aucun message. Écris le premier — il sera chiffré de bout en bout. 🔒</div>` :
        msgs.map((m) => `
          <div style="align-self:${m.mine ? 'flex-end' : 'flex-start'};max-width:75%;">
            <div style="background:${m.mine ? 'var(--green)' : '#fff'};color:${m.mine ? '#fff' : 'var(--ink)'};padding:9px 13px;border-radius:14px;font-size:14px;border:${m.mine ? 'none' : '1px solid #e5e0d5'};">
              ${escapeHtml(m.text)}
            </div>
            <div style="font-size:10px;color:var(--sage);margin-top:2px;text-align:${m.mine ? 'right' : 'left'};">${timeLabel(m.sentAt)}</div>
          </div>
        `).join('')
      }
    </div>
    ${state.sendError ? `<div class="error" style="padding:0 16px;">${escapeHtml(state.sendError)}</div>` : ''}
    <form id="sendForm" style="display:flex;gap:8px;padding:10px 16px calc(10px + env(safe-area-inset-bottom));background:#fff;border-top:1px solid #e5e0d5;">
      <input type="text" id="messageInput" placeholder="Message chiffré…" autocomplete="off"
             value="${escapeHtml(state.messageInput)}" style="flex:1;padding:10px 14px;border:1px solid #cfc9bd;border-radius:20px;font-size:15px;" />
      <button type="submit" class="primary" style="width:auto;max-width:none;margin-top:0;padding:10px 18px;border-radius:20px;" ${state.sendBusy ? 'disabled' : ''}>➤</button>
    </form>
  `;

  document.getElementById('backBtn').addEventListener('click', closeConversation);
  const form = document.getElementById('sendForm');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if (!text) return;
    set({ sendBusy: true, sendError: null, messageInput: '' });
    try {
      const key = await getConvKey(conv);
      const ciphertext = await encryptMessage(key, text);
      const { error } = await supabase.from('messages').insert({
        conversation_id: conv.id,
        sender_id: state.user.id,
        ciphertext,
        type: 'text',
      });
      if (error) throw error;
      set({ sendBusy: false });
    } catch (err) {
      set({ sendBusy: false, sendError: "Échec de l'envoi : " + (err.message || err), messageInput: text });
    }
  });
}

// ---------- Démarrage ----------

supabase.auth.onAuthStateChange((_event, session) => {
  if (session?.user) {
    set({ screen: 'main', user: session.user });
    loadMainData();
  } else {
    if (currentChannel) { supabase.removeChannel(currentChannel); currentChannel = null; }
    set({
      screen: 'auth', user: null, profile: null, members: [], identity: null,
      conversations: null, previews: {}, convKeysCache: {}, openConv: null, messages: null,
    });
  }
});

render();
