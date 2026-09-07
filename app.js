import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { restoreIdentityFromBackup, unwrapConversationKey, decryptMessage, encryptMessage, decryptRaw, encryptRaw } from './tink-hpke.js';

const MEDIA_BUCKET = 'media';

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
  mediaUrls: {},         // messageId -> object URL (image/vocal déchiffré), une fois prête
  fileDownloadBusy: null, // id du message fichier en cours de téléchargement, ou null
  recording: false,
  recordElapsedMs: 0,
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
  if (m.type === 'image') {
    loadImage(m.id, m.media_path, key);
    return { id: m.id, mine, sentAt: m.sent_at, type: 'image' };
  }
  if (m.type === 'file') {
    let fileName = 'Fichier';
    try { if (m.ciphertext) fileName = await decryptMessage(key, m.ciphertext); } catch (_) {}
    return { id: m.id, mine, sentAt: m.sent_at, type: 'file', fileName, mediaPath: m.media_path };
  }
  if (m.type === 'voice') {
    loadImage(m.id, m.media_path, key, sniffAudioMimeType);
    return { id: m.id, mine, sentAt: m.sent_at, type: 'voice' };
  }
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

/**
 * Détecte le vrai conteneur audio à partir des octets (Chrome enregistre en webm/opus, Safari/
 * Android en mp4/AAC — impossible de le deviner à l'avance, il faut regarder le contenu réel).
 */
function sniffAudioMimeType(bytes) {
  if (bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) return 'audio/webm';
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) return 'audio/wav';
  return 'audio/mp4';
}

/**
 * Télécharge + déchiffre un média (image/vocal) et publie son URL objet dans state.mediaUrls.
 * [mimeType] est soit une chaîne fixe, soit une fonction(bytes) → chaîne (détection par contenu).
 */
async function loadImage(messageId, mediaPath, key, mimeType = 'image/jpeg') {
  if (state.mediaUrls[messageId]) return;
  try {
    const { data, error } = await supabase.storage.from(MEDIA_BUCKET).download(mediaPath);
    if (error) throw error;
    const encBytes = new Uint8Array(await data.arrayBuffer());
    const plainBytes = await decryptRaw(key, encBytes);
    const type = typeof mimeType === 'function' ? mimeType(plainBytes) : mimeType;
    const blob = new Blob([plainBytes], { type });
    const url = URL.createObjectURL(blob);
    set({ mediaUrls: { ...state.mediaUrls, [messageId]: url } });
  } catch (_) {
    set({ mediaUrls: { ...state.mediaUrls, [messageId]: 'error' } });
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
            ${renderBubbleContent(m)}
            <div style="font-size:10px;color:var(--sage);margin-top:2px;text-align:${m.mine ? 'right' : 'left'};">${timeLabel(m.sentAt)}</div>
          </div>
        `).join('')
      }
    </div>
    ${state.sendError ? `<div class="error" style="padding:0 16px;">${escapeHtml(state.sendError)}</div>` : ''}
    ${state.recording ? `
    <div style="display:flex;gap:8px;align-items:center;padding:10px 16px calc(10px + env(safe-area-inset-bottom));background:#fff;border-top:1px solid #e5e0d5;">
      <div style="flex:1;display:flex;align-items:center;gap:8px;color:var(--error);font-size:14px;">
        <span style="width:10px;height:10px;border-radius:50%;background:var(--error);"></span>
        Enregistrement… ${recTimeLabel(state.recordElapsedMs)}
      </div>
      <button type="button" id="stopRecBtn" class="primary" style="width:auto;max-width:none;margin-top:0;padding:10px 18px;border-radius:20px;background:var(--error);">⏹ Envoyer</button>
    </div>
    ` : `
    <form id="sendForm" style="display:flex;gap:8px;align-items:center;padding:10px 16px calc(10px + env(safe-area-inset-bottom));background:#fff;border-top:1px solid #e5e0d5;">
      <input type="file" id="imageInput" accept="image/*" style="display:none;" />
      <input type="file" id="fileInput" style="display:none;" />
      <button type="button" id="attachBtn" style="background:none;border:none;font-size:22px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>📷</button>
      <button type="button" id="attachFileBtn" style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>📎</button>
      <button type="button" id="recordBtn" style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>🎙️</button>
      <input type="text" id="messageInput" placeholder="Message chiffré…" autocomplete="off"
             value="${escapeHtml(state.messageInput)}" style="flex:1;padding:10px 14px;border:1px solid #cfc9bd;border-radius:20px;font-size:15px;" />
      <button type="submit" class="primary" style="width:auto;max-width:none;margin-top:0;padding:10px 18px;border-radius:20px;" ${state.sendBusy ? 'disabled' : ''}>➤</button>
    </form>
    `}
  `;

  document.getElementById('backBtn').addEventListener('click', closeConversation);

  if (state.recording) {
    document.getElementById('stopRecBtn').addEventListener('click', () => stopRecording());
  } else {
    const imageInput = document.getElementById('imageInput');
    document.getElementById('attachBtn').addEventListener('click', () => imageInput.click());
    imageInput.addEventListener('change', async () => {
      const file = imageInput.files[0];
      imageInput.value = '';
      if (file) await sendImage(conv, file);
    });

    const fileInput = document.getElementById('fileInput');
    document.getElementById('attachFileBtn').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files[0];
      fileInput.value = '';
      if (file) await sendFile(conv, file);
    });

    document.getElementById('recordBtn').addEventListener('click', () => startRecording(conv));
  }

  document.querySelectorAll('[data-file-msg]').forEach((el) => {
    el.addEventListener('click', () => downloadFile(conv, el.dataset.fileMsg));
  });

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

function renderBubbleContent(m) {
  const bg = m.mine ? 'var(--green)' : '#fff';
  const border = m.mine ? 'none' : '1px solid #e5e0d5';
  if (m.type === 'image') {
    const url = state.mediaUrls[m.id];
    const inner = !url
      ? `<div style="width:200px;height:140px;display:flex;align-items:center;justify-content:center;"><div class="spinner" style="margin:0;"></div></div>`
      : url === 'error'
        ? `<div style="padding:20px;color:${m.mine ? '#fff' : 'var(--ink)'};">🖼️ Image indéchiffrable</div>`
        : `<img src="${url}" style="display:block;max-width:260px;max-height:320px;border-radius:14px;" />`;
    return `<div style="border-radius:14px;overflow:hidden;background:${bg};border:${border};">${inner}</div>`;
  }
  if (m.type === 'file') {
    const busy = state.fileDownloadBusy === m.id;
    return `
      <div class="file-bubble" data-file-msg="${m.id}"
           style="display:flex;align-items:center;gap:10px;cursor:pointer;background:${bg};color:${m.mine ? '#fff' : 'var(--ink)'};padding:10px 14px;border-radius:14px;font-size:14px;border:${border};max-width:260px;">
        <span style="font-size:20px;">${busy ? '⏳' : '📎'}</span>
        <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(m.fileName)}</span>
      </div>
    `;
  }
  if (m.type === 'voice') {
    const url = state.mediaUrls[m.id];
    const inner = !url
      ? `<div class="spinner" style="margin:4px;width:20px;height:20px;border-width:2px;"></div>`
      : url === 'error'
        ? `<span>🎙️ Vocal indéchiffrable</span>`
        : `<audio controls preload="none" src="${url}" style="height:36px;max-width:230px;"></audio>`;
    return `
      <div style="display:flex;align-items:center;background:${bg};color:${m.mine ? '#fff' : 'var(--ink)'};padding:8px 12px;border-radius:14px;font-size:14px;border:${border};">
        ${inner}
      </div>
    `;
  }
  return `
    <div style="background:${bg};color:${m.mine ? '#fff' : 'var(--ink)'};padding:9px 13px;border-radius:14px;font-size:14px;border:${border};">
      ${escapeHtml(m.text)}
    </div>
  `;
}

/** Compresse une image (max 1600px, JPEG q80 — même réglages qu'Android) via canvas. */
async function compressImageFile(file, maxDim = 1600, quality = 0.8) {
  const bitmap = await createImageBitmap(file);
  const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height));
  const w = Math.max(1, Math.round(bitmap.width * scale));
  const h = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w; canvas.height = h;
  canvas.getContext('2d').drawImage(bitmap, 0, 0, w, h);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
  return new Uint8Array(await blob.arrayBuffer());
}

async function sendImage(conv, file) {
  set({ sendBusy: true, sendError: null });
  try {
    const jpeg = await compressImageFile(file);
    const key = await getConvKey(conv);
    const encrypted = await encryptRaw(key, jpeg);
    const path = `${conv.id}/${crypto.randomUUID()}.enc`;
    const { error: upErr } = await supabase.storage.from(MEDIA_BUCKET).upload(path, encrypted, { contentType: 'application/octet-stream' });
    if (upErr) throw upErr;
    const { error } = await supabase.from('messages').insert({
      conversation_id: conv.id,
      sender_id: state.user.id,
      type: 'image',
      media_path: path,
      media_size: encrypted.byteLength,
    });
    if (error) throw error;
    set({ sendBusy: false });
  } catch (err) {
    set({ sendBusy: false, sendError: "Échec de l'envoi de l'image : " + (err.message || err) });
  }
}

const MAX_UPLOAD_BYTES = 50_000_000; // même plafond que l'app Android (Storage gratuit 50 Mo/fichier)

async function sendFile(conv, file) {
  if (file.size > MAX_UPLOAD_BYTES) {
    set({ sendError: `Fichier trop volumineux : ${Math.round(file.size / 1_000_000)} Mo (maximum 50 Mo).` });
    return;
  }
  set({ sendBusy: true, sendError: null });
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const key = await getConvKey(conv);
    const encrypted = await encryptRaw(key, bytes);
    const path = `${conv.id}/${crypto.randomUUID()}.enc`;
    const { error: upErr } = await supabase.storage.from(MEDIA_BUCKET).upload(path, encrypted, { contentType: 'application/octet-stream' });
    if (upErr) throw upErr;
    const ciphertext = await encryptMessage(key, file.name);
    const { error } = await supabase.from('messages').insert({
      conversation_id: conv.id,
      sender_id: state.user.id,
      type: 'file',
      media_path: path,
      media_size: encrypted.byteLength,
      ciphertext,
    });
    if (error) throw error;
    set({ sendBusy: false });
  } catch (err) {
    set({ sendBusy: false, sendError: "Échec de l'envoi du fichier : " + (err.message || err) });
  }
}

/** Télécharge + déchiffre un fichier et déclenche l'enregistrement dans le navigateur. */
async function downloadFile(conv, messageId) {
  const m = (state.messages || []).find((x) => x.id === messageId);
  if (!m || m.type !== 'file' || state.fileDownloadBusy) return;
  set({ fileDownloadBusy: messageId, sendError: null });
  try {
    const key = await getConvKey(conv);
    const { data, error } = await supabase.storage.from(MEDIA_BUCKET).download(m.mediaPath);
    if (error) throw error;
    const encBytes = new Uint8Array(await data.arrayBuffer());
    const plainBytes = await decryptRaw(key, encBytes);
    const blob = new Blob([plainBytes]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = m.fileName || 'fichier';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    set({ fileDownloadBusy: null });
  } catch (err) {
    set({ fileDownloadBusy: null, sendError: "Échec du téléchargement : " + (err.message || err) });
  }
}

// ---------- Mémos vocaux ----------

let mediaRecorder = null;
let recordedChunks = [];
let recordTimer = null;
let recordStream = null;
let recordStartedAt = 0;

function recTimeLabel(ms) {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** Préfère audio/mp4 (AAC) — lisible nativement par l'app Android, et supporté par Safari iOS. */
function pickAudioMimeType() {
  const candidates = ['audio/mp4', 'audio/mp4;codecs=mp4a.40.2', 'audio/webm;codecs=opus', 'audio/webm'];
  for (const c of candidates) {
    if (window.MediaRecorder && MediaRecorder.isTypeSupported(c)) return c;
  }
  return '';
}

/** Encode un AudioBuffer décodé en WAV PCM 16 bits (format universellement lisible). */
function encodeWav(audioBuffer) {
  const numChannels = audioBuffer.numberOfChannels;
  const sampleRate = audioBuffer.sampleRate;
  const numFrames = audioBuffer.length;
  const blockAlign = numChannels * 2;
  const dataSize = numFrames * blockAlign;
  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);
  const writeStr = (offset, str) => { for (let i = 0; i < str.length; i++) view.setUint8(offset + i, str.charCodeAt(i)); };
  writeStr(0, 'RIFF');
  view.setUint32(4, 36 + dataSize, true);
  writeStr(8, 'WAVE');
  writeStr(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true); // PCM
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * blockAlign, true);
  view.setUint16(32, blockAlign, true);
  view.setUint16(34, 16, true);
  writeStr(36, 'data');
  view.setUint32(40, dataSize, true);
  const channels = [];
  for (let c = 0; c < numChannels; c++) channels.push(audioBuffer.getChannelData(c));
  let offset = 44;
  for (let i = 0; i < numFrames; i++) {
    for (let c = 0; c < numChannels; c++) {
      let sample = Math.max(-1, Math.min(1, channels[c][i]));
      sample = sample < 0 ? sample * 0x8000 : sample * 0x7fff;
      view.setInt16(offset, sample, true);
      offset += 2;
    }
  }
  return new Uint8Array(buffer);
}

/** Décode un enregistrement (webm/opus, mp4/AAC…) et le ré-encode en WAV. */
async function blobToWavBytes(blob) {
  const arrayBuf = await blob.arrayBuffer();
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const ctx = new AudioCtx();
  try {
    const audioBuffer = await ctx.decodeAudioData(arrayBuf);
    return encodeWav(audioBuffer);
  } finally {
    ctx.close();
  }
}

async function startRecording(conv) {
  if (state.recording) return;
  try {
    recordStream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (err) {
    set({ sendError: 'Microphone indisponible : ' + (err.message || err) });
    return;
  }
  const mimeType = pickAudioMimeType();
  recordedChunks = [];
  mediaRecorder = new MediaRecorder(recordStream, mimeType ? { mimeType } : undefined);
  recordStartedAt = Date.now();
  mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) recordedChunks.push(e.data); };
  mediaRecorder.onstop = async () => {
    recordStream.getTracks().forEach((t) => t.stop());
    recordStream = null;
    clearInterval(recordTimer);
    const durationMs = Date.now() - recordStartedAt;
    const rawBlob = new Blob(recordedChunks, { type: mediaRecorder.mimeType || mimeType || 'audio/webm' });
    set({ recording: false, recordElapsedMs: 0 });
    if (durationMs < 500) return;
    try {
      // Conversion systématique en WAV (PCM) : le format que produit Chrome (webm/opus) n'est
      // pas fiable sur le lecteur audio natif Android — le WAV, non compressé, l'est toujours.
      const wavBytes = await blobToWavBytes(rawBlob);
      await sendVoice(conv, new Blob([wavBytes], { type: 'audio/wav' }), durationMs);
    } catch (err) {
      set({ sendError: "Conversion audio impossible : " + (err.message || err) });
    }
  };
  mediaRecorder.start();
  set({ recording: true, recordElapsedMs: 0, sendError: null });
  recordTimer = setInterval(() => set({ recordElapsedMs: Date.now() - recordStartedAt }), 250);
}

function stopRecording() {
  if (mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
}

async function sendVoice(conv, blob, durationMs) {
  set({ sendBusy: true, sendError: null });
  try {
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const key = await getConvKey(conv);
    const encrypted = await encryptRaw(key, bytes);
    const path = `${conv.id}/${crypto.randomUUID()}.enc`;
    const { error: upErr } = await supabase.storage.from(MEDIA_BUCKET).upload(path, encrypted, { contentType: 'application/octet-stream' });
    if (upErr) throw upErr;
    const { error } = await supabase.from('messages').insert({
      conversation_id: conv.id,
      sender_id: state.user.id,
      type: 'voice',
      media_path: path,
      media_size: encrypted.byteLength,
      duration_ms: Math.round(durationMs),
    });
    if (error) throw error;
    set({ sendBusy: false });
  } catch (err) {
    set({ sendBusy: false, sendError: "Échec de l'envoi du vocal : " + (err.message || err) });
  }
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
