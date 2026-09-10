import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { restoreIdentityFromBackup, unwrapConversationKey, decryptMessage, encryptMessage, decryptRaw, encryptRaw, newConversationKey, wrapConversationKey, parseTinkPublicKeyJson } from './tink-hpke.js';

const MEDIA_BUCKET = 'media';

// Même projet Supabase que l'app Android — même cercle, mêmes comptes.
const SUPABASE_URL = 'https://yywirxlbbydwsbviansf.supabase.co';
const SUPABASE_KEY = 'sb_publishable_v2LhzpWPrzh7fonZ16d5uQ_IGyxk89H';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const app = document.getElementById('app');

// ---------- Cache local de l'identité déverrouillée (IndexedDB) ----------
// Évite de resaisir la phrase secrète à chaque rechargement de page, comme l'app Android (dont la
// clé privée vit dans l'Android Keystore, accessible sans re-saisie). Choix assumé par l'utilisateur
// (07/09/2026) : la clé privée reste en clair dans le stockage du navigateur (protégé par l'origine
// du site) plutôt qu'en mémoire JS seulement — acceptable pour un usage personnel sur son propre
// appareil, comme le fait déjà l'app native.
const IDENTITY_DB_NAME = 'breeze-identity';
const IDENTITY_STORE = 'identities';

function openIdentityDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDENTITY_DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(IDENTITY_STORE, { keyPath: 'userId' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function saveIdentityToCache(userId, identity) {
  const db = await openIdentityDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(IDENTITY_STORE, 'readwrite');
    tx.objectStore(IDENTITY_STORE).put({ userId, ...identity });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function loadIdentityFromCache(userId) {
  const db = await openIdentityDb();
  const row = await new Promise((resolve, reject) => {
    const tx = db.transaction(IDENTITY_STORE, 'readonly');
    const req = tx.objectStore(IDENTITY_STORE).get(userId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
  db.close();
  if (!row) return null;
  return { keyId: row.keyId, rawPrivateKey: row.rawPrivateKey, rawPublicKey: row.rawPublicKey };
}

async function clearIdentityCache(userId) {
  if (!userId) return;
  const db = await openIdentityDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(IDENTITY_STORE, 'readwrite');
    tx.objectStore(IDENTITY_STORE).delete(userId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

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
  mediaUrls: {},         // messageId -> object URL (image/vocal/vidéo déchiffré), une fois prête
  fileDownloadBusy: null, // id du message fichier en cours de téléchargement, ou null
  recording: false,
  recordElapsedMs: 0,
  videoProcessing: false,

  // Nouveau groupe (modale sur l'accueil)
  newGroupOpen: false,
  newGroupBusy: false,

  // Administration (owner) — miroir de SettingsScreen.AdminView côté Android
  showAdmin: false,
  admin: {
    members: null,         // liste complète des profils (dont role/status/category)
    allowlist: null,       // e-mails invités (table allowlist)
    conversations: null,   // AdminConversationSummary[]
    joinRequests: null,    // demandes d'ajout en attente
    usage: null,           // UsageStats
    busy: false,
    memberSearch: '',
    memberShowCount: 10,
    convSearch: '',
    convShowCount: 10,
    statusTargetId: null,      // id du membre dont on édite statut/catégorie
    confirmRevokeEmail: null,
    confirmDeleteConvId: null,
    confirmGlobalPurge: false,
    purgeResult: null,
  },
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
  if (state.showAdmin) return renderAdmin();
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
    if (!state.identity) {
      try {
        const cached = await loadIdentityFromCache(state.user.id);
        if (cached) set({ identity: cached });
      } catch (_) {}
    }
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
      let otherUid = null;
      if (!isGroup) {
        const { data: others } = await supabase.from('conversation_members').select('user_id').eq('conversation_id', row.conversation_id);
        otherUid = (others || []).map((o) => o.user_id).find((id) => id !== me) || null;
        const other = (state.members || []).find((m) => m.id === otherUid);
        label = other?.display_name?.trim() || other?.email || otherUid?.slice(0, 8) || 'Membre';
      }
      const { data: lastRows } = await supabase
        .from('messages')
        .select('*')
        .eq('conversation_id', row.conversation_id)
        .order('sent_at', { ascending: false })
        .limit(1);
      const last = (lastRows || [])[0] || null;
      list.push({ id: row.conversation_id, encryptedKey: row.encrypted_key, isGroup, otherUid, label, lastMessage: last, lastAt: last?.sent_at || null });
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

// ---------- Création de conversations/groupes (écriture de clés Tink — miroir de Conversations.kt) ----------

function dmKeyOf(a, b) {
  return [a, b].sort().join(':');
}

function myPublicKeyInfo() {
  return { keyId: state.identity.keyId, rawPublicKey: state.identity.rawPublicKey };
}

/** Ouvre le DM avec [member] (le retrouve s'il existe, sinon le crée) puis l'affiche. */
async function openOrCreateDmWeb(member) {
  const me = state.user?.id;
  if (!me || !member?.id || member.id === me) return;
  try {
    const key = dmKeyOf(me, member.id);
    const { data: existing } = await supabase.from('conversations').select('*').eq('dm_key', key).maybeSingle();
    let convId, encryptedKeyRow;
    if (existing) {
      const { data: myMember } = await supabase.from('conversation_members')
        .select('encrypted_key').eq('conversation_id', existing.id).eq('user_id', me).maybeSingle();
      if (!myMember?.encrypted_key) throw new Error('Conversation introuvable ou corrompue.');
      convId = existing.id;
      encryptedKeyRow = myMember.encrypted_key;
    } else {
      if (!member.public_key) throw new Error("Ce membre n'a pas encore de clé de chiffrement (il doit ouvrir l'app une fois).");
      const { keysetBinary } = newConversationKey();
      const otherPub = parseTinkPublicKeyJson(member.public_key);
      const myWrapped = await wrapConversationKey(myPublicKeyInfo(), keysetBinary);
      const otherWrapped = await wrapConversationKey(otherPub, keysetBinary);
      const { data: conv, error: convErr } = await supabase.from('conversations')
        .insert({ type: 'direct', dm_key: key, created_by: me }).select().single();
      if (convErr) throw convErr;
      const { error: memErr } = await supabase.from('conversation_members').insert([
        { conversation_id: conv.id, user_id: me, encrypted_key: myWrapped },
        { conversation_id: conv.id, user_id: member.id, encrypted_key: otherWrapped },
      ]);
      if (memErr) throw memErr;
      convId = conv.id;
      encryptedKeyRow = myWrapped;
    }
    const summary = {
      id: convId, encryptedKey: encryptedKeyRow, isGroup: false, otherUid: member.id,
      label: member.display_name?.trim() || member.email || member.id.slice(0, 8),
      lastMessage: null, lastAt: null,
    };
    const list = state.conversations || [];
    if (!list.some((c) => c.id === convId)) set({ conversations: [summary, ...list] });
    openConversation(convId);
  } catch (err) {
    alert("Impossible d'ouvrir la conversation : " + (err.message || err));
  }
}

/** Crée un groupe [name] avec [memberIds] (+ moi) — génère la clé de conv, la chiffre pour chaque
 * membre ayant une clé publique. Retourne l'id créé, ou null en cas d'échec. */
async function createGroupWeb(name, memberIds) {
  const me = state.user?.id;
  if (!me) return null;
  try {
    const ids = Array.from(new Set([...memberIds, me]));
    const profiles = (state.members || []).filter((m) => ids.includes(m.id));
    const { keysetBinary } = newConversationKey();
    const { data: conv, error: convErr } = await supabase.from('conversations')
      .insert({ type: 'group', dm_key: 'group:' + crypto.randomUUID(), created_by: me, name })
      .select().single();
    if (convErr) throw convErr;
    const inserts = [];
    for (const p of profiles) {
      const pubInfo = p.id === me ? myPublicKeyInfo() : (p.public_key ? parseTinkPublicKeyJson(p.public_key) : null);
      if (!pubInfo) continue;
      const wrapped = await wrapConversationKey(pubInfo, keysetBinary);
      inserts.push({ conversation_id: conv.id, user_id: p.id, encrypted_key: wrapped });
    }
    if (inserts.length) {
      const { error: memErr } = await supabase.from('conversation_members').insert(inserts);
      if (memErr) throw memErr;
    }
    return conv.id;
  } catch (err) {
    alert('Impossible de créer le groupe : ' + (err.message || err));
    return null;
  }
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
      try { await saveIdentityToCache(state.user.id, identity); } catch (_) {}
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
      ${profile?.role === 'owner' ? `<button class="signout" id="adminBtn" style="color:var(--green);margin-left:auto;">⚙ Administration</button>` : ''}
      <button class="signout" id="signOutBtn" style="${profile?.role === 'owner' ? 'margin-left:12px;' : 'margin-left:auto;'}">Se déconnecter</button>
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

    <div style="padding:14px 20px 4px;display:flex;align-items:center;justify-content:space-between;">
      <span style="font-size:13px;font-weight:700;color:var(--green);">Membres du cercle (${members.length})</span>
      <button type="button" id="newGroupBtn" style="background:none;border:1px solid var(--green);color:var(--green);border-radius:14px;padding:4px 10px;font-size:12px;cursor:pointer;">+ Groupe</button>
    </div>
    ${members.length === 0
      ? `<div class="empty">Aucun membre.</div>`
      : members.map((m) => `
        <div class="list-item" data-member="${m.id}" style="cursor:pointer;">
          <div class="avatar" style="width:36px;height:36px;font-size:14px;">${escapeHtml(initialsFor(m.display_name || m.email))}</div>
          <div>
            <div class="name">${escapeHtml(m.display_name?.trim() || m.email || m.id.slice(0, 8))}</div>
            ${m.display_name?.trim() && m.email ? `<div class="preview">${escapeHtml(m.email)}</div>` : ''}
          </div>
        </div>
      `).join('')}
    ${renderNewGroupModal()}
  `;

  document.getElementById('signOutBtn').addEventListener('click', async () => {
    try { await clearIdentityCache(state.user?.id); } catch (_) {}
    await supabase.auth.signOut();
  });
  const adminBtn = document.getElementById('adminBtn');
  if (adminBtn) adminBtn.addEventListener('click', () => { set({ showAdmin: true }); loadAdminData(); });
  wireUnlockEvents();
  document.querySelectorAll('[data-conv]').forEach((el) => {
    el.addEventListener('click', () => openConversation(el.dataset.conv));
  });
  document.querySelectorAll('[data-member]').forEach((el) => {
    el.addEventListener('click', () => {
      const m = (state.members || []).find((x) => x.id === el.dataset.member);
      if (m) openOrCreateDmWeb(m);
    });
  });
  const newGroupBtn = document.getElementById('newGroupBtn');
  if (newGroupBtn) newGroupBtn.addEventListener('click', () => set({ newGroupOpen: true }));
  wireNewGroupModalEvents();
}

function renderNewGroupModal() {
  if (!state.newGroupOpen) return '';
  const members = (state.members || []).filter((m) => m.id !== state.user?.id && m.status === 'active');
  return `
    <div id="newGroupOverlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:50;padding:20px;">
      <div style="background:#fff;border-radius:14px;padding:20px;max-width:420px;width:100%;max-height:80vh;overflow-y:auto;">
        <div style="font-weight:700;font-size:16px;margin-bottom:12px;color:var(--forest);">Nouveau groupe</div>
        <input type="text" id="newGroupName" placeholder="Nom du groupe"
               style="width:100%;padding:10px 14px;border:1px solid #cfc9bd;border-radius:10px;font-size:15px;margin-bottom:12px;box-sizing:border-box;" />
        <div style="font-size:13px;font-weight:700;color:var(--green);margin-bottom:6px;">Membres</div>
        ${members.length === 0 ? `<div class="empty">Aucun membre.</div>` : members.map((m) => `
          <label style="display:flex;align-items:center;gap:10px;padding:8px 0;cursor:pointer;">
            <input type="checkbox" data-newgroup-member="${m.id}" />
            <span>${escapeHtml(m.display_name?.trim() || m.email || m.id.slice(0, 8))}</span>
          </label>
        `).join('')}
        ${state.newGroupBusy ? `<div class="hint" style="margin-top:8px;">Création…</div>` : ''}
        <div style="display:flex;gap:10px;margin-top:16px;">
          <button type="button" id="newGroupCancel" style="flex:1;padding:10px;border-radius:10px;border:1px solid #cfc9bd;background:#fff;cursor:pointer;" ${state.newGroupBusy ? 'disabled' : ''}>Annuler</button>
          <button type="button" id="newGroupCreate" class="primary" style="flex:1;margin-top:0;" ${state.newGroupBusy ? 'disabled' : ''}>Créer</button>
        </div>
      </div>
    </div>
  `;
}

function wireNewGroupModalEvents() {
  const cancelBtn = document.getElementById('newGroupCancel');
  if (cancelBtn) cancelBtn.addEventListener('click', () => set({ newGroupOpen: false }));
  const createBtn = document.getElementById('newGroupCreate');
  if (createBtn) {
    createBtn.addEventListener('click', async () => {
      const name = document.getElementById('newGroupName').value.trim();
      const selected = Array.from(document.querySelectorAll('[data-newgroup-member]:checked')).map((el) => el.dataset.newgroupMember);
      if (!name) { alert('Donne un nom au groupe.'); return; }
      if (selected.length === 0) { alert('Sélectionne au moins un membre.'); return; }
      set({ newGroupBusy: true });
      const id = await createGroupWeb(name, selected);
      set({ newGroupBusy: false, newGroupOpen: false });
      if (id) await loadConversations();
    });
  }
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
  if (m.type === 'video') {
    loadImage(m.id, m.media_path, key, 'video/mp4');
    return { id: m.id, mine, sentAt: m.sent_at, type: 'video' };
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
      <span style="flex:1;">${escapeHtml(conv.label)}${conv.isGroup ? ' 👥' : ''}</span>
      ${!conv.isGroup && conv.otherUid ? `
        <button id="callAudioBtn" style="background:none;border:none;color:#fff;font-size:18px;cursor:pointer;padding:4px 8px;">📞</button>
        <button id="callVideoBtn" style="background:none;border:none;color:#fff;font-size:18px;cursor:pointer;padding:4px 8px;">🎥</button>
      ` : ''}
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
    ${state.videoProcessing ? `
    <div style="display:flex;gap:8px;align-items:center;padding:10px 16px calc(10px + env(safe-area-inset-bottom));background:#fff;border-top:1px solid #e5e0d5;color:var(--sage);font-size:14px;">
      <div class="spinner" style="margin:0;width:18px;height:18px;border-width:2px;"></div>
      Compression de la vidéo…
    </div>
    ` : state.recording ? `
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
      <input type="file" id="videoInput" accept="video/*" style="display:none;" />
      <input type="file" id="fileInput" style="display:none;" />
      <button type="button" id="attachBtn" style="background:none;border:none;font-size:22px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>📷</button>
      <button type="button" id="attachVideoBtn" style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>🎥</button>
      <button type="button" id="attachFileBtn" style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>📎</button>
      <button type="button" id="recordBtn" style="background:none;border:none;font-size:20px;cursor:pointer;padding:4px;" ${state.sendBusy ? 'disabled' : ''}>🎙️</button>
      <input type="text" id="messageInput" placeholder="Message chiffré…" autocomplete="off"
             value="${escapeHtml(state.messageInput)}" style="flex:1;padding:10px 14px;border:1px solid #cfc9bd;border-radius:20px;font-size:15px;" />
      <button type="submit" class="primary" style="width:auto;max-width:none;margin-top:0;padding:10px 18px;border-radius:20px;" ${state.sendBusy ? 'disabled' : ''}>➤</button>
    </form>
    `}
  `;

  document.getElementById('backBtn').addEventListener('click', closeConversation);
  const callAudioBtn = document.getElementById('callAudioBtn');
  if (callAudioBtn) callAudioBtn.addEventListener('click', () => startCall(conv.otherUid, conv.label, 'audio'));
  const callVideoBtn = document.getElementById('callVideoBtn');
  if (callVideoBtn) callVideoBtn.addEventListener('click', () => startCall(conv.otherUid, conv.label, 'video'));

  if (state.videoProcessing) {
    // Rien à câbler : seul l'indicateur de compression est affiché.
  } else if (state.recording) {
    document.getElementById('stopRecBtn').addEventListener('click', () => stopRecording());
  } else {
    const imageInput = document.getElementById('imageInput');
    document.getElementById('attachBtn').addEventListener('click', () => imageInput.click());
    imageInput.addEventListener('change', async () => {
      const file = imageInput.files[0];
      imageInput.value = '';
      if (file) await sendImage(conv, file);
    });

    const videoInput = document.getElementById('videoInput');
    document.getElementById('attachVideoBtn').addEventListener('click', () => videoInput.click());
    videoInput.addEventListener('change', async () => {
      const file = videoInput.files[0];
      videoInput.value = '';
      if (file) await sendVideo(conv, file);
    });

    const fileInput = document.getElementById('fileInput');
    document.getElementById('attachFileBtn').addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
      const file = fileInput.files[0];
      fileInput.value = '';
      if (file) await sendFile(conv, file);
    });

    document.getElementById('recordBtn').addEventListener('click', () => startRecording(conv));

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

  document.querySelectorAll('[data-file-msg]').forEach((el) => {
    el.addEventListener('click', () => downloadFile(conv, el.dataset.fileMsg));
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
  if (m.type === 'video') {
    const url = state.mediaUrls[m.id];
    const inner = !url
      ? `<div style="width:200px;height:140px;display:flex;align-items:center;justify-content:center;"><div class="spinner" style="margin:0;"></div></div>`
      : url === 'error'
        ? `<div style="padding:20px;color:${m.mine ? '#fff' : 'var(--ink)'};">🎥 Vidéo indéchiffrable</div>`
        : `<video controls preload="none" src="${url}" style="display:block;max-width:260px;max-height:320px;border-radius:14px;"></video>`;
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

/** Compresse une image (max 1600px comme Android, JPEG q65 — qualité réduite pour économiser le
 * quota Storage ; la résolution reste identique à Android donc aucune divergence de rendu, seule
 * la qualité JPEG change, ce qui n'affecte pas la compatibilité de lecture côté Android). */
async function compressImageFile(file, maxDim = 1600, quality = 0.65) {
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

// ---------- Vidéos ----------

const MAX_VIDEO_DURATION_S = 60; // limite courte pour maîtriser le quota Storage gratuit (1 Go)
const VIDEO_MAX_DIM = 640; // comme pour la voix, résolution réduite = fichiers bien plus petits
const VIDEO_BITRATE = 800_000; // ~800 kbit/s, qualité correcte pour un message vidéo court

function getVideoDuration(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const v = document.createElement('video');
    v.preload = 'metadata';
    v.onloadedmetadata = () => { URL.revokeObjectURL(url); resolve(v.duration); };
    v.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Vidéo illisible')); };
    v.src = url;
  });
}

/** Préfère video/mp4 (H.264/AAC) — natif sur Safari iOS, lisible directement par Android. */
function pickVideoMimeType() {
  const candidates = ['video/mp4', 'video/mp4;codecs=avc1', 'video/webm;codecs=vp9', 'video/webm'];
  for (const c of candidates) {
    if (window.MediaRecorder && MediaRecorder.isTypeSupported(c)) return c;
  }
  return '';
}

/**
 * Ré-encode une vidéo en la rejouant dans un <video> caché, en dessinant chaque frame réduite sur
 * un canvas, et en ré-enregistrant le résultat (image + son) via MediaRecorder. Pas de dépendance
 * externe : une bibliothèque de transcodage (ffmpeg.wasm) a été testée mais s'est montrée trop
 * lourde (~30 Mo) et peu fiable (chargement qui reste bloqué sans erreur) — cette approche ne
 * réutilise que des API navigateur déjà en place pour les mémos vocaux.
 */
async function recompressVideoFile(file) {
  const url = URL.createObjectURL(file);
  const video = document.createElement('video');
  video.src = url;
  video.muted = false;
  video.playsInline = true;
  await new Promise((resolve, reject) => {
    video.onloadedmetadata = resolve;
    video.onerror = () => reject(new Error('Vidéo illisible'));
  });

  const scale = Math.min(1, VIDEO_MAX_DIM / Math.max(video.videoWidth, video.videoHeight));
  const w = Math.max(2, Math.round(video.videoWidth * scale / 2) * 2);
  const h = Math.max(2, Math.round(video.videoHeight * scale / 2) * 2);

  const canvas = document.createElement('canvas');
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d');
  const canvasStream = canvas.captureStream(30);

  let combinedStream = canvasStream;
  try {
    const srcStream = video.captureStream ? video.captureStream() : video.mozCaptureStream();
    const audioTracks = srcStream.getAudioTracks();
    if (audioTracks.length > 0) combinedStream = new MediaStream([...canvasStream.getVideoTracks(), ...audioTracks]);
  } catch (_) {}

  const mimeType = pickVideoMimeType();
  const rec = new MediaRecorder(combinedStream, mimeType ? { mimeType, videoBitsPerSecond: VIDEO_BITRATE } : { videoBitsPerSecond: VIDEO_BITRATE });
  const chunks = [];
  rec.ondataavailable = (e) => { if (e.data.size > 0) chunks.push(e.data); };
  const stopped = new Promise((resolve) => { rec.onstop = resolve; });

  let drawing = true;
  function drawLoop() {
    if (!drawing) return;
    ctx.drawImage(video, 0, 0, w, h);
    requestAnimationFrame(drawLoop);
  }

  const ended = new Promise((resolve) => { video.onended = resolve; });
  rec.start();
  video.currentTime = 0;
  await video.play();
  drawLoop();
  await ended;
  drawing = false;
  rec.stop();
  await stopped;
  URL.revokeObjectURL(url);

  return new Blob(chunks, { type: rec.mimeType || mimeType || 'video/webm' });
}

async function sendVideo(conv, file) {
  set({ sendError: null });
  let durationS;
  try {
    durationS = await getVideoDuration(file);
  } catch (err) {
    set({ sendError: 'Vidéo illisible : ' + (err.message || err) });
    return;
  }
  if (durationS > MAX_VIDEO_DURATION_S) {
    set({ sendError: `Vidéo trop longue : ${Math.round(durationS)}s (maximum ${MAX_VIDEO_DURATION_S}s).` });
    return;
  }
  set({ sendBusy: true, sendError: null, videoProcessing: true });
  try {
    const compressed = await recompressVideoFile(file);
    const bytes = new Uint8Array(await compressed.arrayBuffer());
    const key = await getConvKey(conv);
    const encrypted = await encryptRaw(key, bytes);
    const path = `${conv.id}/${crypto.randomUUID()}.enc`;
    const { error: upErr } = await supabase.storage.from(MEDIA_BUCKET).upload(path, encrypted, { contentType: 'application/octet-stream' });
    if (upErr) throw upErr;
    const { error } = await supabase.from('messages').insert({
      conversation_id: conv.id,
      sender_id: state.user.id,
      type: 'video',
      media_path: path,
      media_size: encrypted.byteLength,
      duration_ms: Math.round(durationS * 1000),
    });
    if (error) throw error;
    set({ sendBusy: false, videoProcessing: false });
  } catch (err) {
    set({ sendBusy: false, videoProcessing: false, sendError: "Échec de l'envoi de la vidéo : " + (err.message || err) });
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

const VOICE_SAMPLE_RATE = 8000; // qualité téléphonique (norme des appels voix) — réduit la taille ~12x vs 48kHz stéréo

/**
 * Décode un enregistrement (webm/opus, mp4/AAC…) et le ré-encode en WAV **mono 16 kHz** — la
 * qualité stéréo/48kHz native est inutile pour de la voix et gonflerait le stockage Supabase
 * (limité à 1 Go gratuit) ~6x plus que nécessaire.
 */
async function blobToWavBytes(blob) {
  const arrayBuf = await blob.arrayBuffer();
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  const decodeCtx = new AudioCtx();
  let decoded;
  try {
    decoded = await decodeCtx.decodeAudioData(arrayBuf);
  } finally {
    decodeCtx.close();
  }
  const frames = Math.max(1, Math.ceil(decoded.duration * VOICE_SAMPLE_RATE));
  const offline = new OfflineAudioContext(1, frames, VOICE_SAMPLE_RATE);
  const src = offline.createBufferSource();
  src.buffer = decoded;
  src.connect(offline.destination);
  src.start();
  const rendered = await offline.startRendering();
  return encodeWav(rendered);
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

// ---------- Appels (WebRTC) ----------
//
// Signalisation identique à l'app Android (Calls.kt/WebRtcEngine.kt) : broadcast Supabase Realtime
// éphémère sur le canal "call-inbox-<uid>" de chaque utilisateur, événement "signal". Types de
// signal : invite | accept | reject | busy | cancel | end | offer | answer | ice. Seuls les appels
// 1:1 sont repris côté web (les appels de groupe restent expérimentaux même côté Android).

function myDisplayName() {
  return state.profile?.display_name?.trim() || state.user?.email || 'Quelqu\'un';
}

let call = { status: 'idle' }; // idle | outgoing | incoming | active | ended
let lastCallRenderStatus = null;
let callTickTimer = null;
const callChannels = {}; // uid -> { channel, ready: Promise<channel> }
let cachedTurnServers = [];

function callChannelFor(uid) {
  if (callChannels[uid]) return callChannels[uid].ready;
  const ch = supabase.channel('call-inbox-' + uid);
  ch.on('broadcast', { event: 'signal' }, ({ payload }) => onCallSignal(payload));
  const ready = new Promise((resolve) => {
    ch.subscribe((status) => { if (status === 'SUBSCRIBED') resolve(ch); });
  });
  callChannels[uid] = { channel: ch, ready };
  return ready;
}

async function sendCallSignal(signal) {
  try {
    const ch = await callChannelFor(signal.toUid);
    await ch.send({ type: 'broadcast', event: 'signal', payload: signal });
  } catch (_) {}
}

function makeSignal(type, toUid, kind, extra = {}) {
  return {
    type, fromUid: state.user.id, fromName: myDisplayName(), toUid, kind,
    payload: extra.payload || '', callId: extra.callId || '',
    groupId: extra.groupId ?? null, groupName: extra.groupName ?? null,
    participants: extra.participants || '',
  };
}

/** Démarre l'écoute de la boîte d'appels de l'utilisateur connecté (appelé une fois au login). */
async function startCallListening(uid) {
  try {
    const { data, error } = await supabase.functions.invoke('turn-credentials');
    if (!error && data?.iceServers) cachedTurnServers = data.iceServers;
  } catch (_) {}
  await callChannelFor(uid);
}

const CALL_RING_TIMEOUT_MS = 45_000;

function onCallSignal(sig) {
  if (!state.user || sig.toUid !== state.user.id) return;
  if (sig.type === 'invite') {
    if (sig.groupId) return; // appels de groupe non pris en charge côté web
    if (call.status === 'idle') {
      call = { status: 'incoming', peerUid: sig.fromUid, peerName: sig.fromName, kind: sig.kind };
      call.timeoutId = setTimeout(() => {
        if (call.status === 'incoming') { call = { status: 'idle' }; renderCallOverlay(); }
      }, CALL_RING_TIMEOUT_MS);
      renderCallOverlay();
    } else if (call.status === 'incoming' && call.peerUid === sig.fromUid) {
      // déjà affiché, ignorer
    } else {
      sendCallSignal(makeSignal('busy', sig.fromUid, sig.kind));
    }
    return;
  }
  if (sig.type === 'accept') {
    if (call.status === 'outgoing' && call.peerUid === sig.fromUid) {
      clearTimeout(call.timeoutId);
      call = { status: 'active', peerUid: call.peerUid, peerName: call.peerName, kind: call.kind, startedAt: Date.now(), micOn: true, camOn: call.kind === 'video', connected: false };
      renderCallOverlay();
      startWebRtc(true, call.kind, call.peerUid);
    }
    return;
  }
  if (sig.type === 'reject') {
    if (call.status === 'outgoing') { clearTimeout(call.timeoutId); endCall('Appel refusé'); }
    return;
  }
  if (sig.type === 'busy') {
    if (call.status === 'outgoing') { clearTimeout(call.timeoutId); endCall('Occupé'); }
    return;
  }
  if (sig.type === 'cancel') {
    if (call.status === 'incoming') {
      clearTimeout(call.timeoutId);
      call = { status: 'idle' };
      renderCallOverlay();
    }
    return;
  }
  if (sig.type === 'end') {
    if (call.status === 'active') endCall('Appel terminé');
    return;
  }
  if (sig.type === 'offer' || sig.type === 'answer' || sig.type === 'ice') {
    onRemoteRtcSignal(sig.type, sig.payload);
  }
}

function startCall(peerUid, peerName, kind) {
  if (call.status !== 'idle' || !peerUid) return;
  call = { status: 'outgoing', peerUid, peerName, kind };
  sendCallSignal(makeSignal('invite', peerUid, kind));
  call.timeoutId = setTimeout(() => {
    if (call.status === 'outgoing') {
      sendCallSignal(makeSignal('cancel', peerUid, kind));
      endCall('Pas de réponse');
    }
  }, CALL_RING_TIMEOUT_MS);
  renderCallOverlay();
}

function acceptCall() {
  if (call.status !== 'incoming') return;
  clearTimeout(call.timeoutId);
  const { peerUid, peerName, kind } = call;
  call = { status: 'active', peerUid, peerName, kind, startedAt: Date.now(), micOn: true, camOn: kind === 'video', connected: false };
  renderCallOverlay();
  startWebRtc(false, kind, peerUid);
  sendCallSignal(makeSignal('accept', peerUid, kind));
}

function rejectCall() {
  if (call.status !== 'incoming') return;
  clearTimeout(call.timeoutId);
  const { peerUid, kind } = call;
  call = { status: 'idle' };
  renderCallOverlay();
  sendCallSignal(makeSignal('reject', peerUid, kind));
}

function cancelOutgoingCall() {
  if (call.status !== 'outgoing') return;
  clearTimeout(call.timeoutId);
  const { peerUid, kind } = call;
  stopWebRtc();
  call = { status: 'idle' };
  renderCallOverlay();
  sendCallSignal(makeSignal('cancel', peerUid, kind));
}

function hangupCall() {
  if (call.status !== 'active') return;
  const { peerUid, kind } = call;
  endCall('Appel terminé');
  sendCallSignal(makeSignal('end', peerUid, kind));
}

function endCall(reason) {
  stopWebRtc();
  call = { status: 'ended', reason };
  renderCallOverlay();
  setTimeout(() => {
    if (call.status === 'ended') { call = { status: 'idle' }; renderCallOverlay(); }
  }, 1500);
}

function toggleMic() {
  if (call.status !== 'active' || !localCallStream) return;
  call.micOn = !call.micOn;
  localCallStream.getAudioTracks().forEach((t) => { t.enabled = call.micOn; });
  updateCallUi();
}

function toggleCam() {
  if (call.status !== 'active' || !localCallStream || call.kind !== 'video') return;
  call.camOn = !call.camOn;
  localCallStream.getVideoTracks().forEach((t) => { t.enabled = call.camOn; });
  updateCallUi();
}

function callTimeLabel(startedAt) {
  const s = Math.floor((Date.now() - startedAt) / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

function renderCallOverlay() {
  const el = document.getElementById('callOverlay');
  if (!el) return;
  const enteringActive = call.status === 'active' && lastCallRenderStatus !== 'active';
  lastCallRenderStatus = call.status;

  if (call.status === 'idle') {
    el.style.display = 'none';
    el.innerHTML = '';
    clearInterval(callTickTimer);
    return;
  }
  el.style.display = 'flex';

  if (call.status === 'outgoing') {
    el.innerHTML = `
      <div class="call-screen">
        <div class="call-avatar">${escapeHtml(initialsFor(call.peerName))}</div>
        <div class="call-name">${escapeHtml(call.peerName)}</div>
        <div class="call-status">${call.kind === 'video' ? 'Appel vidéo…' : 'Appel…'}</div>
        <div class="call-actions">
          <button id="callCancelBtn" class="call-btn call-btn-end">📴</button>
        </div>
      </div>
    `;
    document.getElementById('callCancelBtn').addEventListener('click', cancelOutgoingCall);
    return;
  }

  if (call.status === 'incoming') {
    el.innerHTML = `
      <div class="call-screen">
        <div class="call-avatar">${escapeHtml(initialsFor(call.peerName))}</div>
        <div class="call-name">${escapeHtml(call.peerName)}</div>
        <div class="call-status">${call.kind === 'video' ? 'Appel vidéo entrant…' : 'Appel entrant…'}</div>
        <div class="call-actions">
          <button id="callRejectBtn" class="call-btn call-btn-end">📴</button>
          <button id="callAcceptBtn" class="call-btn call-btn-accept">📞</button>
        </div>
      </div>
    `;
    document.getElementById('callRejectBtn').addEventListener('click', rejectCall);
    document.getElementById('callAcceptBtn').addEventListener('click', acceptCall);
    return;
  }

  if (call.status === 'ended') {
    el.innerHTML = `<div class="call-screen"><div class="call-status">${escapeHtml(call.reason)}</div></div>`;
    return;
  }

  // call.status === 'active'
  if (enteringActive) {
    el.innerHTML = call.kind === 'video' ? `
      <div class="call-screen call-active">
        <video id="callRemoteMedia" autoplay playsinline style="position:absolute;inset:0;width:100%;height:100%;object-fit:cover;background:#000;"></video>
        <video id="callLocalVideo" autoplay playsinline muted style="position:absolute;bottom:110px;right:16px;width:96px;height:130px;border-radius:12px;object-fit:cover;border:2px solid #fff;z-index:1;"></video>
        <div class="call-name" style="position:absolute;top:max(16px, env(safe-area-inset-top));z-index:1;">${escapeHtml(call.peerName)}</div>
        <div id="callStatusText" class="call-status" style="position:absolute;top:48px;z-index:1;">Connexion…</div>
        <div class="call-actions" style="position:absolute;bottom:max(24px, env(safe-area-inset-bottom));z-index:1;">
          <button id="callMicBtn" class="call-btn">🎙️</button>
          <button id="callCamBtn" class="call-btn">📷</button>
          <button id="callHangupBtn" class="call-btn call-btn-end">📴</button>
        </div>
      </div>
    ` : `
      <div class="call-screen call-active">
        <audio id="callRemoteMedia" autoplay></audio>
        <div class="call-avatar">${escapeHtml(initialsFor(call.peerName))}</div>
        <div class="call-name">${escapeHtml(call.peerName)}</div>
        <div id="callStatusText" class="call-status">Connexion…</div>
        <div class="call-actions">
          <button id="callMicBtn" class="call-btn">🎙️</button>
          <button id="callHangupBtn" class="call-btn call-btn-end">📴</button>
        </div>
      </div>
    `;
    document.getElementById('callMicBtn').addEventListener('click', toggleMic);
    const camBtn = document.getElementById('callCamBtn');
    if (camBtn) camBtn.addEventListener('click', toggleCam);
    document.getElementById('callHangupBtn').addEventListener('click', hangupCall);
    clearInterval(callTickTimer);
    callTickTimer = setInterval(() => { if (call.status === 'active') updateCallUi(); }, 1000);
  }
  updateCallUi();
}

/** Met à jour le contenu dynamique de l'écran d'appel actif sans reconstruire le DOM (évite de
 * couper les flux vidéo/audio en cours en recréant les éléments <video>/<audio>). */
function updateCallUi() {
  if (call.status !== 'active') return;
  const statusEl = document.getElementById('callStatusText');
  if (statusEl) statusEl.textContent = call.connected ? callTimeLabel(call.startedAt) : 'Connexion…';
  const micBtn = document.getElementById('callMicBtn');
  if (micBtn) micBtn.textContent = call.micOn ? '🎙️' : '🔇';
  const camBtn = document.getElementById('callCamBtn');
  if (camBtn) camBtn.textContent = call.camOn ? '📷' : '🚫';
  const localEl = document.getElementById('callLocalVideo');
  if (localEl && localCallStream && localEl.srcObject !== localCallStream) localEl.srcObject = localCallStream;
}

// --- Moteur WebRTC (RTCPeerConnection natif du navigateur) ---

const CALL_ICE_FALLBACK = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:openrelay.metered.ca:80' },
  { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' },
  { urls: 'turn:openrelay.metered.ca:443', username: 'openrelayproject', credential: 'openrelayproject' },
  { urls: 'turn:openrelay.metered.ca:443?transport=tcp', username: 'openrelayproject', credential: 'openrelayproject' },
];

let callPc = null;
let localCallStream = null;
let pendingCallIce = [];
let remoteCallSet = false;

async function startWebRtc(isCaller, kind, peerUid) {
  stopWebRtc();
  remoteCallSet = false;
  pendingCallIce = [];
  const dedicated = cachedTurnServers.map((s) => ({ urls: s.urls, username: s.username, credential: s.credential }));
  callPc = new RTCPeerConnection({ iceServers: [...dedicated, ...CALL_ICE_FALLBACK] });
  callPc.onicecandidate = (e) => {
    if (e.candidate) {
      sendCallSignal(makeSignal('ice', peerUid, kind, { payload: `${e.candidate.sdpMid}|${e.candidate.sdpMLineIndex}|${e.candidate.candidate}` }));
    }
  };
  callPc.ontrack = (e) => {
    const remoteEl = document.getElementById('callRemoteMedia');
    if (remoteEl && remoteEl.srcObject !== e.streams[0]) remoteEl.srcObject = e.streams[0];
  };
  callPc.oniceconnectionstatechange = () => {
    if (callPc && (callPc.iceConnectionState === 'connected' || callPc.iceConnectionState === 'completed')) {
      if (call.status === 'active') { call.connected = true; updateCallUi(); }
    }
  };
  try {
    localCallStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: kind === 'video' ? { facingMode: 'user' } : false });
  } catch (err) {
    endCall('Micro/caméra indisponible');
    return;
  }
  localCallStream.getTracks().forEach((t) => callPc.addTrack(t, localCallStream));
  updateCallUi();
  if (isCaller) {
    const offer = await callPc.createOffer();
    await callPc.setLocalDescription(offer);
    sendCallSignal(makeSignal('offer', peerUid, kind, { payload: offer.sdp }));
  }
}

async function onRemoteRtcSignal(type, payload) {
  if (!callPc) return;
  try {
    if (type === 'offer') {
      await callPc.setRemoteDescription({ type: 'offer', sdp: payload });
      remoteCallSet = true;
      drainCallIce();
      const answer = await callPc.createAnswer();
      await callPc.setLocalDescription(answer);
      if (call.peerUid) sendCallSignal(makeSignal('answer', call.peerUid, call.kind, { payload: answer.sdp }));
    } else if (type === 'answer') {
      await callPc.setRemoteDescription({ type: 'answer', sdp: payload });
      remoteCallSet = true;
      drainCallIce();
    } else if (type === 'ice') {
      const parts = payload.split('|');
      if (parts.length >= 3) {
        const cand = { sdpMid: parts[0] || null, sdpMLineIndex: parts[1] ? parseInt(parts[1], 10) : null, candidate: parts.slice(2).join('|') };
        if (remoteCallSet) { try { await callPc.addIceCandidate(cand); } catch (_) {} } else pendingCallIce.push(cand);
      }
    }
  } catch (_) {}
}

function drainCallIce() {
  if (!callPc) return;
  pendingCallIce.forEach((c) => callPc.addIceCandidate(c).catch(() => {}));
  pendingCallIce = [];
}

function stopWebRtc() {
  if (localCallStream) { localCallStream.getTracks().forEach((t) => t.stop()); localCallStream = null; }
  if (callPc) { try { callPc.close(); } catch (_) {} callPc = null; }
  remoteCallSet = false;
  pendingCallIce = [];
}

// ---------- Administration (owner) — miroir de Profile.kt/Conversations.kt/JoinRequests.kt/SettingsScreen.AdminView ----------

function setAdmin(patch) {
  set({ admin: { ...state.admin, ...patch } });
}

function categoryLabel(c) {
  return { famille: '👨‍👩‍👧 Famille', amis: '🎉 Amis', collegues: '💼 Collègues', special: '🔒 Spécial' }[c] || c;
}

/** « vu à HH:mm » / « vu hier à HH:mm » / « vu le dd/MM à HH:mm », ou null. Miroir de lastSeenLabel (Android). */
function lastSeenLabel(iso) {
  if (!iso) return null;
  try {
    const d = new Date(iso);
    const now = new Date();
    const hm = d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    if (d.toDateString() === now.toDateString()) return `vu à ${hm}`;
    const yesterday = new Date(now); yesterday.setDate(now.getDate() - 1);
    if (d.toDateString() === yesterday.toDateString()) return `vu hier à ${hm}`;
    return `vu le ${d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' })} à ${hm}`;
  } catch (_) { return null; }
}

/** Filet « en ligne » basé sur la fraîcheur de last_seen (même seuil que le fallback Android, 75s). */
function isRecentlyActive(iso) {
  if (!iso) return false;
  try { return (Date.now() - new Date(iso).getTime()) < 75_000; } catch (_) { return false; }
}

async function fetchAllowlistWeb() {
  const { data } = await supabase.from('allowlist').select('email');
  return (data || []).map((r) => r.email);
}

async function revokeInviteWeb(email) {
  await supabase.from('allowlist').delete().eq('email', email);
}

async function setMemberStatusWeb(uid, status) {
  await supabase.from('profiles').update({ status }).eq('id', uid);
}

async function setMemberCategoryWeb(uid, category) {
  await supabase.from('profiles').update({ category }).eq('id', uid);
}

/** Invite un e-mail : hérite de MA catégorie, moi comme parrain — miroir d'inviteEmail (Profile.kt). */
async function inviteEmailWeb(email) {
  const e = (email || '').trim().toLowerCase();
  const me = state.user.id;
  const { data: excluded } = await supabase.from('profiles').select('id').eq('email', e).eq('status', 'excluded');
  if (excluded && excluded.length) {
    throw new Error('Cette personne est exclue. Retire-la des exclus avant de la réinviter.');
  }
  const { data: mine } = await supabase.from('profiles').select('category').eq('id', me).maybeSingle();
  const { error } = await supabase.from('allowlist').insert({ email: e, category: mine?.category || 'amis', sponsor_id: me });
  if (error) throw error;
}

async function fetchJoinRequestsWeb() {
  const { data } = await supabase.from('join_requests').select('*').eq('status', 'pending').order('created_at', { ascending: false });
  return data || [];
}

async function resolveJoinRequestWeb(id, accepted) {
  await supabase.from('join_requests').update({ status: accepted ? 'accepted' : 'rejected' }).eq('id', id);
}

async function deleteMediaObjectWeb(path) {
  try { await supabase.storage.from(MEDIA_BUCKET).remove([path]); } catch (_) {}
}

/** [OWNER] Métadonnées seulement (jamais le contenu, chiffré et illisible sans être membre). */
async function fetchAllConversationsAdminWeb() {
  const { data: convs } = await supabase.from('conversations').select('*');
  const result = [];
  for (const c of convs || []) {
    const { data: members } = await supabase.from('conversation_members').select('conversation_id').eq('conversation_id', c.id);
    const { data: lastRows } = await supabase.from('messages').select('sent_at')
      .eq('conversation_id', c.id).order('sent_at', { ascending: false }).limit(1);
    const label = c.type === 'group' ? (c.name || 'Groupe sans nom') : `DM (${(members || []).length} membres)`;
    result.push({
      id: c.id, type: c.type || 'direct', label, memberCount: (members || []).length,
      lastAt: lastRows?.[0]?.sent_at || null, archived: !!c.archived,
    });
  }
  result.sort((a, b) => (b.lastAt || '').localeCompare(a.lastAt || ''));
  return result;
}

async function setConversationArchivedWeb(id, archived) {
  await supabase.from('conversations').update({ archived }).eq('id', id);
}

/** [OWNER] Supprime définitivement une conversation (messages, médias, adhésions, ligne). */
async function deleteConversationAdminWeb(id) {
  const { data: rows } = await supabase.from('messages').select('media_path').eq('conversation_id', id);
  for (const r of rows || []) {
    if (r.media_path) { await deleteMediaObjectWeb(r.media_path); await deleteMediaObjectWeb(r.media_path + '.thumb'); }
  }
  await supabase.from('messages').delete().eq('conversation_id', id);
  await supabase.from('conversation_members').delete().eq('conversation_id', id);
  await supabase.from('conversations').delete().eq('id', id);
}

/** [OWNER] Purge globale : supprime tous les messages+médias, garde conversations et adhésions. */
async function globalPurgeAllMessagesWeb() {
  const { data: rows } = await supabase.from('messages').select('media_path');
  for (const r of rows || []) {
    if (r.media_path) { await deleteMediaObjectWeb(r.media_path); await deleteMediaObjectWeb(r.media_path + '.thumb'); }
  }
  await supabase.from('messages').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  return (rows || []).length;
}

/** Chiffres réels (comptages Postgres + RPC taille DB/Storage) — miroir de fetchUsageStats (Kotlin). */
async function fetchUsageStatsWeb() {
  const [msgCountRes, memberCountRes, convCountRes, mediaRes] = await Promise.all([
    supabase.from('messages').select('*', { count: 'exact', head: true }),
    supabase.from('profiles').select('*', { count: 'exact', head: true }),
    supabase.from('conversations').select('*', { count: 'exact', head: true }),
    supabase.from('messages').select('media_size'),
  ]);
  const mediaBytes = (mediaRes.data || []).reduce((sum, r) => sum + (r.media_size || 0), 0);
  let dbSizeBytes = null, storageSizeBytes = null;
  try { const { data } = await supabase.rpc('get_database_size_bytes'); dbSizeBytes = data != null ? Number(data) : null; } catch (_) {}
  try { const { data } = await supabase.rpc('get_storage_size_bytes'); storageSizeBytes = data != null ? Number(data) : null; } catch (_) {}
  return {
    messageCount: msgCountRes.count || 0, memberCount: memberCountRes.count || 0, conversationCount: convCountRes.count || 0,
    mediaBytes, dbSizeBytes, storageSizeBytes,
  };
}

async function loadAdminData() {
  setAdmin({ members: null, allowlist: null, conversations: null, joinRequests: null, usage: null, purgeResult: null });
  try {
    const { data: members } = await supabase.from('profiles').select('*');
    const allowlist = await fetchAllowlistWeb();
    setAdmin({ members: members || [], allowlist });
  } catch (_) {
    setAdmin({ members: [], allowlist: [] });
  }
  try {
    setAdmin({ conversations: await fetchAllConversationsAdminWeb() });
  } catch (_) {
    setAdmin({ conversations: [] });
  }
  try {
    setAdmin({ joinRequests: await fetchJoinRequestsWeb() });
  } catch (_) {
    setAdmin({ joinRequests: [] });
  }
  try {
    setAdmin({ usage: await fetchUsageStatsWeb() });
  } catch (_) {
    setAdmin({ usage: null });
  }
}

function renderAdmin() {
  const a = state.admin;
  app.innerHTML = `
    <div class="topbar">
      <button id="adminBackBtn" style="background:none;border:none;color:#fff;font-size:20px;cursor:pointer;padding:0 6px 0 0;">‹</button>
      <span>Administration</span>
    </div>
    <div style="flex:1;overflow-y:auto;padding:16px 20px;">
      ${renderUsageSection(a.usage)}
      ${renderMembersSection(a)}
      ${renderPendingInvitesSection(a)}
      ${renderJoinRequestsSection(a)}
      ${renderConversationsSection(a)}
      ${renderDangerZoneSection(a)}
    </div>
    ${renderStatusModal(a)}
    ${renderConfirmRevokeModal(a)}
    ${renderConfirmDeleteConvModal(a)}
    ${renderConfirmGlobalPurgeModal(a)}
  `;
  document.getElementById('adminBackBtn').addEventListener('click', () => set({ showAdmin: false }));
  wireAdminEvents();
}

const ADMIN_HR = `<hr style="border:none;border-top:1px solid #e5e0d5;margin-bottom:16px;" />`;

function renderUsageSection(u) {
  let body;
  if (!u) {
    body = `<div class="hint" style="margin:0;">Chargement…</div>`;
  } else {
    const dbLine = u.dbSizeBytes != null
      ? `🗄️ Base de données : ${(u.dbSizeBytes / 1_000_000).toFixed(1)} Mo / 500 Mo (${(u.dbSizeBytes / 5_000_000).toFixed(1)}%)`
      : `🗄️ Base de données : indisponible`;
    const storageLine = u.storageSizeBytes != null
      ? `📦 Stockage (médias/avatars) : ${(u.storageSizeBytes / 1_000_000).toFixed(1)} Mo / 1000 Mo (${(u.storageSizeBytes / 10_000_000).toFixed(1)}%)`
      : `📦 Médias envoyés : ~${(u.mediaBytes / 1_000_000).toFixed(1)} Mo (estimation)`;
    body = `
      <div style="font-size:13px;">💬 ${u.messageCount} messages · 👥 ${u.memberCount} membres · 🗂️ ${u.conversationCount} conversations</div>
      <div style="font-size:13px;margin-top:4px;">${dbLine}</div>
      <div style="font-size:13px;margin-top:4px;">${storageLine}</div>
    `;
  }
  return `
    <div style="margin-bottom:20px;">
      <div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:6px;">📊 Utilisation</div>
      ${body}
    </div>
    ${ADMIN_HR}
  `;
}

function renderMembersSection(a) {
  const members = a.members;
  if (members === null) {
    return `<div style="margin-bottom:20px;"><div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:6px;">Membres</div><div class="spinner"></div></div>${ADMIN_HR}`;
  }
  const membersById = {};
  members.forEach((m) => { membersById[m.id] = m; });
  const q = (a.memberSearch || '').toLowerCase();
  const filtered = members
    .filter((m) => !q || (m.display_name || '').toLowerCase().includes(q) || (m.email || '').toLowerCase().includes(q))
    .sort((x, y) => (y.last_seen || '').localeCompare(x.last_seen || ''));
  const visible = filtered.slice(0, a.memberShowCount);
  const rows = visible.map((m) => {
    const label = (m.display_name || '').trim() || m.email || m.id.slice(0, 8);
    const seen = lastSeenLabel(m.last_seen);
    let badge = isRecentlyActive(m.last_seen) ? '● en ligne' : (seen || 'hors ligne');
    badge += '  ' + categoryLabel(m.category || 'amis');
    if (m.role === 'owner') badge += '  ★ owner';
    if (m.status && m.status !== 'active') badge += `  — ${m.status}`;
    const sponsor = m.sponsor_id ? membersById[m.sponsor_id] : null;
    const sponsorLabel = sponsor ? ((sponsor.display_name || '').trim() || sponsor.email || sponsor.id.slice(0, 8)) : null;
    return `
      <div class="list-item" data-admin-member="${m.id}" style="cursor:pointer;">
        <div class="avatar" style="width:40px;height:40px;">${escapeHtml(initialsFor(label))}</div>
        <div style="flex:1;min-width:0;">
          <div class="name">${escapeHtml(label)}</div>
          ${m.display_name?.trim() && m.email ? `<div class="preview">${escapeHtml(m.email)}</div>` : ''}
          <div style="font-size:11px;color:${m.status && m.status !== 'active' ? 'var(--error)' : 'var(--sage)'};">${escapeHtml(badge)}</div>
          ${sponsorLabel ? `<div style="font-size:10px;color:var(--sage);">invité par ${escapeHtml(sponsorLabel)}</div>` : ''}
        </div>
        <span style="color:var(--sage);">⚙</span>
      </div>
    `;
  }).join('');
  const more = filtered.length > a.memberShowCount
    ? `<button type="button" id="memberShowMoreBtn" style="width:100%;padding:10px;background:none;border:none;color:var(--green);font-weight:700;cursor:pointer;">Afficher plus (+${Math.min(10, filtered.length - a.memberShowCount)})</button>`
    : '';
  return `
    <div style="margin-bottom:20px;">
      <div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:6px;">Membres (${members.length})</div>
      <input type="text" id="memberSearchInput" placeholder="Rechercher un membre…" value="${escapeHtml(a.memberSearch || '')}"
             style="width:100%;padding:10px 14px;border:1px solid #cfc9bd;border-radius:10px;font-size:14px;margin-bottom:8px;box-sizing:border-box;" />
      ${rows || '<div class="empty">Aucun membre.</div>'}
      ${more}
    </div>
    ${ADMIN_HR}
  `;
}

function renderPendingInvitesSection(a) {
  const members = a.members || [];
  const memberEmails = new Set(members.map((m) => (m.email || '').toLowerCase()));
  const pending = (a.allowlist || []).filter((e) => !memberEmails.has((e || '').toLowerCase()));
  const rows = pending.map((email) => `
    <div style="display:flex;align-items:center;gap:8px;padding:6px 0;">
      <span style="flex:1;font-size:14px;">${escapeHtml(email)}</span>
      <button type="button" data-revoke-email="${escapeHtml(email)}" style="background:none;border:none;color:var(--error);font-size:13px;cursor:pointer;">Révoquer</button>
    </div>
  `).join('');
  return `
    <div style="margin-bottom:20px;">
      <div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:6px;">Invitations en attente (${pending.length})</div>
      ${rows || '<div class="hint" style="margin:0;">Aucune invitation en attente.</div>'}
    </div>
    ${ADMIN_HR}
  `;
}

function renderJoinRequestsSection(a) {
  const requests = a.joinRequests;
  if (requests === null) {
    return `<div style="margin-bottom:20px;"><div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:6px;">Demandes d'ajout</div><div class="spinner"></div></div>${ADMIN_HR}`;
  }
  const rows = requests.map((r) => `
    <div style="padding:10px 0;border-bottom:1px solid #eee8db;">
      <div style="font-weight:700;font-size:14px;">${escapeHtml(r.name)}</div>
      <div style="font-size:12px;color:var(--sage);">${escapeHtml(r.contact)}</div>
      ${r.message ? `<div style="font-size:13px;margin-top:2px;">${escapeHtml(r.message)}</div>` : ''}
      <div style="margin-top:6px;">
        <button type="button" data-jr-accept="${r.id}" data-jr-email="${escapeHtml(r.contact)}" style="background:none;border:none;color:var(--green);font-weight:700;font-size:13px;cursor:pointer;margin-right:14px;">Inviter</button>
        <button type="button" data-jr-reject="${r.id}" style="background:none;border:none;color:var(--error);font-size:13px;cursor:pointer;">Rejeter</button>
      </div>
    </div>
  `).join('');
  return `
    <div style="margin-bottom:20px;">
      <div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:6px;">Demandes d'ajout (${requests.length})</div>
      ${rows || '<div class="hint" style="margin:0;">Aucune demande en attente.</div>'}
    </div>
    ${ADMIN_HR}
  `;
}

function renderConversationsSection(a) {
  const convs = a.conversations;
  if (convs === null) {
    return `<div style="margin-bottom:20px;"><div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:2px;">Toutes les conversations</div><div class="spinner"></div></div>${ADMIN_HR}`;
  }
  const q = (a.convSearch || '').toLowerCase();
  const filtered = convs.filter((c) => !q || c.label.toLowerCase().includes(q));
  const visible = filtered.slice(0, a.convShowCount);
  const rows = visible.map((c) => `
    <div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid #eee8db;">
      <div style="flex:1;min-width:0;">
        <div style="font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${c.archived ? '🗄️ ' : ''}${escapeHtml(c.label)}</div>
        <div style="font-size:11px;color:var(--sage);">${c.memberCount} membre(s)${c.lastAt ? ' · actif récemment' : ' · vide'}</div>
      </div>
      <button type="button" data-conv-archive="${c.id}" data-conv-archived="${c.archived ? '1' : '0'}" style="background:none;border:none;color:var(--green);font-size:12px;cursor:pointer;white-space:nowrap;">${c.archived ? 'Désarchiver' : 'Archiver'}</button>
      <button type="button" data-conv-delete="${c.id}" style="background:none;border:none;color:var(--error);font-size:12px;cursor:pointer;">Suppr.</button>
    </div>
  `).join('');
  const more = filtered.length > a.convShowCount
    ? `<button type="button" id="convShowMoreBtn" style="width:100%;padding:10px;background:none;border:none;color:var(--green);font-weight:700;cursor:pointer;">Afficher plus (+${Math.min(10, filtered.length - a.convShowCount)})</button>`
    : '';
  return `
    <div style="margin-bottom:20px;">
      <div style="font-size:16px;font-weight:700;color:var(--forest);margin-bottom:2px;">Toutes les conversations (${convs.length})</div>
      <div style="font-size:11px;color:var(--sage);margin-bottom:8px;">Métadonnées seulement (nom/type, membres, activité) — le contenu reste chiffré, illisible sans en être membre.</div>
      <input type="text" id="convSearchInput" placeholder="Rechercher une conversation…" value="${escapeHtml(a.convSearch || '')}"
             style="width:100%;padding:10px 14px;border:1px solid #cfc9bd;border-radius:10px;font-size:14px;margin-bottom:8px;box-sizing:border-box;" />
      ${rows || '<div class="empty">Aucune conversation.</div>'}
      ${more}
    </div>
    ${ADMIN_HR}
  `;
}

function renderDangerZoneSection(a) {
  return `
    <div style="margin-bottom:24px;">
      <div style="font-size:15px;font-weight:700;color:var(--error);margin-bottom:8px;">Zone dangereuse</div>
      <button type="button" id="globalPurgeBtn" ${a.busy ? 'disabled' : ''}
              style="width:100%;padding:12px;border:1px solid var(--error);border-radius:10px;background:none;color:var(--error);font-size:14px;cursor:pointer;">
        🧨 Purge globale de tous les messages
      </button>
      ${a.purgeResult ? `<div style="font-size:13px;color:var(--sage);margin-top:6px;">${escapeHtml(a.purgeResult)}</div>` : ''}
    </div>
  `;
}

function renderStatusModal(a) {
  if (!a.statusTargetId) return '';
  const m = (a.members || []).find((x) => x.id === a.statusTargetId);
  if (!m) return '';
  const label = (m.display_name || '').trim() || m.email || m.id.slice(0, 8);
  const isSelf = m.id === state.user?.id;
  const categories = ['famille', 'amis', 'collegues', 'special'];
  const statuses = [['active', '✅ Actif (visible)'], ['hidden', '🙈 Masqué de l\'annuaire'], ['excluded', '🚫 Exclu']];
  return `
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:60;padding:20px;">
      <div style="background:#fff;border-radius:14px;padding:20px;max-width:380px;width:100%;max-height:85vh;overflow-y:auto;">
        <div style="font-weight:700;font-size:16px;margin-bottom:4px;color:var(--forest);">${escapeHtml(label)}</div>
        <div style="font-size:12px;color:var(--sage);">Statut actuel : ${escapeHtml(m.status || 'active')}</div>
        <div style="font-size:12px;color:var(--sage);margin-bottom:10px;">Catégorie : ${categoryLabel(m.category || 'amis')}</div>
        <div style="font-size:12px;font-weight:700;color:var(--green);margin:10px 0 4px;">Changer la catégorie :</div>
        ${categories.map((cat) => `<button type="button" data-set-category="${cat}" style="display:block;width:100%;text-align:left;padding:8px 6px;background:none;border:none;font-size:14px;cursor:pointer;">${categoryLabel(cat)}</button>`).join('')}
        <hr style="border:none;border-top:1px solid #e5e0d5;margin:10px 0;" />
        <div style="font-size:12px;font-weight:700;color:var(--green);margin-bottom:4px;">Changer le statut :</div>
        ${statuses.map(([value, lbl]) => `<button type="button" data-set-status="${value}" ${isSelf ? 'disabled' : ''} style="display:block;width:100%;text-align:left;padding:8px 6px;background:none;border:none;font-size:14px;cursor:${isSelf ? 'not-allowed' : 'pointer'};color:${isSelf ? '#999' : 'var(--ink)'};">${lbl}</button>`).join('')}
        ${isSelf ? `<div style="font-size:11px;color:var(--sage);margin-top:4px;">(Tu ne peux pas changer ton propre statut.)</div>` : ''}
        <button type="button" id="statusModalClose" style="width:100%;margin-top:14px;padding:10px;border-radius:10px;border:1px solid #cfc9bd;background:#fff;cursor:pointer;">Fermer</button>
      </div>
    </div>
  `;
}

function renderConfirmModal({ title, text, confirmId, cancelId, confirmLabel, busy }) {
  return `
    <div style="position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:70;padding:20px;">
      <div style="background:#fff;border-radius:14px;padding:20px;max-width:360px;width:100%;">
        <div style="font-weight:700;font-size:16px;margin-bottom:8px;color:var(--forest);">${escapeHtml(title)}</div>
        <div style="font-size:13px;color:var(--ink);margin-bottom:16px;">${text}</div>
        <div style="display:flex;gap:10px;">
          <button type="button" id="${cancelId}" ${busy ? 'disabled' : ''} style="flex:1;padding:10px;border-radius:10px;border:1px solid #cfc9bd;background:#fff;cursor:pointer;">Annuler</button>
          <button type="button" id="${confirmId}" ${busy ? 'disabled' : ''} style="flex:1;padding:10px;border-radius:10px;border:none;background:var(--error);color:#fff;cursor:pointer;">${escapeHtml(confirmLabel)}</button>
        </div>
      </div>
    </div>
  `;
}

function renderConfirmRevokeModal(a) {
  if (!a.confirmRevokeEmail) return '';
  return renderConfirmModal({
    title: "Révoquer l'invitation",
    text: `Retirer « ${escapeHtml(a.confirmRevokeEmail)} » de la liste blanche ? Cette personne ne pourra plus créer de compte avec cet e-mail.`,
    confirmId: 'confirmRevokeYes', cancelId: 'confirmRevokeNo', confirmLabel: 'Révoquer', busy: a.busy,
  });
}

function renderConfirmDeleteConvModal(a) {
  if (!a.confirmDeleteConvId) return '';
  const c = (a.conversations || []).find((x) => x.id === a.confirmDeleteConvId);
  return renderConfirmModal({
    title: 'Supprimer définitivement',
    text: `Supprimer « ${escapeHtml(c ? c.label : '')} » et tout son contenu (messages, médias) ? Irréversible.`,
    confirmId: 'confirmDeleteConvYes', cancelId: 'confirmDeleteConvNo', confirmLabel: 'Supprimer', busy: a.busy,
  });
}

function renderConfirmGlobalPurgeModal(a) {
  if (!a.confirmGlobalPurge) return '';
  return renderConfirmModal({
    title: 'Purge globale',
    text: `Supprimer DÉFINITIVEMENT tous les messages et médias de TOUTES les conversations, pour TOUS les membres ? Les conversations elles-mêmes restent (on peut recommencer à discuter dedans), mais tout l'historique disparaît. Cette action est irréversible.`,
    confirmId: 'confirmGlobalPurgeYes', cancelId: 'confirmGlobalPurgeNo', confirmLabel: 'Purger tout', busy: a.busy,
  });
}

function wireAdminEvents() {
  const memberSearchInput = document.getElementById('memberSearchInput');
  if (memberSearchInput) {
    memberSearchInput.addEventListener('input', () => setAdmin({ memberSearch: memberSearchInput.value, memberShowCount: 10 }));
  }
  const memberShowMoreBtn = document.getElementById('memberShowMoreBtn');
  if (memberShowMoreBtn) memberShowMoreBtn.addEventListener('click', () => setAdmin({ memberShowCount: state.admin.memberShowCount + 10 }));

  document.querySelectorAll('[data-admin-member]').forEach((el) => {
    el.addEventListener('click', () => setAdmin({ statusTargetId: el.dataset.adminMember }));
  });

  document.querySelectorAll('[data-revoke-email]').forEach((el) => {
    el.addEventListener('click', () => setAdmin({ confirmRevokeEmail: el.dataset.revokeEmail }));
  });

  document.querySelectorAll('[data-jr-accept]').forEach((el) => {
    el.addEventListener('click', async () => {
      if (state.admin.busy) return;
      setAdmin({ busy: true });
      try {
        await inviteEmailWeb(el.dataset.jrEmail);
        await resolveJoinRequestWeb(el.dataset.jrAccept, true);
      } catch (err) {
        alert(err.message || String(err));
      }
      setAdmin({ busy: false });
      await loadAdminData();
    });
  });
  document.querySelectorAll('[data-jr-reject]').forEach((el) => {
    el.addEventListener('click', async () => {
      if (state.admin.busy) return;
      setAdmin({ busy: true });
      try { await resolveJoinRequestWeb(el.dataset.jrReject, false); } catch (_) {}
      setAdmin({ busy: false });
      await loadAdminData();
    });
  });

  const convSearchInput = document.getElementById('convSearchInput');
  if (convSearchInput) {
    convSearchInput.addEventListener('input', () => setAdmin({ convSearch: convSearchInput.value, convShowCount: 10 }));
  }
  const convShowMoreBtn = document.getElementById('convShowMoreBtn');
  if (convShowMoreBtn) convShowMoreBtn.addEventListener('click', () => setAdmin({ convShowCount: state.admin.convShowCount + 10 }));

  document.querySelectorAll('[data-conv-archive]').forEach((el) => {
    el.addEventListener('click', async () => {
      if (state.admin.busy) return;
      const id = el.dataset.convArchive;
      const archived = el.dataset.convArchived === '1';
      setAdmin({ busy: true });
      try { await setConversationArchivedWeb(id, !archived); } catch (_) {}
      setAdmin({ busy: false });
      await loadAdminData();
    });
  });
  document.querySelectorAll('[data-conv-delete]').forEach((el) => {
    el.addEventListener('click', () => setAdmin({ confirmDeleteConvId: el.dataset.convDelete }));
  });

  const globalPurgeBtn = document.getElementById('globalPurgeBtn');
  if (globalPurgeBtn) globalPurgeBtn.addEventListener('click', () => setAdmin({ confirmGlobalPurge: true }));

  const statusModalClose = document.getElementById('statusModalClose');
  if (statusModalClose) statusModalClose.addEventListener('click', () => setAdmin({ statusTargetId: null }));
  document.querySelectorAll('[data-set-category]').forEach((el) => {
    el.addEventListener('click', async () => {
      const uid = state.admin.statusTargetId;
      setAdmin({ statusTargetId: null, busy: true });
      try { await setMemberCategoryWeb(uid, el.dataset.setCategory); } catch (_) {}
      setAdmin({ busy: false });
      await loadAdminData();
    });
  });
  document.querySelectorAll('[data-set-status]').forEach((el) => {
    el.addEventListener('click', async () => {
      const uid = state.admin.statusTargetId;
      setAdmin({ statusTargetId: null, busy: true });
      try { await setMemberStatusWeb(uid, el.dataset.setStatus); } catch (_) {}
      setAdmin({ busy: false });
      await loadAdminData();
    });
  });

  const confirmRevokeYes = document.getElementById('confirmRevokeYes');
  if (confirmRevokeYes) confirmRevokeYes.addEventListener('click', async () => {
    const email = state.admin.confirmRevokeEmail;
    setAdmin({ confirmRevokeEmail: null, busy: true });
    try { await revokeInviteWeb(email); } catch (_) {}
    setAdmin({ busy: false });
    await loadAdminData();
  });
  const confirmRevokeNo = document.getElementById('confirmRevokeNo');
  if (confirmRevokeNo) confirmRevokeNo.addEventListener('click', () => setAdmin({ confirmRevokeEmail: null }));

  const confirmDeleteConvYes = document.getElementById('confirmDeleteConvYes');
  if (confirmDeleteConvYes) confirmDeleteConvYes.addEventListener('click', async () => {
    const id = state.admin.confirmDeleteConvId;
    setAdmin({ confirmDeleteConvId: null, busy: true });
    try { await deleteConversationAdminWeb(id); } catch (_) {}
    setAdmin({ busy: false });
    await loadAdminData();
  });
  const confirmDeleteConvNo = document.getElementById('confirmDeleteConvNo');
  if (confirmDeleteConvNo) confirmDeleteConvNo.addEventListener('click', () => setAdmin({ confirmDeleteConvId: null }));

  const confirmGlobalPurgeYes = document.getElementById('confirmGlobalPurgeYes');
  if (confirmGlobalPurgeYes) confirmGlobalPurgeYes.addEventListener('click', async () => {
    setAdmin({ busy: true });
    let n = 0;
    try { n = await globalPurgeAllMessagesWeb(); } catch (_) {}
    setAdmin({ busy: false, confirmGlobalPurge: false, purgeResult: `🧨 ${n} message(s) supprimé(s) sur toute la plateforme.` });
    await loadAdminData();
  });
  const confirmGlobalPurgeNo = document.getElementById('confirmGlobalPurgeNo');
  if (confirmGlobalPurgeNo) confirmGlobalPurgeNo.addEventListener('click', () => { if (!state.admin.busy) setAdmin({ confirmGlobalPurge: false }); });
}

// ---------- Démarrage ----------

supabase.auth.onAuthStateChange((_event, session) => {
  if (session?.user) {
    set({ screen: 'main', user: session.user });
    loadMainData();
    startCallListening(session.user.id);
  } else {
    if (currentChannel) { supabase.removeChannel(currentChannel); currentChannel = null; }
    stopWebRtc();
    call = { status: 'idle' };
    renderCallOverlay();
    Object.values(callChannels).forEach(({ channel }) => { try { supabase.removeChannel(channel); } catch (_) {} });
    for (const k of Object.keys(callChannels)) delete callChannels[k];
    set({
      screen: 'auth', user: null, profile: null, members: [], identity: null,
      conversations: null, previews: {}, convKeysCache: {}, openConv: null, messages: null,
    });
  }
});

render();
