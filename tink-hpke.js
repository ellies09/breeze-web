// Compatibilité avec le format cryptographique Tink utilisé par l'app Android Breeze.
// Schéma : HPKE (X25519 + HKDF-SHA256 + AES-256-GCM) pour les clés d'identité,
// AES-256-GCM (Tink) pour les clés de conversation et les messages.
//
// Formats validés le 2026-09-07 sur de vraies données du projet Supabase partagé :
// - Clé publique (profiles.public_key) : JSON Tink base64, HpkePublicKey protobuf.
// - Clé de conversation chiffrée (conversation_members.encrypted_key) :
//     0x01 | keyId(4 octets BE) | enc(32 octets X25519) | ciphertext HPKE
// - Message chiffré (messages.ciphertext) :
//     0x01 | keyId(4 octets BE) | IV(12 octets) | AES-256-GCM(ciphertext+tag 16 octets)

const TYPE_HPKE_PUBLIC = 'type.googleapis.com/google.crypto.tink.HpkePublicKey';
const TYPE_HPKE_PRIVATE = 'type.googleapis.com/google.crypto.tink.HpkePrivateKey';
const TYPE_AES_GCM = 'type.googleapis.com/google.crypto.tink.AesGcmKey';

// ---------- Utilitaires base64 / bytes ----------

export function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// ---------- Lecteur protobuf minimal (varint + length-delimited) ----------

function readVarint(bytes, pos) {
  let result = 0, mult = 1, b;
  do {
    b = bytes[pos++];
    result += (b & 0x7f) * mult;
    mult *= 128;
  } while (b & 0x80);
  return [result, pos];
}

function readTag(bytes, pos) {
  const [tag, p] = readVarint(bytes, pos);
  return [Math.floor(tag / 8), tag % 8, p];
}

function readLengthDelimited(bytes, pos) {
  const [len, p1] = readVarint(bytes, pos);
  return [bytes.slice(p1, p1 + len), p1 + len];
}

function skipField(bytes, pos, wireType) {
  if (wireType === 0) return readVarint(bytes, pos)[1];
  if (wireType === 2) return readLengthDelimited(bytes, pos)[1];
  if (wireType === 5) return pos + 4;
  if (wireType === 1) return pos + 8;
  throw new Error('protobuf : wire type non supporté ' + wireType);
}

// ---------- Messages protobuf Tink (structure fixe, lecture seule) ----------

function parseKeyData(bytes) {
  let pos = 0, typeUrl = null, value = null, keyMaterialType = null;
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 1 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; typeUrl = new TextDecoder().decode(b); }
    else if (f === 2 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; value = b; }
    else if (f === 3 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; keyMaterialType = v; }
    else pos = skipField(bytes, pos, w);
  }
  return { typeUrl, value, keyMaterialType };
}

function parseKeysetKey(bytes) {
  let pos = 0, keyData = null, status = null, keyId = null, outputPrefixType = null;
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 1 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; keyData = parseKeyData(b); }
    else if (f === 2 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; status = v; }
    else if (f === 3 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; keyId = v; }
    else if (f === 4 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; outputPrefixType = v; }
    else pos = skipField(bytes, pos, w);
  }
  return { keyData, status, keyId, outputPrefixType };
}

/** Parse un Keyset Tink binaire (protobuf) : { primaryKeyId, keys: [...] }. */
export function parseKeysetBinary(bytes) {
  let pos = 0, primaryKeyId = null; const keys = [];
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 1 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; primaryKeyId = v; }
    else if (f === 2 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; keys.push(parseKeysetKey(b)); }
    else pos = skipField(bytes, pos, w);
  }
  return { primaryKeyId, keys };
}

function parseHpkeParams(bytes) {
  let pos = 0, kem = null, kdf = null, aead = null;
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 1 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; kem = v; }
    else if (f === 2 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; kdf = v; }
    else if (f === 3 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; aead = v; }
    else pos = skipField(bytes, pos, w);
  }
  return { kem, kdf, aead };
}

function parseHpkePublicKey(bytes) {
  let pos = 0, params = null, publicKey = null;
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 2 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; params = parseHpkeParams(b); }
    else if (f === 3 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; publicKey = b; }
    else pos = skipField(bytes, pos, w);
  }
  return { params, publicKey };
}

function parseHpkePrivateKey(bytes) {
  let pos = 0, publicKey = null, privateKey = null;
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 2 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; publicKey = parseHpkePublicKey(b); }
    else if (f === 3 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; privateKey = b; }
    else pos = skipField(bytes, pos, w);
  }
  return { publicKey, privateKey };
}

function parseAesGcmKey(bytes) {
  let pos = 0, version = null, keyValue = null;
  while (pos < bytes.length) {
    const [f, w, p1] = readTag(bytes, pos); pos = p1;
    if (f === 1 && w === 0) { const [v, p2] = readVarint(bytes, pos); pos = p2; version = v; }
    else if (f === 3 && w === 2) { const [b, p2] = readLengthDelimited(bytes, pos); pos = p2; keyValue = b; }
    else pos = skipField(bytes, pos, w);
  }
  return { version, keyValue };
}

// ---------- API haut niveau ----------

/** Clé publique HPKE (profil.public_key) → { keyId, rawPublicKey(32 octets) }. */
export function parseTinkPublicKeyJson(base64Json) {
  const json = JSON.parse(atob(base64Json));
  const key = json.key[0];
  if (key.keyData.typeUrl !== TYPE_HPKE_PUBLIC) throw new Error('Type de clé publique inattendu.');
  const hpkePub = parseHpkePublicKey(base64ToBytes(key.keyData.value));
  return { keyId: key.keyId, rawPublicKey: hpkePub.publicKey };
}

/** Keyset privé Tink binaire (après déchiffrement de la sauvegarde) → { keyId, rawPrivateKey, rawPublicKey }. */
export function parseTinkPrivateKeysetBinary(bytes) {
  const ks = parseKeysetBinary(bytes);
  const key = ks.keys[0];
  if (key.keyData.typeUrl !== TYPE_HPKE_PRIVATE) throw new Error('Type de clé privée inattendu.');
  const hpkePriv = parseHpkePrivateKey(key.keyData.value);
  return { keyId: key.keyId, rawPrivateKey: hpkePriv.privateKey, rawPublicKey: hpkePriv.publicKey.publicKey };
}

/** Keyset de conversation Tink binaire (après déchiffrement HPKE) → { keyId, rawKey(32 octets) }. */
export function parseTinkAesGcmKeysetBinary(bytes) {
  const ks = parseKeysetBinary(bytes);
  const key = ks.keys[0];
  if (key.keyData.typeUrl !== TYPE_AES_GCM) throw new Error('Type de clé de conversation inattendu.');
  const aesKey = parseAesGcmKey(key.keyData.value);
  return { keyId: key.keyId, rawKey: aesKey.keyValue };
}

let _suitePromise = null;
async function hpkeSuite() {
  if (!_suitePromise) {
    _suitePromise = import('https://esm.sh/hpke-js@1').then(({ CipherSuite, KemId, KdfId, AeadId }) =>
      new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Aes256Gcm }));
  }
  return _suitePromise;
}

/** Déchiffre (HPKE) la clé de conversation avec ma clé privée locale. */
export async function unwrapConversationKey(myPrivateKeyRaw, myKeyId, wrappedB64) {
  const wrapped = base64ToBytes(wrappedB64);
  if (wrapped[0] !== 1) throw new Error('Préfixe Tink inattendu (format non « TINK »).');
  const dv = new DataView(wrapped.buffer, wrapped.byteOffset, wrapped.byteLength);
  const keyId = dv.getUint32(1, false);
  if (keyId !== myKeyId) throw new Error("La clé de conversation n'est pas chiffrée pour ma clé.");
  const enc = wrapped.slice(5, 37);
  const ct = wrapped.slice(37);
  const suite = await hpkeSuite();
  const privKey = await suite.kem.importKey('raw', myPrivateKeyRaw, false);
  const recipient = await suite.createRecipientContext({ recipientKey: privKey, enc });
  const plain = new Uint8Array(await recipient.open(ct));
  return parseTinkAesGcmKeysetBinary(plain);
}

async function aesKeyFor(rawKey32) {
  return crypto.subtle.importKey('raw', rawKey32, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Déchiffre un message (ou des octets bruts) chiffré avec la clé de conversation. */
export async function decryptBytes(conversationKey, ciphertextB64) {
  const bytes = base64ToBytes(ciphertextB64);
  if (bytes[0] !== 1) throw new Error('Préfixe Tink inattendu.');
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const keyId = dv.getUint32(1, false);
  if (keyId !== conversationKey.keyId) throw new Error("Ce message n'a pas été chiffré avec cette clé de conversation.");
  const iv = bytes.slice(5, 17);
  const ct = bytes.slice(17);
  const key = await aesKeyFor(conversationKey.rawKey);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, ct);
  return new Uint8Array(plain);
}

/** Déchiffre un message texte → chaîne UTF-8. */
export async function decryptMessage(conversationKey, ciphertextB64) {
  return new TextDecoder().decode(await decryptBytes(conversationKey, ciphertextB64));
}

/** Chiffre des octets bruts avec la clé de conversation → base64 (format Tink TINK). */
export async function encryptBytes(conversationKey, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKeyFor(conversationKey.rawKey);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plainBytes));
  const out = new Uint8Array(1 + 4 + 12 + ct.length);
  out[0] = 1;
  new DataView(out.buffer).setUint32(1, conversationKey.keyId, false);
  out.set(iv, 5);
  out.set(ct, 17);
  return bytesToBase64(out);
}

/** Chiffre un message texte → base64. */
export async function encryptMessage(conversationKey, plaintext) {
  return encryptBytes(conversationKey, new TextEncoder().encode(plaintext));
}

// ---------- Sauvegarde / restauration de la clé d'identité par phrase secrète ----------
// Même format que KeyManager.kt (Android) : [version(1)=1][salt(16)][iv(12)][ciphertext],
// clé dérivée par PBKDF2WithHmacSHA256, 210 000 itérations, 256 bits.

const PBKDF2_ITERS = 210_000;

/**
 * Restaure l'identité depuis le blob de sauvegarde (encrypted_private_key) + la phrase secrète.
 * Retourne { keyId, rawPrivateKey, rawPublicKey }. Lève une exception si la phrase est incorrecte.
 */
export async function restoreIdentityFromBackup(passphrase, backupB64) {
  const blob = base64ToBytes(backupB64);
  const salt = blob.slice(1, 17);
  const iv = blob.slice(17, 29);
  const ct = blob.slice(29);
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, aesKey, ct));
  } catch (_) {
    throw new Error('Phrase secrète incorrecte.');
  }
  return parseTinkPrivateKeysetBinary(plain);
}
