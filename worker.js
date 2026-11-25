/* SPHERIA API — Cloudflare Worker + D1 (file unico, pronto da incollare in dashboard).
 * Versione logica: pvp28 (come pvp27 + contatori missioni Fedeltà/Sfera/Negozio/Draft).
 * Salvataggio completo (volto/volti/stagione/premi-rango/gettoni/mini-bustine/nuovi-contatori),
 * niente più reset mensile: i punti ranked restano per sempre e si scende solo perdendo
 * (la "stagione" premi vive sul client con la barra bisettimanale).
 * I loggati non perdono più lo stock di bustine se cancellano i dati dell'app.
 *
 * SCHEMA DEL SALVATAGGIO (tabella saves, chiave "data"): per non perdere niente in
 * futuro, ogni nuova cosa da conservare va aggiunta QUI SOTTO in due punti:
 *   1) in cleanSaveXxx (questa sezione: sanifica e taglia i valori) e
 *   2) nella voce corrispondente di `clean` dentro PUT /api/save.
 * Il client invia già tutto l'oggetto data e riapplica da solo ciò che riceve.
 *
 * Binding richiesti (Settings → Bindings del Worker):
 *   D1 database → nome variabile: DB
 * Variabili (Settings → Variables):
 *   GOOGLE_CLIENT_ID = 168173771568-tdq7lt9rgi99o9q2adiii4ovdpc4l8dv.apps.googleusercontent.com
 *   ALLOWED_ORIGIN    = https://spheria-tcg.pages.dev
 *
 * NESSUN segreto nel codice: la verifica del token Google usa le chiavi
 * PUBBLICHE di Google, le sessioni sono token casuali (hash SHA-256 nel DB).
 */
"use strict";

const GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs";
let certsCache = { keys: null, until: 0 };

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function getGoogleKeys() {
  if (certsCache.keys && Date.now() < certsCache.until) return certsCache.keys;
  const r = await fetch(GOOGLE_CERTS_URL, { cf: { cacheTtl: 3600 } });
  if (!r.ok) throw new Error("certs_fetch_failed");
  const j = await r.json();
  certsCache = { keys: j.keys || [], until: Date.now() + 3600 * 1000 };
  return certsCache.keys;
}

// Verifica firma RS256 + exp/iss/aud. Ritorna il payload oppure lancia.
async function verifyGoogleToken(idToken, clientId) {
  const parts = (idToken || "").split(".");
  if (parts.length !== 3) throw new Error("bad_token_shape");
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  const signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
  const sig = b64urlToBytes(parts[2]);
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now - 30) throw new Error("token_expired");
  if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com")
    throw new Error("bad_iss");
  if (payload.aud !== clientId) throw new Error("bad_aud");
  if (!payload.sub) throw new Error("no_sub");
  const keys = await getGoogleKeys();
  const jwk = keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) throw new Error("unknown_kid");
  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, signingInput);
  if (!ok) throw new Error("bad_signature");
  return payload;
}

function hexBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function corsHeaders(env, req) {
  const origin = req.headers.get("Origin") || "";
  const h = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
  if (origin && origin === env.ALLOWED_ORIGIN) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Vary"] = "Origin";
  }
  return h;
}

function json(env, req, obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ "Content-Type": "application/json" }, corsHeaders(env, req)),
  });
}

async function getSessionAccount(env, req) {
  const auth = req.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(\S+)$/i);
  if (!m) return null;
  const th = await sha256hex(m[1]);
  const s = await env.DB.prepare(
    "SELECT account_id, expires_at FROM sessions WHERE token_hash = ?"
  ).bind(th).first();
  if (!s || s.expires_at < Date.now()) return null;
  return s.account_id;
}

async function readJson(req, maxBytes) {
  const ct = req.headers.get("Content-Type") || "";
  if (ct.indexOf("application/json") < 0) throw new Error("bad_content_type");
  const txt = await req.text();
  if (txt.length > (maxBytes || 20000)) throw new Error("body_too_large");
  return JSON.parse(txt);
}

// ---------- salvataggio cloud: voci conservate (vedi SCHEMA in testa al file) ----------
const SAVE_STYLE_IDS = { bronzo: 1, argento: 1, oro: 1, platino: 1, diamante: 1, fullart: 1 };
function clampSaveInt(v, max) {
  v = +v || 0;
  if (v < 0) v = 0;
  if (v > max) v = max;
  return Math.floor(v);
}
// Portafoglio: schegge/nuclei/gettoni/×2/polvere entro un tetto + ricompense missioni già riscosse.
function cleanSaveWallet(w) {
  if (!w || typeof w !== "object") return { schegge: 0, nuclei: 0, draftKeys: 0, x2: 0, x2active: 0, polvere: 0, claimed: {} };
  const claimed = {};
  if (w.claimed && typeof w.claimed === "object") {
    const keys = Object.keys(w.claimed).slice(0, 200);
    for (const k of keys) if (/^[A-Za-z0-9 _:-]{1,40}$/.test(k)) claimed[k] = 1;
  }
  return { schegge: clampSaveInt(w.schegge, 999999), nuclei: clampSaveInt(w.nuclei, 999999), draftKeys: clampSaveInt(w.draftKeys, 999), x2: clampSaveInt(w.x2, 999), x2active: clampSaveInt(w.x2active, 999), polvere: clampSaveInt(w.polvere, 999999), claimed: claimed };
}
// Bustine sigillate: max 20, da 6 (standard) o 3 (mini), solo id carta validi (contenuto fissato all'acquisto).
function cleanSavePacks(p) {
  const out = [];
  if (!Array.isArray(p)) return out;
  for (const pack of p.slice(0, 20)) {
    if (!Array.isArray(pack) || (pack.length !== 6 && pack.length !== 3)) continue;
    const ids = [];
    let ok = true;
    for (const id of pack) {
      if (typeof id !== "string" || !/^[a-z0-9]{3}$/.test(id)) { ok = false; break; }
      ids.push(id);
    }
    if (ok) out.push(ids);
  }
  return out;
}
// Collezione: per ogni id carta (3 minuscole/numeri) copie entro un tetto, stile attivo
// valido e stili sbloccati a pagamento (solo id noti).
function cleanSaveOwn(o) {
  const out = {};
  if (!o || typeof o !== "object") return out;
  const keys = Object.keys(o).slice(0, 200);
  for (const k of keys) {
    if (!/^[a-z0-9]{3}$/.test(k)) continue;
    const e = o[k] || {};
    const copies = clampSaveInt(e.copies, 9999);
    const active = typeof e.active === "string" && SAVE_STYLE_IDS[e.active] ? e.active : "";
    const un = {};
    if (e.un && typeof e.un === "object") {
      for (const u of Object.keys(e.un).slice(0, 10)) if (SAVE_STYLE_IDS[u]) un[u] = 1;
    }
    if (copies > 0 || active || Object.keys(un).length) out[k] = { copies: copies, active: active, un: un };
  }
  return out;
}
// Profilo: volto (id carta), volti sbloccati, stagione premi e premi rango (una tantum).
const SAVE_GRADES = { Argento: 1, Oro: 1, Platino: 1, Diamante: 1, Maestro: 1 };
const SAVE_SEASON_AT = { 100: 1, 200: 1, 300: 1, 400: 1, 500: 1, 600: 1, 800: 1, 1000: 1 };
function cleanSaveFaceUn(fu) {
  const out = {};
  if (!fu || typeof fu !== "object") return out;
  for (const k of Object.keys(fu).slice(0, 32)) if (/^[a-z0-9]{3}$/.test(k)) out[k] = 1;
  return out;
}
function cleanSaveRankRw(rw) {
  const out = {};
  if (!rw || typeof rw !== "object") return out;
  for (const k of Object.keys(rw)) if (SAVE_GRADES[k]) out[k] = 1;
  return out;
}
function cleanSaveSeason(sn) {
  if (!sn || typeof sn !== "object") return null;
  const cl = {};
  if (sn.cl && typeof sn.cl === "object") {
    for (const k of Object.keys(sn.cl)) {
      const a = parseInt(k, 10);
      if (SAVE_SEASON_AT[a]) cl[a] = 1;
    }
  }
  return { c: Math.max(0, sn.c | 0), base: Math.max(0, sn.base | 0), cl: cl };
}
// Premio giornaliero: ultimo giorno riscosso (AAAA-MM-GG) + striscia + grazia mensile.
function cleanSaveDaily(dl) {
  if (!dl || typeof dl !== "object") return null;
  const last = typeof dl.last === "string" && /^\d{4}-\d{2}-\d{2}$/.test(dl.last) ? dl.last : "";
  const streak = Math.max(0, Math.min(100000, dl.streak | 0));
  const gm = typeof dl.graceMonth === "string" && /^\d{4}-\d{2}$/.test(dl.graceMonth) ? dl.graceMonth : "";
  const gu = dl.graceUsed ? 1 : 0;
  if (!last && !streak && !gm && !gu) return null;
  return { last: last, streak: streak, graceMonth: gm, graceUsed: gu };
}
// Sfide giornaliere: giorno + contatori + tris (solo id carta validi).
function cleanSaveDq(q) {
  if (!q || typeof q !== "object") return null;
  const day = typeof q.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(q.day) ? q.day : "";
  if (!day) return null;
  const cards = {};
  if (q.cards && typeof q.cards === "object") {
    for (const k of Object.keys(q.cards).slice(0, 64)) if (/^[a-z0-9]{3}$/.test(k)) cards[k] = 1;
  }
  return {
    day: day,
    played: Math.max(0, Math.min(100000, q.played | 0)),
    won: Math.max(0, Math.min(100000, q.won | 0)),
    cards: cards,
    c: [q.c && q.c[0] ? 1 : 0, q.c && q.c[1] ? 1 : 0, q.c && q.c[2] ? 1 : 0],
    bonus: q.bonus ? 1 : 0,
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(env, req) });

    try {
      // ---------- salute (test da browser) ----------
      if (req.method === "GET" && path === "/api/health") {
        return json(env, req, { ok: true, time: Date.now(), v: "pvp28" });
      }

      // ---------- login Google -> sessione ----------
      if (req.method === "POST" && path === "/api/auth/google") {
        const body = await readJson(req);
        const payload = await verifyGoogleToken(body.idToken, env.GOOGLE_CLIENT_ID);
        const now = Date.now();
        let acc = await env.DB.prepare("SELECT * FROM accounts WHERE google_sub = ?")
          .bind(payload.sub).first();
        if (!acc) {
          const id = "a_" + hexBytes(12);
          await env.DB.prepare(
            "INSERT INTO accounts (id, google_sub, email, name, avatar, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
          ).bind(id, payload.sub, payload.email || null, (payload.name || "Giocatore").slice(0, 60),
            payload.picture || null, now, now).run();
          await env.DB.prepare(
            "INSERT INTO stats (account_id, played, won, best_margin, updated_at) VALUES (?, 0, 0, 0, ?)"
          ).bind(id, now).run();
          acc = await env.DB.prepare("SELECT * FROM accounts WHERE id = ?").bind(id).first();
        } else {
          // Il nome scelto nel profilo non si tocca: resta quello salvato (propagato da /api/save).
          // Si aggiorna solo avatar/email da Google.
          await env.DB.prepare("UPDATE accounts SET avatar = ?, email = ?, updated_at = ? WHERE id = ?")
            .bind(payload.picture || acc.avatar, payload.email || acc.email, now, acc.id).run();
          acc = await env.DB.prepare("SELECT * FROM accounts WHERE id = ?").bind(acc.id).first();
        }
        // Riga classifica (punti/gradi): la crea una volta sola, mai sovrascrive
        try {
          await env.DB.prepare("INSERT OR IGNORE INTO ranked (account_id, points, wins, losses, season, updated_at) VALUES (?, 0, 0, 0, ?, ?)")
            .bind(acc.id, curSeason(), now).run();
        } catch (e) {}
        const token = hexBytes(32);
        await env.DB.prepare("INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
          .bind(await sha256hex(token), acc.id, now, now + 90 * 24 * 3600 * 1000).run();
        const save = await env.DB.prepare("SELECT data, updated_at FROM saves WHERE account_id = ?")
          .bind(acc.id).first();
        const st = await env.DB.prepare("SELECT played, won, best_margin FROM stats WHERE account_id = ?")
          .bind(acc.id).first();
        return json(env, req, {
          session: token,
          account: { id: acc.id, name: acc.name, avatar: acc.avatar, email: acc.email },
          save: save ? { data: JSON.parse(save.data), updated_at: save.updated_at } : null,
          stats: st || { played: 0, won: 0, best_margin: 0 },
        });
      }

      // ---------- rotte autenticate ----------
      const accountId = await getSessionAccount(env, req);
      if (!accountId) return json(env, req, { error: "unauthorized" }, 401);

      if (req.method === "GET" && path === "/api/me") {
        const acc = await env.DB.prepare("SELECT id, name, avatar, email FROM accounts WHERE id = ?")
          .bind(accountId).first();
        const st = await env.DB.prepare("SELECT played, won, best_margin FROM stats WHERE account_id = ?")
          .bind(accountId).first();
        let rk = null;
        try {
          rk = await env.DB.prepare("SELECT points, wins, losses, season FROM ranked WHERE account_id = ?")
            .bind(accountId).first();
        } catch (e) {}
        if (rk && rk.season !== curSeason()) {
          // Niente più reset: i punti restano per sempre, si scende solo perdendo.
          // (La "stagione" premi vive sul client con la barra bisettimanale.)
          try {
            await env.DB.prepare("UPDATE ranked SET season = ?, updated_at = ? WHERE account_id = ?")
              .bind(curSeason(), Date.now(), accountId).run();
          } catch (e) {}
          rk = { points: rk.points | 0, wins: rk.wins | 0, losses: rk.losses | 0, season: curSeason() };
        }
        return json(env, req, { account: acc, stats: st, ranked: rk || { points: 0, wins: 0, losses: 0, season: curSeason() } });
      }

      if (req.method === "GET" && path === "/api/save") {
        const save = await env.DB.prepare("SELECT data, updated_at FROM saves WHERE account_id = ?")
          .bind(accountId).first();
        return json(env, req, { save: save ? { data: JSON.parse(save.data), updated_at: save.updated_at } : null });
      }

      if (req.method === "PUT" && path === "/api/save") {
        const body = await readJson(req, 60000);
        if (!body.data || typeof body.data !== "object") throw new Error("bad_save");
        // accetta solo le chiavi note (profilo/deck/portafoglio/collezione/potere/statistiche locali)
        const clean = {
          profile: body.data.profile && typeof body.data.profile === "object" ? {
            name: String(body.data.profile.name || "Giocatore").slice(0, 15),
            avatar: typeof body.data.profile.avatar === "string" ? body.data.profile.avatar.slice(0, 500) : null,
            face: typeof body.data.profile.face === "string" && /^[a-z0-9]{3}$/.test(body.data.profile.face) ? body.data.profile.face : null,
            faceUn: cleanSaveFaceUn(body.data.profile.faceUn),
            season: cleanSaveSeason(body.data.profile.season),
            rankRw: cleanSaveRankRw(body.data.profile.rankRw),
            daily: cleanSaveDaily(body.data.profile.daily),
            dq: cleanSaveDq(body.data.profile.dq),
          } : { name: "Giocatore", avatar: null },
          decks: body.data.decks && typeof body.data.decks === "object" ? body.data.decks : { decks: [], active: 0 },
          wallet: cleanSaveWallet(body.data.wallet),
          packs: cleanSavePacks(body.data.packs),
          own: cleanSaveOwn(body.data.own),
          power: Math.max(0, Math.min(100, body.data.power | 0 || 0)),
          stats: body.data.stats && typeof body.data.stats === "object" ? (() => {
            const _s = body.data.stats, _n = (v) => Math.max(0, v | 0);
            const _cu = {};
            if (_s.cardsUsed && typeof _s.cardsUsed === "object") {
              for (const _k in _s.cardsUsed)
                if (/^[a-z0-9]{3}$/.test(_k) && _s.cardsUsed[_k] && Object.keys(_cu).length < 64) _cu[_k] = 1;
            }
            const _ww = {};
            if (_s.wonWith && typeof _s.wonWith === "object") {
              for (const _k in _s.wonWith)
                if (/^[a-z0-9]{3}$/.test(_k) && _s.wonWith[_k] && Object.keys(_ww).length < 64) _ww[_k] = 1;
            }
            return {
              played: _n(_s.played), won: _n(_s.won), bestMargin: _n(_s.bestMargin),
              streak: _n(_s.streak), bestStreak: _n(_s.bestStreak), passes: _n(_s.passes),
              wonWithPass: _n(_s.wonWithPass), wonNoPass: _n(_s.wonNoPass),
              pvpPlayed: _n(_s.pvpPlayed), pvpWon: _n(_s.pvpWon), packsOpened: _n(_s.packsOpened),
              spheresWon: _n(_s.spheresWon), maxSphere: Math.min(6, _n(_s.maxSphere)),
              cardsUsedN: _n(_s.cardsUsedN), cardsOwned: _n(_s.cardsOwned),
              stylesN: _n(_s.stylesN), decksReady: _n(_s.decksReady),
              cardsUsed: _cu,
              marginWins5: _n(_s.marginWins5), packsBought: _n(_s.packsBought),
              scheggeSpent: _n(_s.scheggeSpent), draftWon: _n(_s.draftWon),
              bestSpheres: _n(_s.bestSpheres), wonWithN: _n(_s.wonWithN), dailyTotal: _n(_s.dailyTotal), bestDailyStreak: _n(_s.bestDailyStreak), powerCharged: _n(_s.powerCharged), nucleiSpent: _n(_s.nucleiSpent), draftPlayed: _n(_s.draftPlayed),
              wonWith: _ww,
            };
          })() : { played: 0, won: 0, bestMargin: 0 },
        };
        // sanifica deck: max 6 deck, nomi corti, solo id carte noti
        if (!Array.isArray(clean.decks.decks)) clean.decks = { decks: [], active: 0 };
        clean.decks.decks = clean.decks.decks.slice(0, 6).map((d) => ({
          name: String((d && d.name) || "Deck").slice(0, 15),
          cards: Array.isArray(d && d.cards) ? d.cards.filter((c) => /^[a-z0-9]{3}$/.test(c)).slice(0, 6) : [],
        }));
        clean.decks.active = Math.min(Math.max(0, clean.decks.active | 0), 5);
        const now = Date.now();
        await env.DB.prepare("INSERT INTO saves (account_id, data, updated_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(account_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at")
          .bind(accountId, JSON.stringify(clean), now).run();
        // Il nome scelto nel profilo diventa quello visto dagli avversari in PvP
        // (le stanze leggono accounts.name, non il blob del save).
        try {
          await env.DB.prepare("UPDATE accounts SET name = ?, avatar = COALESCE(?, avatar), updated_at = ? WHERE id = ?")
            .bind(clean.profile.name, clean.profile.avatar, now, accountId).run();
        } catch (e) {}
        return json(env, req, { ok: true, updated_at: now });
      }

      // Prima sincronizzazione: importa i progressi locali solo se il contatore server e' vergine
      if (req.method === "POST" && path === "/api/sync-seed") {
        const body = await readJson(req);
        const st = await env.DB.prepare("SELECT played, won FROM stats WHERE account_id = ?")
          .bind(accountId).first();
        if (st && (st.played > 0 || st.won > 0)) return json(env, req, { ok: false, reason: "already_seeded" });
        const now = Date.now();
        await env.DB.prepare("UPDATE stats SET played = ?, won = ?, best_margin = ?, updated_at = ? WHERE account_id = ?")
          .bind(Math.max(0, body.played | 0), Math.max(0, body.won | 0),
            Math.max(0, body.bestMargin | 0), now, accountId).run();
        return json(env, req, { ok: true });
      }

      // ---------- PVP (stanze 1v1 a turni simultanei, commit-reveal) ----------
      // Due client risolvono in modo deterministico con gli stessi input;
      // il server fa da arbitro: sequenza sfere condivisa, verifica hash, riconcilia esito.
      // Costi carte: letti da D1 (tabella `cards`) con cache di 5 minuti, fallback completo
      // se la tabella manca. Carte nuove = una riga INSERT in D1, niente più deploy del worker.
      var PVP_COST_FALLBACK = { c01: 4, c02: 3, c03: 4, c04: 5, c05: 3, c06: 3, c07: 3, c08: 4, c09: 3, c10: 2,
        c11: 3, c12: 2, c13: 4, c14: 1, c15: 6, c16: 2, c17: 3, c18: 4, c19: 3, c20: 3 };
      var pvpCostCache = null, pvpCostCacheAt = 0;
      async function pvpCostMap(env) {
        var now = Date.now();
        if (pvpCostCache && now - pvpCostCacheAt < 5 * 60 * 1000) return pvpCostCache;
        try {
          var rows = await env.DB.prepare("SELECT id, cost FROM cards").all();
          var m = {};
          (rows.results || []).forEach(function (r) { if (r && r.id && (r.cost | 0) > 0) m[r.id] = r.cost | 0; });
          if (Object.keys(m).length >= 6) { pvpCostCache = m; pvpCostCacheAt = now; return m; }
        } catch (e) {}
        return PVP_COST_FALLBACK;
      }
      function pvpValidDeck(arr, COST) {
        if (!Array.isArray(arr) || arr.length !== 6) return false;
        var seen = {}, cost = 0;
        for (var i = 0; i < 6; i++) {
          var id = arr[i];
          if (typeof id !== "string" || !COST[id] || seen[id]) return false;
          seen[id] = true; cost += COST[id];
        }
        return cost <= 20;
      }
      function pvpCode() {
        var abc = "ABCDEFGHJKMNPQRSTUVWXYZ23456789", out = "";
        var b = new Uint8Array(4);
        crypto.getRandomValues(b);
        for (var i = 0; i < 4; i++) out += abc[b[i] % abc.length];
        return out;
      }
      function pvpSpheres(n) {
        var b = new Uint8Array(n), out = [];
        crypto.getRandomValues(b);
        for (var i = 0; i < n; i++) out.push(1 + (b[i] % 6));
        return out;
      }
      // Ranghi PVP (punti Sfere): soglie Bronzo 0 / Argento 200 / Oro 400 / Platino 600 / Diamante 800 / Maestro 1000.
      function rankStart(p) {
        p = p | 0;
        if (p >= 1000) return 1000;
        if (p >= 800) return 800;
        if (p >= 600) return 600;
        if (p >= 400) return 400;
        if (p >= 200) return 200;
        return 0;
      }
      function curSeason() {
        var d = new Date();
        return d.getUTCFullYear() + "-" + ("0" + (d.getUTCMonth() + 1)).slice(-2);
      }
      function pvpCanon(turn, move, salt) {
        // Ricostruito dai campi (ordine fisso) cosi client e server coincidono sempre
        var m = move && move.main ? move.main.c + ":" + (move.main.t ? 1 : 0) : "-";
        var s = move && move.support ? move.support.c + ":" + (move.support.t ? 1 : 0) : "-";
        var p = move && move.pass ? "1" : "0";
        return "T" + turn + "|P" + p + "|M" + m + "|S" + s + "|K" + salt;
      }
      function pvpMoveOk(move, COST) {
        if (!move || typeof move !== "object") return false;
        if (move.pass) return true;
        var m = move.main;
        if (!m || typeof m.c !== "string" || !COST[m.c]) return false;
        if (move.support) {
          var s = move.support;
          if (typeof s.c !== "string" || !COST[s.c] || s.c === m.c) return false;
        }
        return true;
      }
      async function pvpRoom(code) {
        return env.DB.prepare("SELECT * FROM rooms WHERE code = ?").bind(String(code || "").toUpperCase()).first();
      }
      function pvpSide(room, accountId) {
        if (room.a_id === accountId) return "A";
        if (room.b_id === accountId) return "B";
        return null;
      }

      if (req.method === "POST" && path === "/api/pvp/create") {
        var cbody = await readJson(req);
        var cCOST = await pvpCostMap(env);
        if (!pvpValidDeck(cbody.deck, cCOST)) return json(env, req, { error: "bad_deck" }, 400);
        // Pulizia stanze vecchie (3h)
        var cutoff = Date.now() - 3 * 3600 * 1000;
        await env.DB.prepare("DELETE FROM pvp_turns WHERE code IN (SELECT code FROM rooms WHERE updated_at < ?)").bind(cutoff).run();
        await env.DB.prepare("DELETE FROM rooms WHERE updated_at < ?").bind(cutoff).run();
        var code = "";
        for (var ci = 0; ci < 8; ci++) {
          code = pvpCode();
          var dup = await env.DB.prepare("SELECT code FROM rooms WHERE code = ?").bind(code).first();
          if (!dup) break;
          code = "";
        }
        if (!code) return json(env, req, { error: "busy" }, 503);
        var acc = await env.DB.prepare("SELECT name, avatar FROM accounts WHERE id = ?").bind(accountId).first();
        var now = Date.now();
        await env.DB.prepare("INSERT INTO rooms (code, status, a_id, b_id, a_name, a_avatar, a_deck, spheres, turn, updated_at, created_at) VALUES (?, 'waiting', ?, NULL, ?, ?, ?, ?, 1, ?, ?)")
          .bind(code, accountId, (acc && acc.name) || "Giocatore", (acc && acc.avatar) || null, JSON.stringify(cbody.deck), JSON.stringify(pvpSpheres(40)), now, now).run();
        return json(env, req, { ok: true, code: code, side: "A" });
      }

      if (req.method === "POST" && path === "/api/pvp/join") {
        var jbody = await readJson(req);
        var room = await pvpRoom(jbody.code);
        if (!room) return json(env, req, { error: "no_room" }, 404);
        if (room.status !== "waiting") return json(env, req, { error: "room_busy" }, 409);
        var jCOST = await pvpCostMap(env);
        if (!pvpValidDeck(jbody.deck, jCOST)) return json(env, req, { error: "bad_deck" }, 400);
        var jacc = await env.DB.prepare("SELECT name, avatar FROM accounts WHERE id = ?").bind(accountId).first();
        var jnow = Date.now();
        await env.DB.prepare("UPDATE rooms SET status = 'playing', b_id = ?, b_name = ?, b_avatar = ?, b_deck = ?, updated_at = ? WHERE code = ?")
          .bind(accountId, (jacc && jacc.name) || "Giocatore", (jacc && jacc.avatar) || null, JSON.stringify(jbody.deck), jnow, room.code).run();
        return json(env, req, {
          ok: true, side: "B",
          spheres: JSON.parse(room.spheres),
          opp: { name: room.a_name, avatar: room.a_avatar },
        });
      }

      if (req.method === "POST" && path === "/api/pvp/commit") {
        var mbody = await readJson(req);
        var mroom = await pvpRoom(mbody.code);
        if (!mroom) return json(env, req, { error: "no_room" }, 404);
        var mside = pvpSide(mroom, accountId);
        if (!mside || (mroom.status !== "playing" && mroom.status !== "waiting")) return json(env, req, { error: "bad_room" }, 409);
        var mturn = mbody.turn | 0;
        var mhash = String(mbody.hash || "");
        if (!(mturn >= 1 && mturn <= 40) || !/^[0-9a-f]{64}$/.test(mhash)) return json(env, req, { error: "bad_commit" }, 400);
        var col = mside === "A" ? "commit_a" : "commit_b";
        var trow = await env.DB.prepare("SELECT * FROM pvp_turns WHERE code = ? AND turn = ?").bind(mroom.code, mturn).first();
        if (!trow) {
          var ins = { commit_a: null, commit_b: null };
          ins[mside === "A" ? "commit_a" : "commit_b"] = mhash;
          await env.DB.prepare("INSERT INTO pvp_turns (code, turn, commit_a, commit_b) VALUES (?, ?, ?, ?)")
            .bind(mroom.code, mturn, ins.commit_a, ins.commit_b).run();
        } else if (!trow[col]) {
          await env.DB.prepare(("UPDATE pvp_turns SET " + col + " = ? WHERE code = ? AND turn = ?")).bind(mhash, mroom.code, mturn).run();
        } else if (trow[col] !== mhash) {
          return json(env, req, { error: "already" }, 409);
        }
        await env.DB.prepare("UPDATE rooms SET updated_at = ? WHERE code = ?").bind(Date.now(), mroom.code).run();
        return json(env, req, { ok: true });
      }

      if (req.method === "POST" && path === "/api/pvp/reveal") {
        var rbody = await readJson(req);
        var rroom = await pvpRoom(rbody.code);
        if (!rroom) return json(env, req, { error: "no_room" }, 404);
        var rside = pvpSide(rroom, accountId);
        if (!rside || rroom.status !== "playing") return json(env, req, { error: "bad_room" }, 409);
        var rturn = rbody.turn | 0;
        var rmove = rbody.move, rsalt = String(rbody.salt || "");
        var rCOST = await pvpCostMap(env);
        if (!(rturn >= 1 && rturn <= 40) || !pvpMoveOk(rmove, rCOST) || !/^[0-9a-f]{16,64}$/.test(rsalt))
          return json(env, req, { error: "bad_reveal" }, 400);
        var rcol = rside === "A" ? "reveal_a" : "reveal_b";
        var ccol = rside === "A" ? "commit_a" : "commit_b";
        var orow = await env.DB.prepare("SELECT * FROM pvp_turns WHERE code = ? AND turn = ?").bind(rroom.code, rturn).first();
        if (!orow || !orow[ccol]) return json(env, req, { error: "not_committed" }, 409);
        var expect = await sha256hex(pvpCanon(rturn, rmove, rsalt));
        if (expect !== orow[ccol]) return json(env, req, { error: "hash_mismatch" }, 409);
        var rjson = JSON.stringify(rmove);
        if (!orow[rcol]) {
          await env.DB.prepare(("UPDATE pvp_turns SET " + rcol + " = ? WHERE code = ? AND turn = ?")).bind(rjson, rroom.code, rturn).run();
        }
        await env.DB.prepare("UPDATE rooms SET updated_at = ? WHERE code = ?").bind(Date.now(), rroom.code).run();
        var fresh = await env.DB.prepare("SELECT * FROM pvp_turns WHERE code = ? AND turn = ?").bind(rroom.code, rturn).first();
        var ocol = rside === "A" ? "reveal_b" : "reveal_a";
        return json(env, req, { ok: true, opp: fresh && fresh[ocol] ? JSON.parse(fresh[ocol]) : null });
      }

      if (req.method === "GET" && path === "/api/pvp/state") {
        var scode = new URL(req.url).searchParams.get("code");
        var sroom = await pvpRoom(scode);
        if (!sroom) return json(env, req, { error: "no_room" }, 404);
        var sside = pvpSide(sroom, accountId);
        if (!sside) return json(env, req, { error: "bad_room" }, 409);
        await env.DB.prepare(sside === "A" ? "UPDATE rooms SET last_seen_a = ? WHERE code = ?" : "UPDATE rooms SET last_seen_b = ? WHERE code = ?").bind(Date.now(), sroom.code).run();
        var srows = await env.DB.prepare("SELECT turn, commit_a, commit_b, reveal_a, reveal_b FROM pvp_turns WHERE code = ? ORDER BY turn").bind(sroom.code).all();
        var turns = {};
        (srows.results || []).forEach(function (t) {
          var mine = sside === "A" ? t.reveal_a : t.reveal_b;
          var theirs = sside === "A" ? t.reveal_b : t.reveal_a;
          turns[t.turn] = {
            ca: !!t.commit_a, cb: !!t.commit_b,
            mine: mine ? JSON.parse(mine) : null,
            opp: (mine && theirs) ? JSON.parse(theirs) : null,
          };
        });
        var isA = sside === "A";
        return json(env, req, {
          ok: true, status: sroom.status, side: sside,
          spheres: JSON.parse(sroom.spheres),
          opp: (isA ? sroom.b_name : sroom.a_name) ? {
            name: isA ? sroom.b_name : sroom.a_name,
            avatar: isA ? sroom.b_avatar : sroom.a_avatar,
          } : null,
          turns: turns,
          winner: sroom.winner || null,
          ranked: !!sroom.ranked,
          leftBy: sroom.left_by || null,
        });
      }

      if (req.method === "POST" && path === "/api/pvp/report") {
        var pbody = await readJson(req);
        var proom = await pvpRoom(pbody.code);
        if (!proom) return json(env, req, { error: "no_room" }, 404);
        var pside = pvpSide(proom, accountId);
        if (!pside) return json(env, req, { error: "bad_room" }, 409);
        var pw = pbody.winner === "A" || pbody.winner === "B" ? pbody.winner : null;
        var psa = Math.max(0, Math.min(99, pbody.scoreA | 0)), psb = Math.max(0, Math.min(99, pbody.scoreB | 0));
        if (!pw) return json(env, req, { error: "bad_report" }, 400);
        var prep = JSON.stringify({ winner: pw, scoreA: psa, scoreB: psb });
        await env.DB.prepare(pside === "A" ? "UPDATE rooms SET rep_a = ?, updated_at = ? WHERE code = ?" : "UPDATE rooms SET rep_b = ?, updated_at = ? WHERE code = ?")
          .bind(prep, Date.now(), proom.code).run();
        var cur = await pvpRoom(proom.code);
        var decided = null;
        if (cur.left_by && cur.left_by !== pside) {
          // L'avversario ha abbandonato: vale l'esito segnalato dal rimasto
          decided = pw;
        } else if (cur.rep_a && cur.rep_b) {
          var qa = JSON.parse(cur.rep_a), qb = JSON.parse(cur.rep_b);
          if (qa.winner === qb.winner) decided = qa.winner;
          else {
            await env.DB.prepare("UPDATE rooms SET status = 'done', winner = NULL, updated_at = ? WHERE code = ?").bind(Date.now(), cur.code).run();
            return json(env, req, { ok: true, status: "disputed" });
          }
        } else if (!cur.rep_a !== !cur.rep_b) {
          // Una sola segnalazione e l'altro è sparito da oltre 90s (tab chiusa):
          // accetta il risultato del rimasto invece di perdere le statistiche
          var foeSeen = pside === "A" ? (cur.last_seen_b || 0) : (cur.last_seen_a || 0);
          if (Date.now() - foeSeen > 90000) decided = pw;
        }
        if (decided) {
          await env.DB.prepare("UPDATE rooms SET status = 'done', winner = ?, updated_at = ? WHERE code = ?").bind(decided, Date.now(), cur.code).run();
          // Statistiche server (una sola volta per account distinto)
          var seen = {}, now2 = Date.now();
          var ids = [cur.a_id, cur.b_id].filter(function (x) { return x && !seen[x] && (seen[x] = true); });
          var margin = Math.abs(psa - psb);
          for (var si = 0; si < ids.length; si++) {
            var aid = ids[si];
            var won = (decided === "A" && aid === cur.a_id) || (decided === "B" && aid === cur.b_id) ? 1 : 0;
            await env.DB.prepare("UPDATE stats SET played = played + 1, won = won + ?, best_margin = MAX(best_margin, ?), updated_at = ? WHERE account_id = ?")
              .bind(won, won ? margin : 0, now2, aid).run();
          }
          if (cur.ranked) {
            // Punti Sfere: vittoria +20 (+5 schiacciante con 10+ di scarto, +5 impresa contro rango superiore),
            // sconfitta -(13 - propri VP) con minimo 0 — SI SCENDE di rango (retrocessioni).
            var rkq = await env.DB.prepare("SELECT account_id, points FROM ranked WHERE account_id = ? OR account_id = ?")
              .bind(cur.a_id, cur.b_id).all();
            var rpts = {};
            (rkq.results || []).forEach(function (r) { rpts[r.account_id] = r.points | 0; });
            var pa0 = rpts[cur.a_id] != null ? rpts[cur.a_id] : 0;
            var pb0 = rpts[cur.b_id] != null ? rpts[cur.b_id] : 0;
            var wa2 = decided === "A" ? 1 : 0, wb2 = decided === "B" ? 1 : 0;
            var wPre = wa2 ? pa0 : pb0, lPre = wa2 ? pb0 : pa0;
            var wBonus = 0;
            if (Math.abs(psa - psb) >= 10) wBonus += 5; // schiacciante
            if (rankStart(wPre) < rankStart(lPre)) wBonus += 5; // impresa
            var na = wa2 ? pa0 + 20 + wBonus : Math.max(0, pa0 - (13 - (psa | 0)));
            var nb = wb2 ? pb0 + 20 + wBonus : Math.max(0, pb0 - (13 - (psb | 0)));
            var seasonNow = curSeason();
            await env.DB.prepare("INSERT INTO ranked (account_id, points, wins, losses, season, updated_at) VALUES (?, ?, ?, ?, ?, ?) " +
              "ON CONFLICT(account_id) DO UPDATE SET points = excluded.points, wins = wins + ?, losses = losses + ?, season = excluded.season, updated_at = excluded.updated_at")
              .bind(cur.a_id, na, wa2, 1 - wa2, seasonNow, now2, wa2, 1 - wa2).run();
            await env.DB.prepare("INSERT INTO ranked (account_id, points, wins, losses, season, updated_at) VALUES (?, ?, ?, ?, ?, ?) " +
              "ON CONFLICT(account_id) DO UPDATE SET points = excluded.points, wins = wins + ?, losses = losses + ?, season = excluded.season, updated_at = excluded.updated_at")
              .bind(cur.b_id, nb, wb2, 1 - wb2, seasonNow, now2, wb2, 1 - wb2).run();
          }
          return json(env, req, { ok: true, status: "done", winner: decided });
        }
        return json(env, req, { ok: true, status: "open" });
      }

      // ---------- FINTE SIMULATE (backfill client: nessun umano trovato) ----------
      // Stessi punti del report (vittoria +20 con +5 schiacciante, sconfitta -(13 - propri VP)
      // con minimo 0 e retrocessioni), ma senza stanza e SENZA bonus impresa (l'avversario è finto).
      if (req.method === "POST" && path === "/api/pvp/sim") {
        var qbody = await readJson(req);
        var qwon = !!qbody.won;
        var qm = Math.max(0, Math.min(99, qbody.scoreMine | 0));
        var qf = Math.max(0, Math.min(99, qbody.scoreFoe | 0));
        var qnow = Date.now();
        try {
          await env.DB.prepare("INSERT OR IGNORE INTO ranked (account_id, points, wins, losses, season, updated_at) VALUES (?, 0, 0, 0, ?, ?)")
            .bind(accountId, curSeason(), qnow).run();
        } catch (e) {}
        var qr = await env.DB.prepare("SELECT points, wins, losses FROM ranked WHERE account_id = ?").bind(accountId).first();
        var qp0 = (qr && qr.points) | 0;
        var qw0 = (qr && qr.wins) | 0;
        var ql0 = (qr && qr.losses) | 0;
        var qmargin = Math.abs(qm - qf);
        var qpts = qwon ? qp0 + 20 + (qmargin >= 10 ? 5 : 0) : Math.max(0, qp0 - (13 - qm));
        var qnw = qw0 + (qwon ? 1 : 0), qnl = ql0 + (qwon ? 0 : 1);
        await env.DB.prepare("UPDATE stats SET played = played + 1, won = won + ?, best_margin = MAX(best_margin, ?), updated_at = ? WHERE account_id = ?")
          .bind(qwon ? 1 : 0, qwon ? qmargin : 0, qnow, accountId).run();
        await env.DB.prepare("INSERT INTO ranked (account_id, points, wins, losses, season, updated_at) VALUES (?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(account_id) DO UPDATE SET points = excluded.points, wins = excluded.wins, losses = excluded.losses, season = excluded.season, updated_at = excluded.updated_at")
          .bind(accountId, qpts, qnw, qnl, curSeason(), qnow).run();
        return json(env, req, { ok: true, points: qpts, wins: qnw, losses: qnl });
      }

      if (req.method === "POST" && path === "/api/pvp/leave") {
        var lbody = await readJson(req);
        var lroom = await pvpRoom(lbody.code);
        if (!lroom) return json(env, req, { error: "no_room" }, 404);
        var lside = pvpSide(lroom, accountId);
        if (!lside) return json(env, req, { error: "bad_room" }, 409);
        if (lroom.status === "playing" || lroom.status === "waiting") {
          await env.DB.prepare("UPDATE rooms SET status = 'left', left_by = ?, updated_at = ? WHERE code = ?")
            .bind(lside, Date.now(), lroom.code).run();
        }
        return json(env, req, { ok: true });
      }

      // ---------- CLASSIFICATA (matchmaking automatico + punti Sfere) ----------
      // Coda: il client chiama /find ogni 2s. Chi trova un altro in attesa
      // crea la stanza ranked (lo trova = B, chi aspettava = A) ed entrambi
      // ricevono {matched, code, side, spheres, opp}. Chi aspettava lo scopre
      // alla chiamata successiva (riconnessione alla stanza appena creata).
      if (req.method === "POST" && path === "/api/pvp/find") {
        var fbody = await readJson(req);
        var fCOST = await pvpCostMap(env);
        if (!pvpValidDeck(fbody.deck, fCOST)) return json(env, req, { error: "bad_deck" }, 400);
        var fnow = Date.now();
        // Riconnessione: ho gia una stanza ranked in corso? Torno a quella.
        var live = null;
        try {
          live = await env.DB.prepare("SELECT * FROM rooms WHERE ranked = 1 AND status = 'playing' AND (a_id = ? OR b_id = ?) ORDER BY updated_at DESC LIMIT 1")
            .bind(accountId, accountId).first();
        } catch (e) {}
        if (live && (fnow - live.updated_at) < 30 * 60 * 1000) {
          var lside2 = pvpSide(live, accountId);
          var lopp = lside2 === "A" ? { name: live.b_name, avatar: live.b_avatar } : { name: live.a_name, avatar: live.a_avatar };
          return json(env, req, {
            ok: true, matched: true, code: live.code, side: lside2,
            spheres: JSON.parse(live.spheres), opp: lopp, ranked: true,
          });
        }
        // Pulizia code vecchie (2 min) + stanze abbandonate vecchie (3h)
        try {
          await env.DB.prepare("DELETE FROM queue WHERE enqueued_at < ?").bind(fnow - 120000).run();
          var fcut = Date.now() - 3 * 3600 * 1000;
          await env.DB.prepare("DELETE FROM pvp_turns WHERE code IN (SELECT code FROM rooms WHERE updated_at < ?)").bind(fcut).run();
          await env.DB.prepare("DELETE FROM rooms WHERE updated_at < ?").bind(fcut).run();
        } catch (e) {}
        await env.DB.prepare("INSERT INTO queue (account_id, deck, enqueued_at) VALUES (?, ?, ?) " +
          "ON CONFLICT(account_id) DO UPDATE SET deck = excluded.deck, enqueued_at = excluded.enqueued_at")
          .bind(accountId, JSON.stringify(fbody.deck), fnow).run();
        var foe = null;
        try {
          foe = await env.DB.prepare("SELECT account_id, deck FROM queue WHERE account_id != ? ORDER BY enqueued_at ASC LIMIT 1")
            .bind(accountId).first();
        } catch (e) {}
        if (!foe) {
          var fqc = 0; // quanti altri stanno cercando (il client aspetta solo se > 0)
          try {
            var frow = await env.DB.prepare("SELECT COUNT(*) AS n FROM queue WHERE account_id != ?").bind(accountId).first();
            fqc = (frow && frow.n) | 0;
          } catch (e) {}
          return json(env, req, { ok: true, waiting: true, queueCount: fqc });
        }
        // Accoppia: chi aspettava (foe) = A, io = B
        var fcode = "";
        for (var fci = 0; fci < 8; fci++) {
          var fc = pvpCode();
          var fdup = await env.DB.prepare("SELECT code FROM rooms WHERE code = ?").bind(fc).first();
          if (!fdup) { fcode = fc; break; }
        }
        if (!fcode) return json(env, req, { error: "busy" }, 503);
        var fme = await env.DB.prepare("SELECT name, avatar FROM accounts WHERE id = ?").bind(accountId).first();
        var foea = await env.DB.prepare("SELECT name, avatar FROM accounts WHERE id = ?").bind(foe.account_id).first();
        try {
          await env.DB.prepare("INSERT OR IGNORE INTO ranked (account_id, points, wins, losses, season, updated_at) VALUES (?, 0, 0, 0, ?, ?)")
            .bind(foe.account_id, curSeason(), fnow).run();
        } catch (e) {}
        await env.DB.prepare("INSERT INTO rooms (code, status, a_id, b_id, a_name, a_avatar, a_deck, b_name, b_avatar, b_deck, spheres, turn, ranked, updated_at, created_at) VALUES (?, 'playing', ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?)")
          .bind(fcode, foe.account_id, accountId,
            (foea && foea.name) || "Avversario", (foea && foea.avatar) || null, foe.deck,
            (fme && fme.name) || "Giocatore", (fme && fme.avatar) || null, JSON.stringify(fbody.deck),
            JSON.stringify(pvpSpheres(40)), fnow, fnow).run();
        await env.DB.prepare("DELETE FROM queue WHERE account_id = ? OR account_id = ?").bind(accountId, foe.account_id).run();
        return json(env, req, {
          ok: true, matched: true, code: fcode, side: "B",
          spheres: JSON.parse((await pvpRoom(fcode)).spheres),
          opp: { name: (foea && foea.name) || "Avversario", avatar: (foea && foea.avatar) || null },
          ranked: true,
        });
      }

      if (req.method === "POST" && path === "/api/pvp/queue/leave") {
        await env.DB.prepare("DELETE FROM queue WHERE account_id = ?").bind(accountId).run();
        return json(env, req, { ok: true });
      }

      // Esito partita (contatori server, incrementali: niente doppi conteggi)
      if (req.method === "POST" && path === "/api/result") {
        const body = await readJson(req);
        const won = body.won ? 1 : 0;
        const margin = Math.max(0, body.margin | 0);
        await env.DB.prepare("UPDATE stats SET played = played + 1, won = won + ?, " +
          "best_margin = MAX(best_margin, ?), updated_at = ? WHERE account_id = ?")
          .bind(won, won ? margin : 0, Date.now(), accountId).run();
        return json(env, req, { ok: true });
      }

      // Elimina account e tutti i dati (irreversibile, richiede login).
      // POST usato dal sito (stesso percorso del login, niente preflight strani);
      // DELETE tenuto per compatibilita.
      if ((req.method === "POST" && path === "/api/account/delete") ||
          (req.method === "DELETE" && path === "/api/account")) {
        await env.DB.prepare("DELETE FROM sessions WHERE account_id = ?").bind(accountId).run();
        await env.DB.prepare("DELETE FROM saves WHERE account_id = ?").bind(accountId).run();
        await env.DB.prepare("DELETE FROM stats WHERE account_id = ?").bind(accountId).run();
        await env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(accountId).run();
        return json(env, req, { ok: true });
      }

      if (req.method === "GET" && path === "/api/leaderboard") {
        const rows = await env.DB.prepare(
          "SELECT s.account_id, a.name, a.avatar, s.played, s.won FROM stats s JOIN accounts a ON a.id = s.account_id " +
          "WHERE s.played > 0 ORDER BY s.won DESC, s.played ASC LIMIT 20"
        ).all();
        const top = (rows.results || []).map((r, i) => ({
          rank: i + 1, name: r.name, avatar: r.avatar, played: r.played, won: r.won,
          me: r.account_id === accountId,
        }));
        const better = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM stats WHERE (won > (SELECT won FROM stats WHERE account_id = ?)) " +
          "OR (won = (SELECT won FROM stats WHERE account_id = ?) AND played < (SELECT played FROM stats WHERE account_id = ?))"
        ).bind(accountId, accountId, accountId).first();
        const mine = await env.DB.prepare("SELECT played, won FROM stats WHERE account_id = ?")
          .bind(accountId).first();
        return json(env, req, {
          top: top,
          me: mine && mine.played > 0 ? { rank: (better ? better.n : 0) + 1, played: mine.played, won: mine.won } : null,
        });
      }

      return json(env, req, { error: "not_found" }, 404);
    } catch (e) {
      return json(env, req, { error: "bad_request" }, 400);
    }
  },
};
