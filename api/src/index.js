// Auth par token Bearer (pas de cookie) : la GUI vit sur un domaine différent
// de l'API (local puis GitHub Pages vs workers.dev), et les cookies tiers
// SameSite=None sont de plus en plus restreints/expirés par les navigateurs
// (Safari ITP, etc.) indépendamment du Max-Age qu'on configure côté serveur.
// Un token en localStorage + header Authorization évite complètement ce
// problème. On reflète l'origine de la requête tant que la GUI n'a pas
// d'origine fixe — à verrouiller sur l'origine GitHub Pages définitive plus tard.
// Ceci dit, comme il n'y a plus de cookie, un site tiers ne peut de toute
// façon pas lire le token dans le localStorage d'un autre domaine : le
// scénario CSRF classique que ce verrouillage évite habituellement ne
// s'applique plus vraiment ici.
function corsHeaders(request) {
  return {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    Vary: "Origin",
  };
}

// Le runtime Workers plafonne PBKDF2 à 100 000 itérations (NotSupportedError
// au-delà), quel que soit le plan — donc ce n'est pas un choix, c'est le max.
const PBKDF2_ITERATIONS = 100000;
const SESSION_DURATION_SECONDS = 60 * 60 * 24 * 30; // 30 jours

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    let response;
    try {
      if (url.pathname === "/health" && request.method === "GET") {
        // L'API répond dans tous les cas (sinon cette requête n'aurait pas
        // abouti) : seul l'état de la DB peut varier indépendamment.
        let dbOk = false;
        try {
          const result = await env.DB.prepare("SELECT 1 AS ok").first();
          dbOk = !!(result && result.ok === 1);
        } catch (err) {
          console.log(`health check: DB error: ${err}`);
        }
        response = json({ api: true, db: dbOk });
      } else if (url.pathname === "/auth/register" && request.method === "POST") {
        response = await handleRegister(request, env);
      } else if (url.pathname === "/auth/login" && request.method === "POST") {
        response = await handleLogin(request, env);
      } else if (url.pathname === "/auth/logout" && request.method === "POST") {
        response = await handleLogout(request, env);
      } else if (url.pathname === "/auth/login/mfa" && request.method === "POST") {
        response = await handleLoginMfa(request, env);
      } else if (url.pathname === "/account/change-password" && request.method === "POST") {
        response = await handleChangePassword(request, env);
      } else if (url.pathname === "/account/mfa/setup" && request.method === "POST") {
        response = await handleMfaSetup(request, env);
      } else if (url.pathname === "/account/mfa/confirm" && request.method === "POST") {
        response = await handleMfaConfirm(request, env);
      } else if (url.pathname === "/account/mfa/disable" && request.method === "POST") {
        response = await handleMfaDisable(request, env);
      } else if (url.pathname === "/me" && request.method === "GET") {
        response = await handleMe(request, env);
      } else if (url.pathname === "/gw2/link" && request.method === "POST") {
        response = await handleLinkGw2(request, env);
      } else if (url.pathname === "/gw2/link" && request.method === "DELETE") {
        response = await handleUnlinkGw2(request, env);
      } else if (url.pathname === "/guild/matches" && request.method === "GET") {
        response = await handleGuildMatches(request, env);
      } else if (url.pathname === "/admin/bootstrap" && request.method === "POST") {
        response = await handleAdminBootstrap(request, env);
      } else if (url.pathname === "/admin/promote" && request.method === "POST") {
        response = await handleAdminPromote(request, env);
      } else if (url.pathname === "/admin/users" && request.method === "GET") {
        response = await handleAdminListUsers(request, env, url);
      } else if (url.pathname === "/admin/users/delete" && request.method === "POST") {
        response = await handleAdminDeleteUser(request, env);
      } else if (url.pathname === "/admin/users/reset-password" && request.method === "POST") {
        response = await handleAdminResetPassword(request, env);
      } else if (url.pathname === "/admin/analytics" && request.method === "GET") {
        response = await handleAdminAnalytics(request, env);
      } else if (url.pathname === "/admin/metrics" && request.method === "GET") {
        response = await handleAdminMetrics(request, env);
      } else {
        response = json({ error: "Route introuvable." }, 404);
      }
    } catch (err) {
      response = json({ error: "Erreur serveur.", detail: String((err && err.message) || err) }, 500);
    }

    // Fusionne le CORS sur la réponse du handler sans écraser ses propres
    // en-têtes (notamment Set-Cookie sur login/register/logout).
    const headers = new Headers(response.headers);
    Object.entries(cors).forEach(([k, v]) => headers.set(k, v));
    return new Response(response.body, { status: response.status, headers });
  },
};

// --- Authentification ---

async function handleRegister(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  if (!isValidEmail(email)) return json({ error: "Email invalide." }, 400);
  if (password.length < 10) return json({ error: "Le mot de passe doit faire au moins 10 caractères." }, 400);

  // Anti-spam de création de comptes, par IP (pas par email : un attaquant
  // choisirait de toute façon un email différent à chaque tentative).
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const cooldownError = await checkCooldown(env, "register:" + ip, 5000);
  if (cooldownError) return cooldownError;

  const existing = await env.DB.prepare("SELECT id FROM accounts WHERE email = ?").bind(email).first();
  if (existing) {
    trackEvent(env, "register", "email_taken");
    return json({ error: "Un compte existe déjà avec cet email." }, 409);
  }

  const { hash, salt } = await hashPassword(password);
  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO accounts (id, email, password_hash, password_salt) VALUES (?, ?, ?, ?)")
    .bind(id, email, hash, salt)
    .run();

  trackEvent(env, "register", "success");
  return startSession(env, id, email);
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";

  const genericError = () => json({ error: "Email ou mot de passe incorrect." }, 401);
  if (!isValidEmail(email) || !password) return genericError();

  // Anti brute-force : cooldown par email ciblé (empêche de tester des
  // mots de passe en rafale contre un compte précis).
  const cooldownError = await checkCooldown(env, "login:" + email, 2000);
  if (cooldownError) return cooldownError;

  const account = await env.DB.prepare(
    "SELECT id, email, password_hash, password_salt, mfa_enabled FROM accounts WHERE email = ?"
  ).bind(email).first();

  if (!account) {
    await hashPassword(password); // temps constant : évite de révéler que l'email n'existe pas
    trackEvent(env, "login", "failure");
    return genericError();
  }

  const ok = await verifyPassword(password, account.password_salt, account.password_hash);
  if (!ok) {
    trackEvent(env, "login", "failure");
    return genericError();
  }

  if (account.mfa_enabled) {
    const challengeToken = randomToken(24);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    await env.DB.prepare("INSERT INTO mfa_challenges (token, account_id, expires_at) VALUES (?, ?, ?)")
      .bind(challengeToken, account.id, expiresAt).run();
    trackEvent(env, "login", "mfa_required");
    return json({ mfa_required: true, challenge_token: challengeToken });
  }

  trackEvent(env, "login", "success");
  return startSession(env, account.id, account.email);
}

async function handleLogout(request, env) {
  const token = bearerToken(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  return json({ ok: true });
}

async function handleChangePassword(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const body = await request.json().catch(() => ({}));
  const currentPassword = body.current_password || "";
  const newPassword = body.new_password || "";
  if (newPassword.length < 10) return json({ error: "Le nouveau mot de passe doit faire au moins 10 caractères." }, 400);

  const row = await env.DB.prepare("SELECT password_hash, password_salt FROM accounts WHERE id = ?").bind(account.id).first();
  const ok = await verifyPassword(currentPassword, row.password_salt, row.password_hash);
  if (!ok) return json({ error: "Mot de passe actuel incorrect." }, 401);

  const { hash, salt } = await hashPassword(newPassword);
  const currentToken = bearerToken(request);
  await env.DB.prepare("UPDATE accounts SET password_hash = ?, password_salt = ? WHERE id = ?")
    .bind(hash, salt, account.id).run();
  // Invalide les autres sessions (autres appareils/navigateurs), garde celle-ci active.
  await env.DB.prepare("DELETE FROM sessions WHERE account_id = ? AND token != ?")
    .bind(account.id, currentToken).run();

  trackEvent(env, "change_password", "success");
  return json({ ok: true });
}

// --- MFA (TOTP) ---

async function handleMfaSetup(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const secret = generateTotpSecret();
  const encrypted = await encryptSecret(env, secret);
  // Stocké mais mfa_enabled reste à 0 tant que /account/mfa/confirm n'a pas
  // vérifié un vrai code — évite de s'activer un MFA qu'on n'a pas su lire.
  await env.DB.prepare("UPDATE accounts SET mfa_secret_encrypted = ? WHERE id = ?")
    .bind(encrypted, account.id).run();

  const label = encodeURIComponent(`GW2 Guild Tool:${account.email}`);
  const otpauthUri = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent("GW2 Guild Tool")}&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;

  return json({ secret, otpauth_uri: otpauthUri });
}

async function handleMfaConfirm(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const body = await request.json().catch(() => ({}));
  const row = await env.DB.prepare("SELECT mfa_secret_encrypted FROM accounts WHERE id = ?").bind(account.id).first();
  if (!row.mfa_secret_encrypted) return json({ error: "Lance d'abord la configuration du MFA." }, 400);

  const secret = await decryptSecret(env, row.mfa_secret_encrypted);
  const ok = await verifyTotp(secret, body.code);
  if (!ok) return json({ error: "Code invalide." }, 401);

  await env.DB.prepare("UPDATE accounts SET mfa_enabled = 1 WHERE id = ?").bind(account.id).run();
  trackEvent(env, "mfa_enable", "success");
  return json({ ok: true });
}

async function handleMfaDisable(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const body = await request.json().catch(() => ({}));
  const row = await env.DB.prepare("SELECT password_hash, password_salt FROM accounts WHERE id = ?").bind(account.id).first();
  const ok = await verifyPassword(body.current_password || "", row.password_salt, row.password_hash);
  if (!ok) return json({ error: "Mot de passe actuel incorrect." }, 401);

  await env.DB.prepare("UPDATE accounts SET mfa_enabled = 0, mfa_secret_encrypted = NULL WHERE id = ?").bind(account.id).run();
  trackEvent(env, "mfa_disable", "success");
  return json({ ok: true });
}

async function handleLoginMfa(request, env) {
  const body = await request.json().catch(() => ({}));
  const challengeToken = body.challenge_token || "";
  const genericError = () => json({ error: "Code invalide ou expiré." }, 401);

  const challenge = await env.DB.prepare(
    "SELECT account_id FROM mfa_challenges WHERE token = ? AND expires_at > datetime('now')"
  ).bind(challengeToken).first();
  if (!challenge) return genericError();

  const account = await env.DB.prepare("SELECT id, email, mfa_secret_encrypted FROM accounts WHERE id = ?")
    .bind(challenge.account_id).first();
  if (!account || !account.mfa_secret_encrypted) return genericError();

  const secret = await decryptSecret(env, account.mfa_secret_encrypted);
  const ok = await verifyTotp(secret, body.code);
  if (!ok) return genericError();

  await env.DB.prepare("DELETE FROM mfa_challenges WHERE token = ?").bind(challengeToken).run();
  trackEvent(env, "login_mfa", "success");
  return startSession(env, account.id, account.email);
}

async function handleMe(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const links = await env.DB.prepare(
    "SELECT gw2_links.id, gw2_account_name, GROUP_CONCAT(user_guilds.guild_id) AS guild_ids " +
    "FROM gw2_links LEFT JOIN user_guilds ON user_guilds.gw2_link_id = gw2_links.id " +
    "WHERE account_id = ? GROUP BY gw2_links.id"
  ).bind(account.id).all();

  return json({
    id: account.id,
    email: account.email,
    role: account.role,
    mfa_enabled: !!account.mfa_enabled,
    gw2_links: links.results.map((r) => ({
      id: r.id,
      name: r.gw2_account_name,
      guilds: r.guild_ids ? r.guild_ids.split(",") : [],
    })),
  });
}

// --- Liaison d'une clé API GW2 ---

// L'API GW2 est appelée depuis le NAVIGATEUR (pas depuis ce Worker) : les IP
// de sortie des Workers Cloudflare sont mutualisées entre des milliers de
// clients, et GW2 rate-limite (au moins en partie) par IP source — ça nous
// faisait hériter de blocages sans rapport avec notre propre usage. Le
// navigateur, lui, part de l'IP de l'utilisateur, comme n'importe quel client
// GW2 normal. Le Worker fait confiance aux infos rapportées par le client
// (id/nom/guildes) plutôt que de les revérifier lui-même — compromis assumé,
// acceptable pour un outil entre membres de confiance d'une même guilde.
const GW2_ID_RE = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i;

async function handleLinkGw2(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const body = await request.json().catch(() => ({}));
  const apiKey = (body.api_key || "").trim();
  const gw2Account = body.gw2_account || {};

  if (!apiKey) return json({ error: "Clé API manquante." }, 400);
  if (!GW2_ID_RE.test(gw2Account.id || "")) return json({ error: "Identifiant de compte GW2 invalide." }, 400);
  if (typeof gw2Account.name !== "string" || !gw2Account.name) return json({ error: "Nom de compte GW2 manquant." }, 400);
  if (!Array.isArray(gw2Account.guilds)) gw2Account.guilds = [];

  console.log(`gw2/link requested by account=${account.id} gw2_id=${gw2Account.id}`);

  // Cooldown local : évite le spam d'écritures en base (plus de rapport avec
  // GW2 puisqu'on ne l'appelle plus depuis ici, mais reste utile en soi).
  const cooldownError = await checkCooldown(env, "gw2link:" + account.id, 3000);
  if (cooldownError) {
    console.log(`gw2/link blocked by cooldown for account=${account.id}`);
    return cooldownError;
  }

  const owner = await env.DB.prepare("SELECT account_id FROM gw2_links WHERE id = ?").bind(gw2Account.id).first();
  if (owner && owner.account_id !== account.id) {
    trackEvent(env, "gw2_link", "already_linked");
    return json({ error: "Ce compte GW2 est déjà lié à un autre compte." }, 409);
  }

  const encrypted = await encryptSecret(env, apiKey);
  await env.DB.prepare(
    "INSERT INTO gw2_links (id, account_id, gw2_account_name, api_key_encrypted) VALUES (?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET gw2_account_name = excluded.gw2_account_name, api_key_encrypted = excluded.api_key_encrypted"
  ).bind(gw2Account.id, account.id, gw2Account.name, encrypted).run();

  await env.DB.prepare("DELETE FROM user_guilds WHERE gw2_link_id = ?").bind(gw2Account.id).run();
  const guildIds = gw2Account.guilds || [];
  for (const guildId of guildIds) {
    await env.DB.prepare("INSERT INTO user_guilds (gw2_link_id, guild_id) VALUES (?, ?)").bind(gw2Account.id, guildId).run();
  }

  trackEvent(env, "gw2_link", "success");
  return json({ id: gw2Account.id, name: gw2Account.name, guilds: guildIds });
}

async function handleUnlinkGw2(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  const body = await request.json().catch(() => ({}));
  const linkId = body.id;
  if (!linkId) return json({ error: "Identifiant manquant." }, 400);

  const link = await env.DB.prepare("SELECT account_id FROM gw2_links WHERE id = ?").bind(linkId).first();
  if (!link || link.account_id !== account.id) return json({ error: "Introuvable." }, 404);

  await env.DB.prepare("DELETE FROM user_guilds WHERE gw2_link_id = ?").bind(linkId).run();
  await env.DB.prepare("DELETE FROM gw2_links WHERE id = ?").bind(linkId).run();
  return json({ ok: true });
}

// --- Matching de guilde ---

async function handleGuildMatches(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  trackEvent(env, "guild_matches", "query");

  const myLinks = await env.DB.prepare("SELECT id FROM gw2_links WHERE account_id = ?").bind(account.id).all();
  const myLinkIds = myLinks.results.map((r) => r.id);
  if (myLinkIds.length === 0) return json({ matches: [] });

  const linkPlaceholders = myLinkIds.map(() => "?").join(",");
  const myGuilds = await env.DB.prepare(
    `SELECT DISTINCT guild_id FROM user_guilds WHERE gw2_link_id IN (${linkPlaceholders})`
  ).bind(...myLinkIds).all();
  const guildIds = myGuilds.results.map((r) => r.guild_id);
  if (guildIds.length === 0) return json({ matches: [] });

  const guildPlaceholders = guildIds.map(() => "?").join(",");
  const others = await env.DB.prepare(
    `SELECT ug.guild_id, gl.id AS gw2_link_id, gl.gw2_account_name
     FROM user_guilds ug
     JOIN gw2_links gl ON gl.id = ug.gw2_link_id
     WHERE ug.guild_id IN (${guildPlaceholders}) AND gl.account_id != ?`
  ).bind(...guildIds, account.id).all();

  const byGuild = {};
  others.results.forEach((row) => {
    byGuild[row.guild_id] = byGuild[row.guild_id] || [];
    byGuild[row.guild_id].push({ gw2_link_id: row.gw2_link_id, name: row.gw2_account_name });
  });

  return json({ matches: byGuild });
}

// --- Administration ---

// Amorce le tout premier admin : ne fonctionne que si SUPER_ADMIN_MODE=true
// ET qu'aucun admin n'existe encore (double verrou — même en oubliant de
// repasser le flag à false, l'endpoint devient un no-op après coup).
async function handleAdminBootstrap(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;

  if (env.SUPER_ADMIN_MODE !== "true") {
    return json({ error: "Mode bootstrap désactivé." }, 403);
  }

  const existingAdmin = await env.DB.prepare("SELECT id FROM accounts WHERE role = 'admin' LIMIT 1").first();
  if (existingAdmin) {
    return json({ error: "Un admin existe déjà — utilise la promotion normale." }, 403);
  }

  await env.DB.prepare("UPDATE accounts SET role = 'admin' WHERE id = ?").bind(account.id).run();
  trackEvent(env, "admin_bootstrap", "success");
  return json({ ok: true, role: "admin" });
}

// Un admin peut en promouvoir un autre — indépendant du mode bootstrap.
async function handleAdminPromote(request, env) {
  const admin = await requireAdmin(request, env);
  if (admin instanceof Response) return admin;

  const body = await request.json().catch(() => ({}));
  const email = (body.email || "").trim().toLowerCase();
  if (!isValidEmail(email)) return json({ error: "Email invalide." }, 400);

  const target = await env.DB.prepare("SELECT id, role FROM accounts WHERE email = ?").bind(email).first();
  if (!target) return json({ error: "Aucun compte avec cet email." }, 404);
  if (target.role === "admin") return json({ error: "Déjà admin." }, 409);

  await env.DB.prepare("UPDATE accounts SET role = 'admin' WHERE id = ?").bind(target.id).run();
  trackEvent(env, "admin_promote", "success");
  return json({ ok: true, email });
}

// Pas sensible (visible dans wrangler.toml), donc en dur ici plutôt qu'en
// secret — seul le token CF_ANALYTICS_TOKEN ci-dessous a besoin d'en être un.
const CLOUDFLARE_ACCOUNT_ID = "8cfbb71203c475ce15c0f1d522670443";

async function handleAdminAnalytics(request, env) {
  const admin = await requireAdmin(request, env);
  if (admin instanceof Response) return admin;

  if (!env.CF_ANALYTICS_TOKEN) {
    return json({ error: "Analytics non configuré (secret CF_ANALYTICS_TOKEN manquant)." }, 501);
  }

  const query =
    "SELECT index1 AS event, blob1 AS outcome, count() AS n " +
    "FROM gw2_guild_tool_events GROUP BY event, outcome ORDER BY event, n DESC";

  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/analytics_engine/sql`,
    { method: "POST", headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}` }, body: query }
  );

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    return json({ error: "Erreur requête analytics.", detail: detail.slice(0, 300) }, 502);
  }

  const data = await res.json();
  return json({ rows: data.data || [] });
}

// Métriques natives du Worker (requêtes/erreurs/latence par heure) via l'API
// GraphQL Analytics — même token CF_ANALYTICS_TOKEN, un scope suffit pour
// les deux (Account > Analytics > Read couvre Analytics Engine ET GraphQL).
async function handleAdminMetrics(request, env) {
  const admin = await requireAdmin(request, env);
  if (admin instanceof Response) return admin;

  if (!env.CF_ANALYTICS_TOKEN) {
    return json({ error: "Analytics non configuré (secret CF_ANALYTICS_TOKEN manquant)." }, 501);
  }

  const end = new Date();
  const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);

  const gqlQuery = `
    query ($accountTag: string!, $scriptName: string!, $start: string!, $end: string!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          workersInvocationsAdaptive(
            limit: 200
            filter: { scriptName: $scriptName, datetime_geq: $start, datetime_leq: $end }
            orderBy: [datetimeHour_ASC]
          ) {
            dimensions { datetimeHour status }
            sum { requests errors }
            quantiles { cpuTimeP50 cpuTimeP99 }
          }
        }
      }
    }`;

  const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.CF_ANALYTICS_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      query: gqlQuery,
      variables: {
        accountTag: CLOUDFLARE_ACCOUNT_ID,
        scriptName: "gw2-guild-api-dev",
        start: start.toISOString(),
        end: end.toISOString(),
      },
    }),
  });

  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    return json({ error: "Erreur requête métriques.", detail: detail.slice(0, 300) }, 502);
  }

  const data = await res.json();
  if (data.errors) return json({ error: "Erreur GraphQL.", detail: JSON.stringify(data.errors).slice(0, 300) }, 502);

  const rows = data.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];

  // Regroupe par heure (les statuts success/erreur arrivent en lignes séparées).
  const byHour = {};
  for (const row of rows) {
    const hour = row.dimensions.datetimeHour;
    byHour[hour] = byHour[hour] || { hour, requests: 0, errors: 0, cpuTimeP50: 0, cpuTimeP99: 0 };
    byHour[hour].requests += row.sum.requests;
    byHour[hour].errors += row.sum.errors;
    byHour[hour].cpuTimeP50 = Math.max(byHour[hour].cpuTimeP50, row.quantiles.cpuTimeP50 || 0);
    byHour[hour].cpuTimeP99 = Math.max(byHour[hour].cpuTimeP99, row.quantiles.cpuTimeP99 || 0);
  }

  return json({ hours: Object.values(byHour).sort((a, b) => a.hour.localeCompare(b.hour)) });
}

const ADMIN_USERS_PAGE_SIZE = 20;

async function handleAdminListUsers(request, env, url) {
  const admin = await requireAdmin(request, env);
  if (admin instanceof Response) return admin;

  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1", 10) || 1);
  const offset = (page - 1) * ADMIN_USERS_PAGE_SIZE;

  const [users, totalRow] = await Promise.all([
    env.DB.prepare("SELECT id, email, role, created_at FROM accounts ORDER BY created_at LIMIT ? OFFSET ?")
      .bind(ADMIN_USERS_PAGE_SIZE, offset).all(),
    env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first(),
  ]);

  return json({
    users: users.results,
    page,
    pageSize: ADMIN_USERS_PAGE_SIZE,
    total: totalRow.n,
    totalPages: Math.max(1, Math.ceil(totalRow.n / ADMIN_USERS_PAGE_SIZE)),
  });
}

async function handleAdminDeleteUser(request, env) {
  const admin = await requireAdmin(request, env);
  if (admin instanceof Response) return admin;

  const body = await request.json().catch(() => ({}));
  const targetId = body.id;
  if (!targetId) return json({ error: "Identifiant manquant." }, 400);
  if (targetId === admin.id) return json({ error: "Tu ne peux pas te supprimer toi-même." }, 400);

  const target = await env.DB.prepare("SELECT id, role FROM accounts WHERE id = ?").bind(targetId).first();
  if (!target) return json({ error: "Compte introuvable." }, 404);

  if (target.role === "admin") {
    const adminCount = await env.DB.prepare("SELECT COUNT(*) AS n FROM accounts WHERE role = 'admin'").first();
    if (adminCount.n <= 1) return json({ error: "Impossible de supprimer le dernier admin." }, 400);
  }

  const links = await env.DB.prepare("SELECT id FROM gw2_links WHERE account_id = ?").bind(targetId).all();
  for (const link of links.results) {
    await env.DB.prepare("DELETE FROM user_guilds WHERE gw2_link_id = ?").bind(link.id).run();
  }
  await env.DB.prepare("DELETE FROM gw2_links WHERE account_id = ?").bind(targetId).run();
  await env.DB.prepare("DELETE FROM sessions WHERE account_id = ?").bind(targetId).run();
  await env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(targetId).run();

  trackEvent(env, "admin_delete_user", "success");
  return json({ ok: true });
}

async function handleAdminResetPassword(request, env) {
  const admin = await requireAdmin(request, env);
  if (admin instanceof Response) return admin;

  const body = await request.json().catch(() => ({}));
  const targetId = body.id;
  const newPassword = body.new_password || "";
  if (!targetId) return json({ error: "Identifiant manquant." }, 400);
  if (newPassword.length < 10) return json({ error: "Le mot de passe doit faire au moins 10 caractères." }, 400);

  const target = await env.DB.prepare("SELECT id FROM accounts WHERE id = ?").bind(targetId).first();
  if (!target) return json({ error: "Compte introuvable." }, 404);

  const { hash, salt } = await hashPassword(newPassword);
  await env.DB.prepare("UPDATE accounts SET password_hash = ?, password_salt = ? WHERE id = ?")
    .bind(hash, salt, targetId).run();
  // Un mot de passe réinitialisé par un admin invalide les sessions existantes.
  await env.DB.prepare("DELETE FROM sessions WHERE account_id = ?").bind(targetId).run();

  trackEvent(env, "admin_reset_password", "success");
  return json({ ok: true });
}

// --- Sessions ---

async function startSession(env, accountId, email) {
  const token = randomToken(32);
  const expiresAt = new Date(Date.now() + SESSION_DURATION_SECONDS * 1000).toISOString();
  await env.DB.prepare("INSERT INTO sessions (token, account_id, expires_at) VALUES (?, ?, ?)")
    .bind(token, accountId, expiresAt)
    .run();
  return json({ id: accountId, email, token });
}

function bearerToken(request) {
  const header = request.headers.get("Authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7).trim() : null;
}

async function requireSession(request, env) {
  const token = bearerToken(request);
  if (!token) return json({ error: "Non authentifié." }, 401);

  const row = await env.DB.prepare(
    "SELECT accounts.id, accounts.email, accounts.role, accounts.mfa_enabled FROM sessions " +
    "JOIN accounts ON accounts.id = sessions.account_id " +
    "WHERE sessions.token = ? AND sessions.expires_at > datetime('now')"
  ).bind(token).first();

  if (!row) return json({ error: "Session expirée ou invalide." }, 401);
  return row;
}

async function requireAdmin(request, env) {
  const account = await requireSession(request, env);
  if (account instanceof Response) return account;
  if (account.role !== "admin") return json({ error: "Accès réservé aux administrateurs." }, 403);
  return account;
}

async function checkCooldown(env, key, cooldownMs) {
  const row = await env.DB.prepare("SELECT last_at FROM rate_limits WHERE key = ?").bind(key).first();
  const now = Date.now();
  if (row && now - new Date(row.last_at).getTime() < cooldownMs) {
    return json({ error: "Merci de patienter quelques secondes avant de réessayer." }, 429);
  }
  await env.DB.prepare(
    "INSERT INTO rate_limits (key, last_at) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET last_at = excluded.last_at"
  ).bind(key, new Date(now).toISOString()).run();
  return null;
}

// --- Mots de passe (PBKDF2-SHA256) ---

async function hashPassword(password, existingSaltB64) {
  const salt = existingSaltB64 ? b64ToBytes(existingSaltB64) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bytesToB64(new Uint8Array(bits)), salt: bytesToB64(salt) };
}

async function verifyPassword(password, saltB64, expectedHashB64) {
  const { hash } = await hashPassword(password, saltB64);
  return timingSafeEqual(hash, expectedHashB64);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// --- TOTP (RFC 6238), compatible Google Authenticator / Authy / etc. ---
// Pas de QR code (pas de dépendance externe pour l'encodeur) : le secret est
// affiché en base32 pour saisie manuelle, supportée par toutes ces applis.

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function generateTotpSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20)); // 160 bits, standard TOTP
  return base32Encode(bytes);
}

function base32Encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    out += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  return out;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/=+$/, "");
  let bits = "";
  for (const c of clean) {
    const val = BASE32_ALPHABET.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

async function totpAt(secretBase32, timeStep) {
  const keyBytes = base32Decode(secretBase32);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);

  const counter = new ArrayBuffer(8);
  const counterView = new DataView(counter);
  // JS numbers can't hold a full 64-bit int, mais largement suffisant ici
  // (timeStep ne dépassera pas 2^32 avant des milliards d'années).
  counterView.setUint32(4, timeStep, false);

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

// Tolère ±1 pas (30s) de dérive d'horloge, comme la plupart des implémentations.
async function verifyTotp(secretBase32, code) {
  if (!/^\d{6}$/.test(code || "")) return false;
  const currentStep = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (const delta of [0, -1, 1]) {
    if ((await totpAt(secretBase32, currentStep + delta)) === code) return true;
  }
  return false;
}

// --- Chiffrement des clés API GW2 (AES-256-GCM) ---

async function encryptSecret(env, plaintext) {
  const key = await getEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return bytesToB64(combined);
}

async function decryptSecret(env, storedB64) {
  const key = await getEncryptionKey(env);
  const combined = b64ToBytes(storedB64);
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(plaintext);
}

async function getEncryptionKey(env) {
  return crypto.subtle.importKey("raw", b64ToBytes(env.ENCRYPTION_KEY), "AES-GCM", false, ["encrypt", "decrypt"]);
}

// --- Utilitaires ---

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function randomToken(byteLength) {
  return bytesToB64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function bytesToB64(bytes) {
  let str = "";
  bytes.forEach((b) => (str += String.fromCharCode(b)));
  return btoa(str);
}

function bytesToB64Url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

// --- Analytics (Workers Analytics Engine, gratuit : 100k points/jour) ---

function trackEvent(env, eventType, outcome) {
  // Pas d'await : l'écriture est fire-and-forget, ne doit jamais ralentir
  // ni faire échouer une requête si le binding est absent ou en erreur.
  try {
    env.ANALYTICS?.writeDataPoint({
      indexes: [eventType],
      blobs: [outcome],
      doubles: [1],
    });
  } catch (err) {
    console.log(`analytics write failed: ${err}`);
  }
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}
