-- Comptes humains (email + mot de passe)
-- role : 'user' ou 'admin'. Nouveau compte D1 depuis zéro seulement — sur la
-- base existante, la colonne a été ajoutée une fois via un ALTER TABLE à part
-- (SQLite n'a pas d'ADD COLUMN IF NOT EXISTS, donc pas rejouable ici sans
-- casser l'application idempotente de ce fichier à chaque déploiement).
-- password_hash/password_salt restent NOT NULL même pour les comptes créés
-- via Google : un mot de passe aléatoire inutilisable est généré à la
-- création plutôt que d'assouplir la contrainte (évite une migration lourde
-- de colonne sur la table existante).
CREATE TABLE IF NOT EXISTS accounts (
  id                    TEXT PRIMARY KEY,
  email                 TEXT NOT NULL UNIQUE,
  password_hash         TEXT NOT NULL,
  password_salt         TEXT NOT NULL,
  role                  TEXT NOT NULL DEFAULT 'user',
  google_sub            TEXT,
  mfa_secret_encrypted  TEXT,
  mfa_enabled           INTEGER NOT NULL DEFAULT 0,
  created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_google_sub ON accounts(google_sub) WHERE google_sub IS NOT NULL;

-- Défis MFA temporaires : émis après un mot de passe correct sur un compte
-- avec MFA actif, avant la validation du code TOTP. Courte durée de vie.
CREATE TABLE IF NOT EXISTS mfa_challenges (
  token      TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  expires_at TEXT NOT NULL
);

-- Sessions actives (cookie httpOnly côté client, token opaque ici)
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);

-- Comptes GW2 liés à un compte (un compte peut lier plusieurs clés API)
-- id = GUID du compte GW2 (renvoyé par /v2/account), stable et unique
CREATE TABLE IF NOT EXISTS gw2_links (
  id                TEXT PRIMARY KEY,
  account_id        TEXT NOT NULL REFERENCES accounts(id),
  gw2_account_name  TEXT NOT NULL,
  api_key_encrypted TEXT NOT NULL,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_gw2_links_account ON gw2_links(account_id);

-- Appartenance aux guildes de chaque compte GW2 lié, pour le matching entre membres
CREATE TABLE IF NOT EXISTS user_guilds (
  gw2_link_id TEXT NOT NULL REFERENCES gw2_links(id),
  guild_id    TEXT NOT NULL,
  PRIMARY KEY (gw2_link_id, guild_id)
);
CREATE INDEX IF NOT EXISTS idx_user_guilds_guild ON user_guilds(guild_id);

-- Anti-abus : évite que l'app elle-même martèle l'API GW2 (cooldown par compte)
CREATE TABLE IF NOT EXISTS rate_limits (
  key     TEXT PRIMARY KEY,
  last_at TEXT NOT NULL
);

-- CSRF sur le flow OAuth Google (state à usage unique, courte durée de vie)
-- intent='login' (par défaut) : connexion/inscription classique, account_id
-- NULL. intent='link' : déclenché depuis "Mon compte" par un utilisateur déjà
-- authentifié qui veut lier son compte Google — account_id est fixé au
-- moment de la génération du state (donc côté serveur, jamais rejouable pour
-- un autre compte), avant même la redirection vers Google.
CREATE TABLE IF NOT EXISTS oauth_states (
  state      TEXT PRIMARY KEY,
  intent     TEXT NOT NULL DEFAULT 'login',
  account_id TEXT,
  expires_at TEXT NOT NULL
);

-- Code d'échange à usage unique après /auth/google/callback : évite de
-- mettre le token de session final dans l'URL de redirection (historique
-- navigateur, logs, header Referer). kind='login' -> session prête à
-- récupérer ; kind='link_pending' -> un compte existe déjà avec cet email,
-- google_sub/google_email restent côté serveur jusqu'à ce que le client
-- prouve qu'il possède ce compte (mot de passe) puis appelle
-- /account/google/link avec ce même code, jamais un google_sub fourni par
-- le client directement.
CREATE TABLE IF NOT EXISTS oauth_exchange_codes (
  code         TEXT PRIMARY KEY,
  kind         TEXT NOT NULL,
  account_id   TEXT,
  google_sub   TEXT,
  google_email TEXT,
  expires_at   TEXT NOT NULL
);
