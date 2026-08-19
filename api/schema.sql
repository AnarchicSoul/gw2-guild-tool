-- Comptes humains (email + mot de passe)
CREATE TABLE IF NOT EXISTS accounts (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
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
