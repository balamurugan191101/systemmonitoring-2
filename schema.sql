CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username varchar(64) NOT NULL UNIQUE,
  email varchar(254) NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('Super Admin','Admin','IT Engineer','Viewer')),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_normalized ON users (lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS users_username_normalized ON users (lower(username));
CREATE TABLE IF NOT EXISTS sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamp(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expire_idx ON sessions(expire);
CREATE TABLE IF NOT EXISTS monitored_computers (
  id text PRIMARY KEY,
  display_name text NOT NULL,
  monitoring_status text NOT NULL DEFAULT 'unknown',
  metadata jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO monitored_computers(id,display_name) VALUES ('local','Local monitored computer') ON CONFLICT (id) DO NOTHING;
CREATE TABLE IF NOT EXISTS user_computer_access (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  computer_id text NOT NULL REFERENCES monitored_computers(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id,computer_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id bigserial PRIMARY KEY,
  user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  action text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}',
  ip_address inet,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_created_at ON audit_logs(created_at DESC);
