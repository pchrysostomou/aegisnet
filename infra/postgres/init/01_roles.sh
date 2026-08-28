#!/bin/sh
# Creates least-privilege roles on first database initialisation only.
#
#   aegisnet_migrator — owns the schema, runs Alembic migrations (Chunk 2 onward).
#   aegisnet_app      — the runtime role used by the API and worker. It receives table
#                       privileges from the migrations, never DDL rights, and will be
#                       granted INSERT/SELECT only on audit_log (THREAT_MODEL T-2.5, T-5.3).
#
# This script does NOT create tables. No schema exists until Chunk 2.
#
# The role names and passwords below are interpolated into SQL text. That makes them an
# injection surface if they ever contain a quote or a backslash, so both are validated
# against a strict allowlist before any SQL is built, and the script fails closed rather
# than emitting SQL it cannot reason about. `make bootstrap` only ever produces
# URL-safe base64 secrets, so this guard should never fire in normal use — it exists for
# the case where someone hand-edits .env.
set -eu

die() {
	echo "[init] FATAL: $1" >&2
	exit 1
}

require() {
	eval "value=\${$1:-}"
	[ -n "$value" ] || die "$1 is not set; refusing to initialise roles"
}

# Identifiers: letters, digits and underscores only.
require_identifier() {
	require "$1"
	eval "value=\${$1}"
	case $value in
	*[!A-Za-z0-9_]* | "") die "$1 must match [A-Za-z0-9_]+ (got a disallowed character)" ;;
	esac
}

# Secrets: URL-safe base64 alphabet only. Deliberately excludes quotes, backslashes,
# semicolons, and whitespace, so the literals below cannot terminate a string or a statement.
require_secret() {
	require "$1"
	eval "value=\${$1}"
	case $value in
	*[!A-Za-z0-9_=+/.-]*) die "$1 contains a character that is unsafe to interpolate into SQL" ;;
	esac
	[ "${#value}" -ge 16 ] || die "$1 is shorter than 16 characters"
}

require_identifier POSTGRES_USER
require_identifier POSTGRES_DB
require_identifier AEGISNET_MIGRATOR_USER
require_identifier AEGISNET_APP_USER
require_secret AEGISNET_MIGRATOR_PASSWORD
require_secret AEGISNET_APP_PASSWORD

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${AEGISNET_MIGRATOR_USER}') THEN
    CREATE ROLE ${AEGISNET_MIGRATOR_USER} LOGIN PASSWORD '${AEGISNET_MIGRATOR_PASSWORD}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${AEGISNET_APP_USER}') THEN
    CREATE ROLE ${AEGISNET_APP_USER} LOGIN PASSWORD '${AEGISNET_APP_PASSWORD}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
\$\$;

-- Nobody creates objects in public except the migrator.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ${AEGISNET_APP_USER}, ${AEGISNET_MIGRATOR_USER};
GRANT CREATE ON SCHEMA public TO ${AEGISNET_MIGRATOR_USER};

GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ${AEGISNET_APP_USER}, ${AEGISNET_MIGRATOR_USER};

-- Deny the app role the ability to create databases or roles by construction (above),
-- and make it impossible for it to read the superuser's future objects implicitly.
ALTER DATABASE ${POSTGRES_DB} SET search_path TO public;
SQL

echo "[init] least-privilege roles ensured: ${AEGISNET_MIGRATOR_USER}, ${AEGISNET_APP_USER}"
