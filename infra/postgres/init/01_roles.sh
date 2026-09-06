#!/bin/sh
# Creates least-privilege roles on first database initialisation only.
#
#   aegisnet_migrator — owns the schema and runs the Alembic migrations. It also receives
#                       CREATE on the database so a revision can install a *trusted*
#                       extension (citext, for users.email); trusted extensions need no
#                       superuser.
#   aegisnet_app      — the runtime role used by the API and worker. It receives table
#                       privileges from the migrations, never DDL rights, and holds
#                       INSERT/SELECT only on audit_log (THREAT_MODEL T-2.5, T-5.3).
#   aegisnet_retention — the only role in this deployment that may DELETE a row, and only from
#                       the four tables with a retention period. It cannot INSERT and cannot
#                       UPDATE anything, anywhere. It exists so that the runtime role does not
#                       need DELETE on audit_log to prune it: append-only is a property three
#                       decision records rest on, and a retention job is not a reason to give
#                       it up (ADR-033).
#
# This script does NOT create tables. The schema is created only by `alembic upgrade head`
# (`make migrate`), under the migrator role.
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
require_identifier AEGISNET_RETENTION_USER
require_secret AEGISNET_MIGRATOR_PASSWORD
require_secret AEGISNET_APP_PASSWORD
require_secret AEGISNET_RETENTION_PASSWORD

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
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${AEGISNET_RETENTION_USER}') THEN
    CREATE ROLE ${AEGISNET_RETENTION_USER} LOGIN PASSWORD '${AEGISNET_RETENTION_PASSWORD}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END
\$\$;

-- Nobody creates objects in public except the migrator.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ${AEGISNET_APP_USER}, ${AEGISNET_MIGRATOR_USER}, ${AEGISNET_RETENTION_USER};
GRANT CREATE ON SCHEMA public TO ${AEGISNET_MIGRATOR_USER};

GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ${AEGISNET_APP_USER}, ${AEGISNET_MIGRATOR_USER}, ${AEGISNET_RETENTION_USER};
-- Trusted extensions (citext) require CREATE on the database; the app role never gets it.
GRANT CREATE ON DATABASE ${POSTGRES_DB} TO ${AEGISNET_MIGRATOR_USER};

-- Deny the app role the ability to create databases or roles by construction (above),
-- and make it impossible for it to read the superuser's future objects implicitly.
ALTER DATABASE ${POSTGRES_DB} SET search_path TO public;
SQL

echo "[init] least-privilege roles ensured: ${AEGISNET_MIGRATOR_USER}, ${AEGISNET_APP_USER}, ${AEGISNET_RETENTION_USER}"
