#!/bin/sh
# DFIR lab - create .env with the operator and agent tokens when missing.
#
# HTTPS is deferred: the lab runs plain HTTP, so no certificates are created
# here. Run this directly or via `make lab-init`; re-running is safe and keeps
# existing tokens.
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
env_file="$root/../../.env"

umask 077
if [ -f "$env_file" ]; then
  echo ".env already exists - keeping existing tokens"
  exit 0
fi

operator="$(openssl rand -hex 32)"
agent="$(openssl rand -hex 32)"
while [ "$operator" = "$agent" ]; do
  agent="$(openssl rand -hex 32)"
done
printf 'DFIR_OPERATOR_TOKEN=%s\nDFIR_AGENT_TOKEN=%s\n' "$operator" "$agent" > "$env_file"
echo "wrote $env_file with fresh random tokens"
