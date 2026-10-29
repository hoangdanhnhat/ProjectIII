#!/bin/sh
# NOTE: HTTPS is deferred. The lab runs plain HTTP and uses gen-env.sh for
# tokens, so this script is NOT run by the lab. It is kept for the later TLS
# phase (it also writes .env when missing).
#
# DFIR lab - one-time bootstrap for the Docker lab.
#
# Creates (idempotently, never overwrites):
#   deploy/docker/certs/ca.pem, ca.key      self-signed lab CA
#   deploy/docker/certs/server.pem, .key    server cert with SANs
#                                           DNS:dfir-server, DNS:localhost, IP:127.0.0.1
#   .env                                    DFIR_OPERATOR_TOKEN / DFIR_AGENT_TOKEN
#
# All of it is gitignored. The CA and certificate are for this lab only -
# never reuse them in any other environment.
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
certs="$root/certs"
env_file="$root/../../.env"

umask 077
mkdir -p "$certs" "$root/../../data"

if [ ! -f "$env_file" ]; then
  operator="$(openssl rand -hex 32)"
  agent="$(openssl rand -hex 32)"
  while [ "$operator" = "$agent" ]; do
    agent="$(openssl rand -hex 32)"
  done
  printf 'DFIR_OPERATOR_TOKEN=%s\nDFIR_AGENT_TOKEN=%s\n' "$operator" "$agent" > "$env_file"
  echo "wrote $env_file with fresh random tokens"
else
  echo ".env already exists - keeping existing tokens"
fi

if [ ! -f "$certs/ca.pem" ] || [ ! -f "$certs/ca.key" ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
    -subj '/CN=DFIR Lab CA' \
    -keyout "$certs/ca.key" -out "$certs/ca.pem"
  echo "created lab CA: $certs/ca.pem"
else
  echo "lab CA already exists - keeping it"
fi

if [ ! -f "$certs/server.pem" ] || [ ! -f "$certs/server.key" ]; then
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  openssl req -newkey rsa:3072 -nodes \
    -subj '/CN=dfir-server' \
    -keyout "$certs/server.key" -out "$work/server.csr"
  printf 'subjectAltName=DNS:dfir-server,DNS:localhost,IP:127.0.0.1\n' > "$work/san.ext"
  openssl x509 -req -in "$work/server.csr" \
    -CA "$certs/ca.pem" -CAkey "$certs/ca.key" -CAcreateserial \
    -days 825 -extfile "$work/san.ext" -out "$certs/server.pem"
  echo "created server certificate: $certs/server.pem (SANs: dfir-server, localhost, 127.0.0.1)"
else
  echo "server certificate already exists - keeping it"
fi

chmod 0600 "$certs/ca.key" "$certs/server.key"
echo "done. Next: make lab-up   (or: docker compose up -d --build)"
