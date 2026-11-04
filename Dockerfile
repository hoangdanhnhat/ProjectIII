# DFIR/CA evidence collector - Docker lab images.
#
# One builder stage compiles and tests both binaries; two final targets are
# selected by compose.yaml (or manually):
#
#   docker build --target server .
#   docker build --target web .
#
# Lab only: containers run as root and are not hardened for production.

FROM golang:1.24 AS builder
WORKDIR /src
COPY . .
RUN go test ./... \
 && go build -o /out/dfir-server ./cmd/dfir-server \
 && go build -o /out/dfir-agent ./cmd/dfir-agent

# --- coordination server ----------------------------------------------------

# ca-certificates is required for the VirusTotal HTTPS lookups: the plain
# ubuntu image ships without a trust store, so every TLS connection fails
# with "x509: certificate signed by unknown authority".
FROM ubuntu:24.04 AS server
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/dfir-server /usr/local/bin/dfir-server
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dfir-server"]

# --- monitored web host: Apache2 + agent -------------------------------------

FROM ubuntu:24.04 AS web
RUN apt-get update \
 && apt-get install -y --no-install-recommends apache2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/dfir-agent /usr/local/bin/dfir-agent
COPY deploy/docker/entrypoint-web.sh /entrypoint-web.sh
RUN chmod 0755 /entrypoint-web.sh
ENTRYPOINT ["/entrypoint-web.sh"]
