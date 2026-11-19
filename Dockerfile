# --- front-end bundle (React console) ---------------------------------------

FROM node:22-alpine AS console
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# --- Volatility wrapper ------------------------------------------------------
# Built from the pinned upstream commit; the repository is not vendored here
# because it carries no license file. The binary is the only artifact copied
# into the runtime image.

FROM golang:1.24 AS volwrapper
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/BeanBagKing/VolGolangWrapper.git /w \
 && cd /w \
 && git checkout 0fbc6d8de9c859e5270bde2bfb5ee15cfe82497a \
 && CGO_ENABLED=0 go build -trimpath -o /out/vol-wrapper .

# --- Go binaries --------------------------------------------------------------
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
# Vite builds straight into internal/webui/dist (see web/vite.config.ts).
COPY --from=console /internal/webui/dist ./internal/webui/dist
RUN go test ./... \
 && go build -o /out/dfir-server ./cmd/dfir-server \
 && go build -o /out/dfir-agent ./cmd/dfir-agent

# --- coordination server ----------------------------------------------------

# ca-certificates is required for the VirusTotal HTTPS lookups: the plain
# ubuntu image ships without a trust store, so every TLS connection fails
# with "x509: certificate signed by unknown authority".
# Python + Volatility 3 (the stable 2.28.2 release) power memory analysis;
# util-linux provides taskset for limiting the wrapper's parallelism.
FROM ubuntu:24.04 AS server
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-venv util-linux \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/volatility \
 && /opt/volatility/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/volatility/bin/pip install --no-cache-dir volatility3==2.28.2
COPY --from=builder /out/dfir-server /usr/local/bin/dfir-server
COPY --from=volwrapper /out/vol-wrapper /usr/local/bin/vol-wrapper
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
