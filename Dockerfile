# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.24-alpine
ARG RUNTIME_IMAGE=alpine:3.21

FROM ${GO_IMAGE} AS build
ARG GOPROXY=https://proxy.golang.org,direct
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay

FROM ${RUNTIME_IMAGE}
RUN addgroup -S -g 10001 relay && adduser -S -D -H -u 10001 -G relay relay \
    && mkdir -p /data && chown relay:relay /data && chmod 0700 /data
COPY --from=build /out/relay /usr/local/bin/relay
USER relay:relay
# Container-side defaults; listen on all interfaces inside the container.
ENV RELAY_LISTEN_ADDR=0.0.0.0:8080 \
    RELAY_DASHBOARD_ADDR=0.0.0.0:8081 \
    RELAY_STATS_DB=/data/relay-stats.db
VOLUME ["/data"]
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/relay"]
