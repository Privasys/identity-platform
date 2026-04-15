FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /idp ./cmd/idp/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite curl
COPY --from=builder /idp /usr/local/bin/idp

# /data is the encrypted volume mount point.
# On enclave-os-virtual this is a per-container LUKS2+AEAD volume.
# On plain Docker, bind-mount a host directory here.
RUN mkdir -p /data
VOLUME /data

EXPOSE 8091

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD curl -f http://127.0.0.1:8091/healthz || exit 1

ENTRYPOINT ["idp"]
