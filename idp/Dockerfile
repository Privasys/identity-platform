FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /idp ./cmd/idp/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite
COPY --from=builder /idp /usr/local/bin/idp

# Default data directory.
RUN mkdir -p /var/lib/privasys
VOLUME /var/lib/privasys

EXPOSE 8091
ENTRYPOINT ["idp"]
