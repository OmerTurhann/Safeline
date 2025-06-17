# 1. Aşama: Caddy'yi Coraza modülüyle derliyoruz
FROM golang:1.24 AS builder

# Caddy'nin özel yapısını derleyecek aracı indiriyoruz
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /build

# Caddy + Coraza modülü derleniyor
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2@latest

# 2. Aşama: Temiz Caddy imajı üzerine derlenmiş binary'yi kopyalıyoruz
FROM caddy:2.7.4

# Derlenmiş özel Caddy binary'sini yerleştiriyoruz
COPY --from=builder /build/caddy /usr/bin/caddy
