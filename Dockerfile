FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Open-core (free) образ: FileVault recovery-escrow — enterprise-фича, здесь НЕ
# собирается (escrow RPC → Unimplemented, lock mode=filevault → 409, age не в графе).
# Enterprise-образ собирается ЭТИМ ЖЕ файлом — через build-args BUILD_TAGS/пины ниже.
# По умолчанию они пусты, поэтому обычная сборка остаётся open-core.
# VERSION — semver релиза (из файла VERSION); штампуется в бинарь для `routineops-server -version`.
# Пусто => "dev". compose передаёт build-arg из окружения: export VERSION=$(cat VERSION).
ARG VERSION=dev
# BUILD_TAGS/пины — enterprise-сборка ТЕМ ЖЕ Dockerfile. По умолчанию пусто => open-core,
# как и было: пустой -tags ничего не включает, а пустые пины дают Free-поведение
# (сервер без вшитого вендор-ключа отвергает ЛЮБУЮ лицензию, без recipient escrow
# выключен fail-closed).
#
# 🔴 Пины — ТОЛЬКО ldflags, никогда не env: публичный ключ, читаемый из окружения,
# покупатель подменит своим и выпишет себе лицензию сам (docs/licensing.md).
ARG BUILD_TAGS=
ARG LICENSE_VENDOR_PUBKEY=
ARG ESCROW_RECIPIENT_FPR=
RUN CGO_ENABLED=0 go build ${BUILD_TAGS:+-tags ${BUILD_TAGS}} \
      -ldflags="-s -w -X main.version=${VERSION} \
                -X main.licenseVendorPubKey=${LICENSE_VENDOR_PUBKEY} \
                -X main.escrowRecipientFpr=${ESCROW_RECIPIENT_FPR}" \
      -o routineops-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/routineops-server .
COPY migrations/ migrations/
EXPOSE 8081 50051
CMD ["./routineops-server"]