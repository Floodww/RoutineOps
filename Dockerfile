FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Open-core (free) образ: FileVault recovery-escrow — enterprise-фича, здесь НЕ
# собирается (escrow RPC → Unimplemented, lock mode=filevault → 409, age не в графе).
# Enterprise-образ собирается ОТДЕЛЬНО: go build -tags enterprise + -X main.escrowRecipientFpr=<fpr>
# Здесь escrow-ldflags намеренно отсутствуют.
# VERSION — semver релиза (из файла VERSION); штампуется в бинарь для `routineops-server -version`.
# Пусто => "dev". compose передаёт build-arg из окружения: export VERSION=$(cat VERSION).
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o routineops-server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/routineops-server .
COPY migrations/ migrations/
EXPOSE 8081 50051
CMD ["./routineops-server"]