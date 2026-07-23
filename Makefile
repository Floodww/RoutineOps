SHELL := /bin/bash
MODULE := github.com/Floodww/RoutineOps
VERSION ?= $(shell cat VERSION 2>/dev/null || echo 0.0.0)
LDFLAGS := -X main.version=$(VERSION)

# Числовая PE-версия для VERSIONINFO Windows-exe из VERSION (semver x.y.z); если
# VERSION не semver (напр. git-hash в dev-сборке) → 0.0.0. WI сравнивает именно
# FixedFileInfo: versioned-файл перезаписывает unversioned/старее при апгрейде MSI.
WINVER := $(shell echo "$(VERSION)" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' || echo 0.0.0)
WV_MAJ := $(word 1,$(subst ., ,$(WINVER)))
WV_MIN := $(word 2,$(subst ., ,$(WINVER)))
WV_PAT := $(word 3,$(subst ., ,$(WINVER)))
GOVERSIONINFO := go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0

.DEFAULT_GOAL := help

# Пусто = УНИВЕРСАЛЬНЫЙ агент: release-ключ приезжает в ответе на enroll (модель
# универсального MSI/PKG). Вшить ключ конкретного деплоя можно только явно:
#   RELEASE_PUBKEY=<base64> make build-win
#
# Раньше здесь стоял боевой ключ мейнтейнера, и `make build-win` + `make msi-exe`
# (msi-exe лишь копирует exe, не пересобирая) вшивали его в публичный MSI. У чужого
# деплоя такой агент молча терял self-update: вшитый ключ АВТОРИТЕТЕН и не обходится
# ключом из enroll (SEC-2), а `version`/`diag` при этом рапортовали «self-update
# включено». build/pkg/build-pkg.sh и release-darwin ключ и так не передают — Makefile
# теперь с ними согласован, а build/msi/README.md («по умолчанию переменная пуста»)
# наконец не врёт.
RELEASE_PUBKEY ?=
RELEASE_KEY    ?= $(HOME)/release_ed25519.pem

# FileVault recovery-escrow — ENTERPRISE-фича (carve-out). Open-core агент её НЕ
# собирает (символов main.escrowRecipient/_Fpr нет; escrow не шлётся, age не в графе).
# Enterprise-сборка агента:
#   make build-mac AGENT_TAGS=enterprise ESCROW_RECIPIENT=age1... ESCROW_RECIPIENT_FPR=<fpr>
# ESCROW_RECIPIENT_FPR получить enterprise-бинарём сервера: `routineops-server -escrow-fpr age1...`.
AGENT_TAGS           ?=
ESCROW_RECIPIENT     ?=
ESCROW_RECIPIENT_FPR ?=
# escrow-ldflags добавляются ТОЛЬКО в enterprise-сборке (иначе таргетят несуществующие
# символы). TAGSFLAG подставляет -tags, когда AGENT_TAGS задан.
ifeq ($(AGENT_TAGS),enterprise)
ESCROW_LDFLAGS := -X main.escrowRecipient=$(ESCROW_RECIPIENT) -X main.escrowRecipientFpr=$(ESCROW_RECIPIENT_FPR)
else
ESCROW_LDFLAGS :=
endif
TAGSFLAG := $(if $(AGENT_TAGS),-tags $(AGENT_TAGS),)

# Guard: ESCROW_* без AGENT_TAGS=enterprise = молчаливая потеря пиннинга (символов
# в free-агенте нет, -X по несуществующему символу линкер игнорирует) → жёсткая
# ошибка в агентских таргетах (не глобально, чтобы env с ESCROW_* не ломал make up/logs).
check-escrow-tags:
	@if [ "$(AGENT_TAGS)" != "enterprise" ] && [ -n "$(ESCROW_RECIPIENT)$(ESCROW_RECIPIENT_FPR)" ]; then \
		echo "ОШИБКА: ESCROW_RECIPIENT/_FPR заданы без AGENT_TAGS=enterprise — escrow молча не попадёт в free-агент." >&2; \
		exit 1; \
	fi

.PHONY: help proto tidy fmt agent mockserver build certs up down logs run-mock run-agent test clean \
        pkg-linux pkg-deb pkg-rpm pkg-deb-arm64 pkg-rpm-arm64 \
        build-win build-mac build-linux build-linux-arm64 build-all lint publish-release syso-win check-escrow-tags

help: ## Список целей
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2}'

fmt: ## Отформатировать весь Go-код (gofmt). Прогоняйте перед пушем — это гейт CI.
	gofmt -w .

proto: ## Перегенерировать Go-код из proto (ОБЩИЙ файл — менять согласованно, ADR-4)
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       proto/agent.proto

tidy: ## Привести go.mod/go.sum в порядок (добавит pgx и пр.)
	go mod tidy

agent: ## Собрать агент -> bin/agent
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/agent ./cmd/agent

mockserver: ## Собрать mock-сервер -> bin/mockserver
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/mockserver ./cmd/mockserver

cli: ## Собрать CLI конфигурации парка -> bin/routineops (см. docs/config-as-code.md)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/routineops ./cmd/routineops

build: agent mockserver ## Собрать оба бинарника

certs: ## Сгенерировать dev-сертификаты. Агентский — задать DEVICE_ID=<uuid>
	./scripts/gen-certs.sh $(DEVICE_ID)

up: ## Поднять PostgreSQL + Redis
	docker compose up -d

down: ## Остановить окружение (данные сохраняются; -v для сброса схемы)
	docker compose down

logs: ## Логи окружения
	docker compose logs -f

run-mock: ## Запустить mock-сервер (нужны certs/server.* + certs/ca.crt и поднятый Postgres)
	go run ./cmd/mockserver

run-agent: ## Запустить агент. Требует DEVICE_ID=<uuid> (тот же, что в certs)
	@test -n "$(DEVICE_ID)" || { echo "укажи DEVICE_ID=<uuid>"; exit 1; }
	ROUTINEOPS_AGENT_CERT=certs/agents/$(DEVICE_ID)/agent.crt \
	ROUTINEOPS_AGENT_KEY=certs/agents/$(DEVICE_ID)/agent.key \
	ROUTINEOPS_CA_CERT=certs/agents/$(DEVICE_ID)/ca.crt \
	go run ./cmd/agent

test: ## Прогнать тесты
	go test ./...

syso-win: ## Сгенерировать cmd/agent/rsrc_windows_amd64.syso: манифест + PE-VERSIONINFO из VERSION
	# Манифест (UAC/longpath) И числовая PE-версия в одном .syso (два .syso не
	# линкуются: "too many .rsrc sections"). FixedFileInfo=$(WINVER).0 — по нему WI
	# решает перезапись файла при апгрейде MSI (versioned > unversioned/старее),
	# иначе старый exe не заменялся в поле (баг апгрейда v23→v25).
	$(GOVERSIONINFO) -64 -arm=false -o cmd/agent/rsrc_windows_amd64.syso \
		-manifest cmd/agent/agent.manifest \
		-ver-major $(WV_MAJ) -ver-minor $(WV_MIN) -ver-patch $(WV_PAT) -ver-build 0 \
		-product-ver-major $(WV_MAJ) -product-ver-minor $(WV_MIN) -product-ver-patch $(WV_PAT) -product-ver-build 0 \
		-file-version "$(WINVER).0" -product-version "$(WINVER)" \
		-company RoutineOps -product-name "RoutineOps Agent" -description "RoutineOps Agent" \
		-internal-name RoutineOps-agent -original-name RoutineOps-agent.exe \
		cmd/agent/versioninfo.json

build-win: syso-win check-escrow-tags ## Кросс-компиляция агента для Windows amd64 (манифест + VERSIONINFO из syso-win)
	# -H windowsgui: GUI-subsystem, чтобы трей в юзер-сессии не открывал консольное
	# окно (его закрытие убивало агент). CLI-ветки re-attach'атся к консоли родителя
	# через attachParentConsole (см. cmd/agent/console_windows.go).
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
		$(TAGSFLAG) -ldflags "$(LDFLAGS) -X main.releasePubKey=$(RELEASE_PUBKEY) $(ESCROW_LDFLAGS) -H windowsgui" \
		-o bin/agent_windows_amd64.exe ./cmd/agent

build-mac: check-escrow-tags ## Кросс-компиляция агента для macOS arm64 (CGO=0: без Cocoa-замка и keychain)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
		$(TAGSFLAG) -ldflags "$(LDFLAGS) -X main.releasePubKey=$(RELEASE_PUBKEY) $(ESCROW_LDFLAGS)" \
		-o bin/agent_darwin_arm64 ./cmd/agent

build-mac-native: check-escrow-tags ## Нативная сборка для macOS с CGO (Cocoa-замок блокировки + настоящий keychain). Запускать НА маке.
	CGO_ENABLED=1 GOOS=darwin go build -trimpath \
		$(TAGSFLAG) -ldflags "$(LDFLAGS) -X main.releasePubKey=$(RELEASE_PUBKEY) $(ESCROW_LDFLAGS)" \
		-o bin/agent_darwin_native ./cmd/agent

build-linux: check-escrow-tags ## Кросс-компиляция агента для Linux amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
		$(TAGSFLAG) -ldflags "$(LDFLAGS) -X main.releasePubKey=$(RELEASE_PUBKEY) $(ESCROW_LDFLAGS)" \
		-o bin/agent_linux_amd64 ./cmd/agent

build-linux-arm64: check-escrow-tags ## Кросс-компиляция агента для Linux arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
		$(TAGSFLAG) -ldflags "$(LDFLAGS) -X main.releasePubKey=$(RELEASE_PUBKEY) $(ESCROW_LDFLAGS)" \
		-o bin/agent_linux_arm64 ./cmd/agent

build-all: build build-win build-mac build-linux build-linux-arm64 ## Собрать всё (сервер + агент 3 платформы)

# ── Linux-пакеты (.deb/.rpm) через nfpm ──
# Один nfpm.yaml на оба формата; арх/версия/бинарь передаются через окружение.
# Юнит systemd в пакет НЕ кладём — его генерит `enroll -install-service` (см.
# build/nfpm/nfpm.yaml). NFPM берётся из PATH или ~/go/bin.
NFPM ?= $(shell command -v nfpm 2>/dev/null || echo $(HOME)/go/bin/nfpm)

# pkg-linux собирает .deb и .rpm под amd64 и arm64 (4 артефакта в bin/).
pkg-linux: pkg-deb pkg-rpm pkg-deb-arm64 pkg-rpm-arm64 ## Собрать .deb+.rpm (amd64+arm64)

# nfpmPackage <arch> <bin> <format>: staging бинаря + сборка. Каталог staging и
# сгенерированный конфиг УНИКАЛЬНЫ per (arch,format) — иначе под `make -j`
# arm64-cp перетёр бы amd64-payload между cp и nfpm (amd64-пакет с arm64-ELF).
# src подставляется через sed (nfpm не разворачивает ${env} в glob src); пути
# scripts/src — repo-relative, nfpm резолвит их от CWD (корень репо).
define nfpmPackage
	rm -rf build/nfpm/stage-$(1)-$(3)
	mkdir -p build/nfpm/stage-$(1)-$(3)
	cp $(2) build/nfpm/stage-$(1)-$(3)/RoutineOps-agent
	sed 's#__SRC__#build/nfpm/stage-$(1)-$(3)/RoutineOps-agent#' build/nfpm/nfpm.yaml \
		> build/nfpm/stage-$(1)-$(3)/nfpm.yaml
	PKG_ARCH=$(1) PKG_VERSION=$(VERSION) $(NFPM) package -f build/nfpm/stage-$(1)-$(3)/nfpm.yaml -p $(3) -t bin/
endef

pkg-deb: build-linux ## .deb amd64
	$(call nfpmPackage,amd64,bin/agent_linux_amd64,deb)

pkg-rpm: build-linux ## .rpm amd64
	$(call nfpmPackage,amd64,bin/agent_linux_amd64,rpm)

pkg-deb-arm64: build-linux-arm64 ## .deb arm64
	$(call nfpmPackage,arm64,bin/agent_linux_arm64,deb)

pkg-rpm-arm64: build-linux-arm64 ## .rpm arm64
	$(call nfpmPackage,arm64,bin/agent_linux_arm64,rpm)

msi-exe: build-win ## Подготовить exe для сборки MSI: bin -> build/msi/mdm-agent.exe
	cp bin/agent_windows_amd64.exe build/msi/mdm-agent.exe
	@echo "Готово. Сборку MSI запускайте НА WINDOWS (WiX):"
	@echo "  pwsh build/msi/build-msi.ps1 -Version <x.y.z.b> [-PfxPath cert.pfx -PfxPassword ...]"

lint: ## Запустить golangci-lint
	golangci-lint run ./...

publish-release: ## Опубликовать релиз: make publish-release BINARY=./bin/agent_darwin_arm64 OS=darwin ARCH=arm64 VERSION=v1.0.0
	@test -n "$(BINARY)"  || { echo "укажи BINARY=<путь>"; exit 1; }
	@test -n "$(OS)"      || { echo "укажи OS=<darwin|linux|windows>"; exit 1; }
	@test -n "$(ARCH)"    || { echo "укажи ARCH=<amd64|arm64>"; exit 1; }
	@test -n "$(VERSION)" || { echo "укажи VERSION=<semver>"; exit 1; }
	go run ./cmd/publish-release \
		-binary $(BINARY) -version $(VERSION) -os $(OS) -arch $(ARCH) \
		-key $(RELEASE_KEY)

clean: ## Удалить собранные бинарники
	rm -rf bin

pkg-mac: build-mac ## Создать .pkg установщик для macOS (архитектура arm64)
	# build-pkg.sh пересобирает бинарь САМ (не переиспользует bin/agent_darwin_arm64
	# от build-mac) — AGENT_TAGS + ESCROW_RECIPIENT/_FPR обязаны быть проброшены в его
	# окружение, иначе enterprise .pkg молча соберётся free-агентом без escrow.
	cd build/pkg && AGENT_TAGS="$(AGENT_TAGS)" ESCROW_RECIPIENT="$(ESCROW_RECIPIENT)" ESCROW_RECIPIENT_FPR="$(ESCROW_RECIPIENT_FPR)" ./build-pkg.sh $(VERSION) arm64

pkg-mac-native: build-mac-native ## Создать .pkg установщик для macOS (нативная сборка)
	cd build/pkg && AGENT_TAGS="$(AGENT_TAGS)" ESCROW_RECIPIENT="$(ESCROW_RECIPIENT)" ESCROW_RECIPIENT_FPR="$(ESCROW_RECIPIENT_FPR)" ./build-pkg.sh $(VERSION) native

release-darwin: pkg-mac-native ## [МЕЙНТЕЙНЕР, НА МАКЕ] Собрать macOS-релиз и обновить артефакты в git
	# Linux-прод не может собрать macOS-агента: cgo нужен для Cocoa-замка (lockui_darwin.go)
	# и Keychain (keystore/provider_darwin.go); `CGO_ENABLED=0 GOOS=darwin` молча подставляет
	# заглушки по тегам `!darwin || !cgo`. Поэтому релиз рождается здесь и едет в git.
	# RELEASE_PUBKEY НЕ передаём: артефакты обязаны быть универсальными (ключ — из enroll).
	@echo ""
	@echo "Проверь и закоммить:"
	@git status --short build/pkg/RoutineOps-agent.pkg build/darwin/ || true
