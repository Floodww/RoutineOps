SHELL := /bin/bash
MODULE := github.com/Floodww/RoutineOps
# VERSION здесь = ВЕРСИЯ АГЕНТА (файл AGENT_VERSION). Makefile собирает только агента и
# его пакеты (agent/msi/deb/rpm/pkg/publish-release); сервер+веб версионируются отдельно
# (файл VERSION в корне, читается Dockerfile). Имя переменной оставлено VERSION, чтобы
# `make <target> VERSION=<semver>` по-прежнему переопределял версию агента.
VERSION ?= $(shell cat AGENT_VERSION 2>/dev/null || echo 0.0.0)
LDFLAGS := -X main.version=$(VERSION)

# Числовая PE-версия для VERSIONINFO Windows-exe из VERSION (semver x.y.z); если
# VERSION не semver (напр. git-hash в dev-сборке) → 0.0.0. WI сравнивает именно
# FixedFileInfo: versioned-файл перезаписывает unversioned/старее при апгрейде MSI.
WINVER := $(shell echo "$(VERSION)" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' || echo 0.0.0)
WV_MAJ := $(word 1,$(subst ., ,$(WINVER)))
WV_MIN := $(word 2,$(subst ., ,$(WINVER)))
WV_PAT := $(word 3,$(subst ., ,$(WINVER)))
GOVERSIONINFO := go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.7.0

# Версия protoc, которой сгенерирован лежащий в репозитории контракт. Гейт в цели
# `proto` не даст перегенерировать другой версией: иначе строка версии в шапке
# скачет между машинами и даёт конфликт на пустом месте.
# Плагины пинятся отдельно: protoc-gen-go v1.36.11, protoc-gen-go-grpc v1.6.2.
#
# ВНИМАНИЕ, две РАЗНЫЕ строки версии одного и того же компилятора:
#   protoc --version      → "libprotoc 35.0"   ← с этим сравнивает гейт
#   шапка proto/agent.pb.go → "protoc v7.35.0" ← это пишет protoc-gen-go
# protoc-gen-go подставляет мажор из внутреннего представления (7.x), а CLI
# печатает номер релиза (35.0). Гейт обязан сравнивать с CLI-формой — иначе он
# падает на той самой машине, которой контракт и сгенерирован.
PROTOC_VERSION := 35.0

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
	@if [ "$(AGENT_TAGS)" = "enterprise" ] && { [ -z "$(ESCROW_RECIPIENT)" ] || [ -z "$(ESCROW_RECIPIENT_FPR)" ]; }; then \
		echo "ОШИБКА: AGENT_TAGS=enterprise, но ESCROW_RECIPIENT/_FPR пусты." >&2; \
		echo "-X по пустой строке линкер отработает МОЛЧА, и enterprise-агент уедет с выключенным FileVault-escrow." >&2; \
		echo "Задай оба: ESCROW_RECIPIENT=age1... ESCROW_RECIPIENT_FPR=<fpr>." >&2; \
		exit 1; \
	fi

# Guard: удалённый стол — enterprise-фича (роадмап, Этап 2), и доказывать это чтением
# build-тегов нельзя. Проверяются ОБА направления на реальных бинарях: во free-агенте
# кодов сеанса нет ни одного, в enterprise они есть.
#
# Почему по бинарю, а не по `go list -deps`: гард check-oss-no-enterprise.sh строит граф
# по ИСХОДНИКАМ и на enterprise-БИНАРЬ в build/ радостно печатает «open-core чист» — эта
# дыра уже описана в scripts/export-free.sh для escrow. Здесь она закрыта тем же способом.
#
# Токен — путь пакета: Go кладёт его в таблицы имён, поэтому он есть в бинаре тогда и
# только тогда, когда пакет реально слинкован. Коды причин (SCOPE_VIOLATION и прочие) на
# эту роль не годятся, и это выяснилось прогоном: линкер выбрасывает недостижимые строковые
# константы, а платформенные ветки на чужой ОС просто не компилируются — гейт был бы
# красным на исправном дереве. Путь пакета проверен на всех трёх ОС в обе стороны.
# Пакетов теперь два: захват (internal/agent/screen) и формат кадра
# (internal/screenframe, общий с сервером). Второй проверяется той же меркой не для
# симметрии: он появился отдельным пакетом ИМЕННО чтобы сервер не тащил платформенный
# захват, и ровно поэтому его легче всего случайно затянуть во free-граф.
#
# LC_ALL=C у greps по бинарям — не гигиена. В UTF-8-локали grep разбирает вход как текст
# и строку с невалидной последовательностью байт молча не сопоставляет; в бинаре таких
# последовательностей полно, и находка токена зависела бы от того, куда легли байты 0x0a.
# Опасная сторона здесь — «во free-бинаре токена нет»: гейт напечатал бы «free чист».
#
# Третьим шагом той же меркой меряется ТРЕКНУТЫЙ darwin-prebuilt. Проверки выше говорят
# только про свежесобранные бинари, а в поле и в публичный Free-срез уезжает файл из
# build/darwin — и он обязан быть open-core. Здесь он проверяется потому, что это дёшево
# (голый grep, никаких инструментов) и потому попадает в pre-push. MSI и PKG той же
# проверкой накрыты в scripts/check-installer-versions.sh: их надо распаковывать
# (msitools/bsdtar), в pre-push такой зависимости не место.
REMOTE_TOKEN := internal/agent/screen
FRAME_TOKEN  := internal/screenframe
check-remote-tags: ## Гейт §9.17: удалённого стола нет во free-сборке и есть в enterprise
	@fail=0; \
	for pkg in 'agent/screen' 'internal/screenframe'; do \
		if go list -deps ./cmd/agent 2>/dev/null | grep -q "$$pkg\$$"; then \
			echo "ОШИБКА: пакет $$pkg в графе FREE-сборки — удалённый стол утёк в open-core." >&2; \
			fail=1; \
		fi; \
		if ! go list -deps -tags enterprise ./cmd/agent 2>/dev/null | grep -q "$$pkg\$$"; then \
			echo "ОШИБКА: пакета $$pkg НЕТ в графе enterprise-сборки — фича отвалилась," >&2; \
			echo "  либо гейт проверяет не то. Зелёный гейт без этой проверки бесполезен." >&2; \
			fail=1; \
		fi; \
	done; \
	tmp=$$(mktemp -d); \
	CGO_ENABLED=0 go build -o "$$tmp/free" ./cmd/agent/ >/dev/null 2>&1 || { echo "ОШИБКА: free-сборка не собралась" >&2; fail=1; }; \
	CGO_ENABLED=0 go build -tags enterprise -o "$$tmp/ent" ./cmd/agent/ >/dev/null 2>&1 || { echo "ОШИБКА: enterprise-сборка не собралась" >&2; fail=1; }; \
	for tok in "$(REMOTE_TOKEN)" "$(FRAME_TOKEN)"; do \
		if [ -f "$$tmp/free" ] && LC_ALL=C grep -qa "$$tok" "$$tmp/free"; then \
			echo "ОШИБКА: $$tok найден во FREE-БИНАРЕ." >&2; fail=1; \
		fi; \
		if [ -f "$$tmp/ent" ] && ! LC_ALL=C grep -qa "$$tok" "$$tmp/ent"; then \
			echo "ОШИБКА: $$tok отсутствует в ENTERPRISE-БИНАРЕ — проверка по бинарю бесполезна." >&2; fail=1; \
		fi; \
	done; \
	rm -rf "$$tmp"; \
	if [ -f build/darwin/agent_darwin_arm64 ]; then \
		sh scripts/agent-edition-guard.sh "" build/darwin/agent_darwin_arm64 "трекнутый darwin-prebuilt" || fail=1; \
	else \
		echo "ОШИБКА: нет build/darwin/agent_darwin_arm64 — трекнутый prebuilt пропал из дерева." >&2; fail=1; \
	fi; \
	[ "$$fail" -eq 0 ] || exit 1; \
	echo "check-remote-tags: free чист (граф и бинарь), enterprise содержит фичу ✅"

# Гейт: enterprise-агент СОБИРАЕТСЯ под все три ОС.
#
# Заведён по факту, а не на всякий случай. `internal/agent/screen` объявлял тип `rect`,
# и такой же тип (структура RECT из Win32) объявлял соседний capture_windows.go — пакет
# не компилировался под GOOS=windows ВООБЩЕ, то есть enterprise-агент нельзя было собрать
# для платформы, которую владелец назвал первой по приоритету. Не заметили этого ровно
# потому, что все существующие проверки собирают агента под ХОЗЯЙСКУЮ ОС: check-remote-tags
# и тесты идут на linux, публикуемый windows-бинарь — free (там пакета screen нет вовсе).
#
# Отсюда правило: платформенный код проверяется КРОСС-КОМПИЛЯЦИЕЙ, а не тем, что «у меня
# собралось». darwin проверяется в обеих ипостасях: CGO=0 — то, что уезжает
# кросс-компиляцией, CGO=1 — нативная сборка с Cocoa (плашка наблюдения и замок).
check-agent-platforms: ## Гейт: enterprise-агент компилируется под windows/linux/darwin
	@fail=0; \
	for os in windows linux darwin; do \
		if ! GOOS=$$os CGO_ENABLED=0 go build -tags enterprise -o /dev/null ./cmd/agent 2>/tmp/agent-build-$$os.log; then \
			echo "ОШИБКА: enterprise-агент не собирается под GOOS=$$os:" >&2; \
			head -20 /tmp/agent-build-$$os.log >&2; \
			fail=1; \
		fi; \
	done; \
	if [ "$$(go env GOOS)" = "darwin" ]; then \
		if ! CGO_ENABLED=1 go build -tags enterprise -o /dev/null ./cmd/agent 2>/tmp/agent-build-darwin-cgo.log; then \
			echo "ОШИБКА: нативная (CGO) enterprise-сборка macOS не собирается:" >&2; \
			grep -v 'duplicate libraries' /tmp/agent-build-darwin-cgo.log | head -20 >&2; \
			fail=1; \
		fi; \
	else \
		echo "check-agent-platforms: нативная CGO-сборка macOS пропущена (не на маке)"; \
	fi; \
	[ "$$fail" -eq 0 ] || exit 1; \
	echo "check-agent-platforms: enterprise-агент собирается под все три ОС ✅"

.PHONY: help proto tidy fmt scan-free hooks agent mockserver build certs up down logs run-mock run-agent test clean \
        pkg-linux pkg-deb pkg-rpm pkg-deb-arm64 pkg-rpm-arm64 \
        build-win build-win-arm64 build-mac build-linux build-linux-arm64 build-all lint publish-release syso-win \
        check-escrow-tags check-remote-tags

help: ## Список целей
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-17s\033[0m %s\n", $$1, $$2}'

scan-free: ## Проверить Free-срез на утечки — гейт ПЕРЕД пушем (секунды, без тулчейна)
	@# Почему цель, а не «просто запусти скрипт»: на macOS скрипт запускаться ОТКАЗЫВАЕТСЯ
	@# (нужен bash 4+ и GNU sed), то есть половина команды выполнить рекомендацию не может
	@# в принципе. Здесь этот случай уводится в контейнер, и гейт становится одинаковым
	@# для всех. В CI суперсета он же есть шагом, но Actions там лежат на биллинге —
	@# сегодня работает только локальный прогон.
	@if [ -n "$${BASH_VERSINFO:-}" ] && [ "$$(bash -c 'echo $${BASH_VERSINFO[0]}')" -ge 4 ]; then \
		bash scripts/export-free.sh --scan-only; \
	else \
		echo "== bash 3.x/BSD userland — ухожу в docker (golang:1.26) =="; \
		docker run --rm -v "$$PWD":/src -w /src golang:1.26 \
			bash -c 'git config --global --add safe.directory /src && bash scripts/export-free.sh --scan-only'; \
	fi

fmt: ## Отформатировать весь Go-код (gofmt). Прогоняйте перед пушем — это гейт CI.
	gofmt -w .

hooks: ## Включить гейты репозитория: pre-commit (быстрое) + pre-push (тесты и линтеры)
	@# core.hooksPath, а НЕ копия в .git/hooks: копия протухает молча — правку хука
	@# получают только те, кто вспомнит переустановить. Здесь хук версионируется
	@# вместе с кодом.
	@git config core.hooksPath scripts/hooks
	@chmod +x scripts/hooks/pre-commit scripts/hooks/pre-push
	@echo "Хуки включены (core.hooksPath=scripts/hooks)."
	@echo "  pre-commit: gofmt + перегенерация proto + buf breaking. Обойти: git commit --no-verify"
	@echo "  pre-push:   go test ./internal/server/..., golangci-lint (обе сборки), гейты web."
	@echo "              Обойти осознанно: SKIP_GATES=1 git push"

proto: ## Перегенерировать Go-код из proto (ОБЩИЙ файл — менять согласованно, ADR-4)
	@# Версии зафиксированы намеренно. Шапка сгенерированных файлов содержит версию
	@# компилятора, поэтому у двух разработчиков с разными protoc КАЖДАЯ перегенерация
	@# дёргала строку туда-сюда: шумный дифф в общем контракте и ложные конфликты.
	@# Кодоген через buf сюда не годится: корень модуля в buf.yaml = proto/, и дескриптор
	@# получил бы имя agent.proto вместо proto/agent.proto (переименование файла в
	@# реестре + 300 строк churn), а CI-джоба `buf breaking` прибита к subdir=proto.
	@have=$$(protoc --version | awk '{print $$2}'); \
	if [ "$$have" != "$(PROTOC_VERSION)" ]; then \
	  echo "protoc $$have, а контракт генерируется $(PROTOC_VERSION)."; \
	  echo "Поставьте нужную версию: https://github.com/protocolbuffers/protobuf/releases/tag/v$(PROTOC_VERSION)"; \
	  echo "(перегенерация чужой версией меняет шапку файлов и создаёт конфликт на ровном месте)"; \
	  exit 1; \
	fi
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

syso-win-arm64: ## Сгенерировать cmd/agent/rsrc_windows_arm64.syso (манифест + PE-VERSIONINFO для arm64)
	# Отдельный .syso, а не переиспользование amd64-шного: Go подхватывает ресурс по
	# СУФФИКСУ АРХИТЕКТУРЫ в имени файла, поэтому rsrc_windows_amd64.syso в arm64-сборку
	# не попадёт вовсе — молча, без ошибки. Итог был бы: exe без манифеста (нет
	# longpath/UAC) и без PE-VERSIONINFO, а по этой метке Windows Installer решает,
	# заменять ли файл при апгрейде MSI.
	$(GOVERSIONINFO) -arm -64 -o cmd/agent/rsrc_windows_arm64.syso \
		-manifest cmd/agent/agent.manifest \
		-ver-major $(WV_MAJ) -ver-minor $(WV_MIN) -ver-patch $(WV_PAT) -ver-build 0 \
		-product-ver-major $(WV_MAJ) -product-ver-minor $(WV_MIN) -product-ver-patch $(WV_PAT) -product-ver-build 0 \
		-file-version "$(WINVER).0" -product-version "$(WINVER)" \
		-company RoutineOps -product-name "RoutineOps Agent" -description "RoutineOps Agent" \
		-internal-name RoutineOps-agent -original-name RoutineOps-agent.exe \
		cmd/agent/versioninfo.json

build-win-arm64: syso-win-arm64 check-escrow-tags ## Кросс-компиляция агента для Windows arm64
	# Нативная сборка под ARM-ноутбуки (Snapdragon X, Surface). Эмуляция x64 на них
	# работает, но у службы, которая живёт месяцами и лезет в реестр, WMI и SCM,
	# нативный бинарь дешевле и предсказуемее.
	#
	# Артефакт на настоящем arm64-железе НЕ прогонялся — его нет ни у меня, ни на
	# билд-боксе. Пока это сборка «собирается и линкуется», а не «проверено в поле»:
	# перед публикацией в releases нужен полевой install/enroll на живой машине.
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
		$(TAGSFLAG) -ldflags "$(LDFLAGS) -X main.releasePubKey=$(RELEASE_PUBKEY) $(ESCROW_LDFLAGS) -H windowsgui" \
		-o bin/agent_windows_arm64.exe ./cmd/agent

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

# CHANNEL — канал выкатки (Q-52). Дефолт stable сознательно совпадает с дефолтом
# самой команды: забытая переменная обязана вести себя как до появления каналов, а не
# тихо посадить релиз в канарейку, откуда его никто не ждёт.
CHANNEL ?= stable

publish-release: ## Опубликовать релиз: make publish-release BINARY=./bin/agent_darwin_arm64 OS=darwin ARCH=arm64 VERSION=v1.0.0 [CHANNEL=beta]
	@test -n "$(BINARY)"  || { echo "укажи BINARY=<путь>"; exit 1; }
	@test -n "$(OS)"      || { echo "укажи OS=<darwin|linux|windows>"; exit 1; }
	@test -n "$(ARCH)"    || { echo "укажи ARCH=<amd64|arm64>"; exit 1; }
	@test -n "$(VERSION)" || { echo "укажи VERSION=<semver>"; exit 1; }
	go run ./cmd/publish-release \
		-binary $(BINARY) -version $(VERSION) -os $(OS) -arch $(ARCH) \
		-key $(RELEASE_KEY) -channel $(CHANNEL)

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
