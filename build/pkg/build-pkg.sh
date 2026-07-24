#!/bin/bash
# Скрипт сборки macOS PKG инсталлятора для MDM Агента

set -e

VERSION=${1:-1.0.0}
ARCH=${2:-arm64}
EXE_PATH="../../bin/agent_darwin_${ARCH}"
if [ "$ARCH" == "native" ]; then
    EXE_PATH="../../bin/agent_darwin_native"
fi

# УНИВЕРСАЛЬНЫЙ .pkg (зеркало универсального MSI): ни CA, ни release-ключ не вшиты,
# один пакет годен для любого деплоя. Привязка к серверу приезжает в /tmp/mdm-enroll.env.
#
# CA. Раньше ca.crt лежал в payload → пакет был per-deployment. Теперь агент качает
# CA по CA_URL и сверяет с CA_SHA256 (loadCABundle, internal/agent/enroll/enroll.go:192).
# Это НЕ возврат к дыре SEC-1: тот postinstall тянул CA через `curl -k` вообще без
# сверки, и активный MITM подсовывал rogue-CA → rogue gRPC-сервер → RCE под root на
# КАЖДОЙ установке. Здесь пин обязателен: `-ca-url` без `-ca-sha256` отвергается ДО
# сетевого запроса. Скачанный CA нужен лишь чтобы запинить TLS самого enroll-запроса;
# рантайм-CA приходит в ответе и пишется в -ca (CAOut, enroll.go:162).
#
# releasePubKey. Пустой по умолчанию: универсальный агент берёт ключ из enroll-ответа
# (release_pubkey → рядом с CA). Вшитый ключ АВТОРИТЕТНЕЕ полученного (main.go:1161),
# поэтому литерал здесь делал бы пакет непригодным для чужого деплоя — тот сервер
# подписывает релизы СВОИМ ключом (install.sh:56 генерит per-deployer). Переопределить
# для deployment-specific сборки: RELEASE_PUBKEY=<base64> ./build-pkg.sh ...
RELEASE_PUBKEY=${RELEASE_PUBKEY-}

cd ../..
echo "Компиляция бинарного файла версии v$VERSION..."
# FileVault recovery-escrow — ENTERPRISE-фича (carve-out). Free .pkg (дефолт) её
# НЕ собирает: escrow-символов main.escrowRecipient/_Fpr в free-агенте нет, а
# -X по несуществующему символу линкер МОЛЧА игнорирует. Поэтому логика тегов
# здесь обязана зеркалить Makefile (AGENT_TAGS/TAGSFLAG/ESCROW_LDFLAGS):
#   enterprise .pkg: make pkg-mac[-native] AGENT_TAGS=enterprise ESCROW_RECIPIENT=age1... ESCROW_RECIPIENT_FPR=<fpr>
# Этот скрипт САМ пересобирает бинарь (не переиспользует bin/agent_darwin_* от
# make build-mac) — рассинхрон с Makefile = .pkg тихо теряет enterprise-код.
TAGSFLAG=""
LDFLAGS_ESCROW=""
if [ "${AGENT_TAGS:-}" == "enterprise" ]; then
    TAGSFLAG="-tags enterprise"
    LDFLAGS_ESCROW="-X main.escrowRecipient=${ESCROW_RECIPIENT:-} -X main.escrowRecipientFpr=${ESCROW_RECIPIENT_FPR:-}"
elif [ -n "${ESCROW_RECIPIENT:-}${ESCROW_RECIPIENT_FPR:-}" ]; then
    echo "ОШИБКА: ESCROW_RECIPIENT/_FPR заданы, но AGENT_TAGS != enterprise —" >&2
    echo "free-агент не содержит escrow-символов, пиннинг молча потеряется." >&2
    echo "Для enterprise .pkg добавь AGENT_TAGS=enterprise." >&2
    exit 1
fi
if [ -n "$RELEASE_PUBKEY" ]; then
    echo "release-ключ ВШИВАЕТСЯ в бинарь (deployment-specific пакет)"
else
    echo "release-ключ НЕ вшивается — приедет в enroll-ответе (универсальный пакет)"
fi
if [ "$ARCH" == "native" ]; then
    CGO_ENABLED=1 GOOS=darwin go build -trimpath $TAGSFLAG -ldflags "-X main.version=v$VERSION -X main.releasePubKey=$RELEASE_PUBKEY $LDFLAGS_ESCROW" -o bin/agent_darwin_native ./cmd/agent
else
    CGO_ENABLED=1 GOOS=darwin GOARCH=$ARCH go build -trimpath $TAGSFLAG -ldflags "-X main.version=v$VERSION -X main.releasePubKey=$RELEASE_PUBKEY $LDFLAGS_ESCROW" -o "bin/agent_darwin_$ARCH" ./cmd/agent
fi
cd build/pkg

if [ ! -f "$EXE_PATH" ]; then
    echo "Ошибка: Бинарный файл $EXE_PATH не найден после сборки."
    exit 1
fi

OUT_PKG="mdm-agent-v${VERSION}-${ARCH}.pkg"

echo "Сборка PKG пакета версии $VERSION (архитектура: $ARCH)..."

WORK_DIR=$(mktemp -d)
PAYLOAD_DIR="$WORK_DIR/payload"
SCRIPTS_DIR="$WORK_DIR/scripts"

# 1. Готовим Payload (то, что будет скопировано на диск)
mkdir -p "$PAYLOAD_DIR/usr/local/bin"
export COPYFILE_DISABLE=1
cp "$EXE_PATH" "$PAYLOAD_DIR/usr/local/bin/RoutineOps-agent"
chmod +x "$PAYLOAD_DIR/usr/local/bin/RoutineOps-agent"

# CA в payload НЕ кладём: качается по CA_URL с пином CA_SHA256 (см. шапку).
# Каталог /usr/local/etc/mdm создаст сам enroll (writeFile → MkdirAll).

# 2. Готовим Scripts (postinstall/preinstall)
mkdir -p "$SCRIPTS_DIR"

# preinstall: снять tamper-защиту ДО выкладки payload. На энролленной машине
# /usr/local/bin/RoutineOps-agent и оба plist лежат под chflags schg (tamper.Arm), а
# immutable-файл ядро не даёт ни перезаписать, ни удалить даже root'у — Installer
# падает ещё на копировании payload («The installer encountered an error») и до
# postinstall не доходит. Из Go этот момент недостижим: наш код в переустановке
# запускается уже ПОСЛЕ выкладки. Защиту вернёт сам агент (tamper.Arm в конце
# `enroll -install-service`).
cat << 'INNER_EOF' > "$SCRIPTS_DIR/preinstall"
#!/bin/bash
for f in /usr/local/bin/RoutineOps-agent \
         /Library/LaunchDaemons/RoutineOps-agent.plist \
         /Library/LaunchAgents/RoutineOps-agent.tray.plist; do
    [ -e "$f" ] && chflags noschg,nouchg "$f" 2>/dev/null
done
exit 0
INNER_EOF
chmod +x "$SCRIPTS_DIR/preinstall"

cat << 'INNER_EOF' > "$SCRIPTS_DIR/postinstall"
#!/bin/bash
echo "RoutineOps Agent установлен в /usr/local/bin/RoutineOps-agent."

# -ca — это и ВХОД (пин TLS enroll-запроса, если файл уже лежит), и ВЫХОД: enroll
# положит туда рантайм-CA из ответа сервера. На чистой машине файла нет, поэтому
# бутстрап-CA качается по -ca-url и сверяется с -ca-sha256 (без пина enroll откажет).
CA_PATH="/usr/local/etc/mdm/ca.crt"
ENROLL_ENV="/tmp/mdm-enroll.env"

# Auto-enroll возможен, ТОЛЬКО если env-файл положил root (Jamf/оператор), а не
# любой локальный юзер. postinstall бежит от root, а /tmp world-writable — sticky
# НЕ мешает создать новый файл. Прежний `. "$ENROLL_ENV"` = локальный root-RCE:
# source исполняет произвольный код из чужого файла. Защита: (1) файл обязан быть
# owned by root и без write-бита для group/other; (2) не source, а разбор ТОЛЬКО
# известных ключей — код не исполняется, даже если проверка (1) кем-то обойдена.
consume_enroll_env() {
    local f="$1" owner perms
    owner=$(stat -f '%u' "$f" 2>/dev/null) || return 1
    perms=$(stat -f '%Lp' "$f" 2>/dev/null) || return 1
    if [ "$owner" != "0" ]; then
        echo "Игнорирую $f: владелец не root (uid $owner) — возможна подмена." >&2
        return 1
    fi
    if [ $(( 0$perms & 022 )) -ne 0 ]; then
        echo "Игнорирую $f: доступен на запись group/other (mode $perms)." >&2
        return 1
    fi
    # `|| [ -n "$k" ]` — не терять последнюю строку файла без финального \n
    # (read тогда заполняет переменные, но возвращает ненулевой код).
    while IFS='=' read -r k v || [ -n "$k" ]; do
        k=${k%$'\r'}; v=${v%$'\r'}   # срезать хвостовой CR (файл, сохранённый с Windows CRLF)
        v=${v%\"}; v=${v#\"}   # снять парные кавычки, если оператор их поставил
        case "$k" in
            ENROLL_URL)    ENROLL_URL=$v ;;
            ENROLL_TOKEN)  ENROLL_TOKEN=$v ;;
            ENROLL_SERVER) ENROLL_SERVER=$v ;;
            CA_URL)        CA_URL=$v ;;
            CA_SHA256)     CA_SHA256=$v ;;
        esac
    done < "$f"
    return 0
}

hint() {
    # CA сервер отдаёт по /ca.crt (handler.go:131); /downloads/* — это releasesDir.
    # Готовый скрипт с подставленными URL/пином даёт UI («Добавить устройство»).
    echo "Для завершения установки выполните:"
    echo "sudo /usr/local/bin/RoutineOps-agent enroll -install-service \\"
    echo "  -enroll-url https://<host>/api/v1/enroll -server <host>:50051 -token <token> \\"
    echo "  -ca $CA_PATH -ca-url https://<host>/ca.crt -ca-sha256 <sha256 от ca.crt>"
}

if [ -f "$ENROLL_ENV" ] && consume_enroll_env "$ENROLL_ENV"; then
    echo "Найден доверенный $ENROLL_ENV. Выполняю автоматическую регистрацию..."
    if [ -n "$ENROLL_URL" ] && [ -n "$ENROLL_TOKEN" ] && [ -n "$ENROLL_SERVER" ] \
       && [ -n "$CA_URL" ] && [ -n "$CA_SHA256" ]; then
        if /usr/local/bin/RoutineOps-agent enroll -install-service \
            -enroll-url "$ENROLL_URL" -token "$ENROLL_TOKEN" -server "$ENROLL_SERVER" \
            -ca "$CA_PATH" -ca-url "$CA_URL" -ca-sha256 "$CA_SHA256"; then
            # Файл отработал — удаляем. Он стоячий креденшл: bulk-токен многоразовый и
            # заводит устройства, а лежит в world-writable /tmp на КАЖДОМ эндпоинте.
            # Плюс postinstall бежит и на апгрейде пакета: уцелевший файл молча
            # переэнролливает хост (и воскрешал бы списанный).
            rm -f "$ENROLL_ENV"
            echo "Регистрация выполнена, $ENROLL_ENV удалён."
        else
            echo "Ошибка авто-регистрации ($ENROLL_ENV оставлен для повтора)" >&2
        fi
        exit 0
    fi
    echo "В $ENROLL_ENV не хватает переменных." >&2
    echo "Нужны все пять: ENROLL_URL, ENROLL_TOKEN, ENROLL_SERVER, CA_URL, CA_SHA256." >&2
fi

hint
exit 0
INNER_EOF
chmod +x "$SCRIPTS_DIR/postinstall"

# 3. Собираем PKG
find "$PAYLOAD_DIR" -name "._*" -delete

pkgbuild --root "$PAYLOAD_DIR" \
         --identifier com.routineops.agent \
         --version "$VERSION" \
         --scripts "$SCRIPTS_DIR" \
         --install-location "/" \
         "$OUT_PKG"

# 4. Подпись кода и нотаризация (Опционально)
if [ -n "$SIGNING_IDENTITY" ]; then
    echo "Подписываем пакет сертификатом: $SIGNING_IDENTITY"
    # Подпись пакета (требуется Developer ID Installer)
    productsign --sign "$SIGNING_IDENTITY" "$OUT_PKG" "${OUT_PKG}.signed"
    mv "${OUT_PKG}.signed" "$OUT_PKG"

    if [ -n "$APPLE_ID" ] && [ -n "$APP_PASSWORD" ] && [ -n "$TEAM_ID" ]; then
        echo "Отправляем пакет на нотаризацию Apple..."
        xcrun notarytool submit "$OUT_PKG" \
            --apple-id "$APPLE_ID" \
            --password "$APP_PASSWORD" \
            --team-id "$TEAM_ID" \
            --wait
        
        echo "Прикрепляем тикет нотаризации к пакету (stapling)..."
        xcrun stapler staple "$OUT_PKG"
    else
        echo "Пропуск нотаризации (установите APPLE_ID, APP_PASSWORD, TEAM_ID)"
    fi
else
    echo "Пропуск подписи пакета (установите SIGNING_IDENTITY для подписи)"
fi

rm -rf "$WORK_DIR"
echo "Готово! Пакет собран: $OUT_PKG"

# 5. Канонические артефакты релиза (зеркало build/msi/RoutineOps-agent.msi в git).
# macOS-агент требует cgo (Cocoa-замок lockui_darwin.go + Keychain provider_darwin.go),
# поэтому Linux-прод собрать его НЕ может: `CGO_ENABLED=0 GOOS=darwin` молча выбирает
# заглушки по тегам `!darwin || !cgo`. Мейнтейнер собирает здесь, на маке, и кладёт в git:
#   build/pkg/RoutineOps-agent.pkg          — install.sh раздаст через /downloads
#   build/darwin/agent_darwin_arm64  — update.sh/install.sh ПОДПИШУТ ключом деплойера
#                                      и опубликуют в agent_releases (self-update)
# Deployment-specific сборку (RELEASE_PUBKEY задан) в репо не кладём: она чужому деплою
# не годится.
REPO_ROOT="$(cd ../.. && pwd)"
if [ "$ARCH" == "native" ]; then
    REL_ARCH=$(uname -m); [ "$REL_ARCH" == "x86_64" ] && REL_ARCH=amd64
    BIN_SRC="$REPO_ROOT/bin/agent_darwin_native"
else
    REL_ARCH="$ARCH"
    BIN_SRC="$REPO_ROOT/bin/agent_darwin_$ARCH"
fi

if [ -n "$RELEASE_PUBKEY" ]; then
    echo "RELEASE_PUBKEY задан → пакет deployment-specific; канонические артефакты НЕ обновлены."
    exit 0
fi

# install.sh/update.sh ищут РОВНО build/darwin/agent_darwin_arm64. Собери релиз на
# Intel-маке — они молча не найдут файл, скажут «отсутствует» и выйдут с кодом 0:
# деплой «успешен», а маки без self-update. Падаем громко.
if [ "$REL_ARCH" != "arm64" ]; then
    echo "ОШИБКА: канонический релиз собирается только под arm64, а здесь $REL_ARCH." >&2
    echo "Собери на Apple Silicon либо: ./build-pkg.sh $VERSION arm64" >&2
    exit 1
fi

# Артефакт уезжает в ПУБЛИЧНЫЙ репозиторий. leak-guard (export-free.sh V4) слеп к
# бинарям: GNU grep пишет «binary file matches» в stderr, который там гасится
# в /dev/null. Значит проверяем здесь, у источника. -trimpath обязан вычистить
# и /home/<user>/go/pkg/mod/..., и путь рабочей копии.
if LC_ALL=C grep -aqE '/home/[a-z]|/Users/[a-z]' "$BIN_SRC"; then
    echo "ОШИБКА: в бинаре остались абсолютные пути сборки — собран без -trimpath." >&2
    LC_ALL=C grep -aoE '(/home|/Users)/[^ ]{0,40}' "$BIN_SRC" | sort -u | head -3 >&2
    exit 1
fi

sha256_of() { # формат `<hash>  <файл>`, совместим с `sha256sum -c` в alpine
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

mkdir -p "$REPO_ROOT/build/darwin"
cp "$BIN_SRC" "$REPO_ROOT/build/darwin/agent_darwin_${REL_ARCH}"
( cd "$REPO_ROOT/build/darwin" && sha256_of "agent_darwin_${REL_ARCH}" > "agent_darwin_${REL_ARCH}.sha256" )
# Версия, ВШИТАЯ в этот бинарь (-X main.version) — версия АГЕНТА. Деплойер публикует
# prebuilt под СВОИМ $(cat AGENT_VERSION); если мейнтейнер забыл пересобрать артефакт
# после бампа, агент вечно качал бы «новую» версию и продолжал рапортовать старую — петля
# обновления каждые 6ч. update.sh/install.sh сверяют этот файл с AGENT_VERSION.
echo "v$VERSION" > "$REPO_ROOT/build/darwin/agent_darwin_${REL_ARCH}.version"
cp "$OUT_PKG" "$REPO_ROOT/build/pkg/RoutineOps-agent.pkg"

echo ""
echo "Канонические артефакты обновлены — закоммить их, это и есть macOS-релиз:"
echo "  build/pkg/RoutineOps-agent.pkg"
echo "  build/darwin/agent_darwin_${REL_ARCH} (+ .sha256, .version)"
