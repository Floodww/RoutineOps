#!/bin/sh
# postinstall для .deb/.rpm: бинарь уже выложен, завершаем регистрацию агента.
# Зеркалит логику build/pkg/build-pkg.sh (macOS), адаптированную под GNU stat.
set -e

echo "RoutineOps Agent установлен в /usr/local/bin/RoutineOps-agent."

CA_PATH="/etc/routineops/ca.crt"
ENROLL_ENV="/etc/routineops/enroll.env"

# Auto-enroll возможен, ТОЛЬКО если env-файл положил root (Ansible/оператор).
# Прежний `. "$ENROLL_ENV"` был бы локальным root-RCE: source исполняет
# произвольный код. Защита: (1) файл owned by root и без write-бита group/other;
# (2) не source, а разбор ТОЛЬКО известных ключей — код не исполняется, даже если
# проверку (1) обойти. /etc уже root-only, но проверяем явно (defense-in-depth).
consume_enroll_env() {
    f="$1"
    owner=$(stat -c '%u' "$f" 2>/dev/null) || return 1
    perms=$(stat -c '%a' "$f" 2>/dev/null) || return 1
    if [ "$owner" != "0" ]; then
        echo "Игнорирую $f: владелец не root (uid $owner) — возможна подмена." >&2
        return 1
    fi
    if [ $(( 0$perms & 022 )) -ne 0 ]; then
        echo "Игнорирую $f: доступен на запись group/other (mode $perms)." >&2
        return 1
    fi
    # cr через printf: скрипт бежит под /bin/sh (dash), где bash-идиома $'\r'
    # НЕ раскрывается и молча оставила бы CR на месте.
    cr=$(printf '\r')
    # `|| [ -n "$k" ]` — не терять последнюю строку файла без финального \n
    # (read тогда заполняет переменные, но возвращает ненулевой код).
    while IFS='=' read -r k v || [ -n "$k" ]; do
        k=${k%"$cr"}; v=${v%"$cr"}   # срезать хвостовой CR (файл, сохранённый с Windows CRLF)
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
    echo "Для завершения установки выполните:"
    echo "sudo /usr/local/bin/RoutineOps-agent enroll -install-service \\"
    echo "  -enroll-url https://<host>/api/v1/enroll -server <host>:50051 -token <token> \\"
    echo "  -ca $CA_PATH -ca-url https://<host>/ca.crt -ca-sha256 <sha256 от ca.crt>"
    echo "Либо положите доверенный root-owned $ENROLL_ENV (ENROLL_URL, ENROLL_TOKEN,"
    echo "ENROLL_SERVER, CA_URL, CA_SHA256) и переустановите пакет."
}

if [ -f "$ENROLL_ENV" ] && consume_enroll_env "$ENROLL_ENV"; then
    echo "Найден доверенный $ENROLL_ENV. Выполняю автоматическую регистрацию..."
    if [ -n "$ENROLL_URL" ] && [ -n "$ENROLL_TOKEN" ] && [ -n "$ENROLL_SERVER" ] \
       && [ -n "$CA_URL" ] && [ -n "$CA_SHA256" ]; then
        /usr/local/bin/RoutineOps-agent enroll -install-service \
            -enroll-url "$ENROLL_URL" -token "$ENROLL_TOKEN" -server "$ENROLL_SERVER" \
            -ca "$CA_PATH" -ca-url "$CA_URL" -ca-sha256 "$CA_SHA256" \
            || echo "Ошибка авто-регистрации"
        exit 0
    fi
    echo "В $ENROLL_ENV не хватает переменных." >&2
    echo "Нужны все пять: ENROLL_URL, ENROLL_TOKEN, ENROLL_SERVER, CA_URL, CA_SHA256." >&2
fi

hint
exit 0
