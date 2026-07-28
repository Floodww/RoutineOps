#!/usr/bin/env bash
# Подпись macOS-бинаря агента БЕЗ Apple Developer ID (pre-release путь).
#
# Зачем: на Apple Silicon исполняемый файл обязан быть подписан, иначе ОС его
# убивает. Developer ID + нотаризация — это «zero-friction запуск из браузера»,
# для enterprise-агента (ставится админом/деплоем, дальше self-update по ed25519)
# это апгрейд на будущее, а не блокер. Здесь — ad-hoc (по умолчанию) или
# self-signed идентичность (стабильный code identity), оба бесплатны.
#
# Использование:
#   installer/macos/sign-macos.sh [путь-к-бинарю]      # ad-hoc (identity "-")
#   MACOS_SIGN_IDENTITY="Mac Dev: …" installer/macos/sign-macos.sh bin/agent
#
# Будущий Developer ID — codesign --options runtime +
# notarytool).
set -euo pipefail

BIN="${1:-bin/agent}"
# Различаем «переменная не задана» (штатный ad-hoc путь) и
# «задана пустой» — последнее означает, что секрет не подставился в CI/оболочке.
# Раньше оба случая молча давали ad-hoc с кодом 0, то есть артефакт другого класса
# под видом подписанного, и отличить их автоматике было не по чему.
if [[ -n "${MACOS_SIGN_IDENTITY+x}" && -z "$MACOS_SIGN_IDENTITY" ]]; then
	echo "ошибка: MACOS_SIGN_IDENTITY задана, но пуста — вероятно, не подставился секрет" >&2
	echo "       для намеренной ad-hoc подписи вызывай без этой переменной" >&2
	exit 1
fi
IDENTITY="${MACOS_SIGN_IDENTITY:--}" # "-" = ad-hoc

if [[ ! -f "$BIN" ]]; then
	echo "ошибка: бинарь не найден: $BIN" >&2
	exit 1
fi

# ДО переподписи: если подпись на входе уже есть и она БИТАЯ — это модифицированные
# после сборки байты, а не ad-hoc от Go-линкера. --force залакировал бы правку, и
# стоящая ниже «проверка целостности» проверяла бы уже свою собственную свежую
# подпись — то есть не могла бы покраснеть никогда.
if codesign -d "$BIN" >/dev/null 2>&1; then
	if ! codesign --verify --strict "$BIN" >/dev/null 2>&1; then
		echo "ошибка: у $BIN уже есть подпись, и она невалидна (код или подпись изменены)" >&2
		echo "       пересобери бинарь; --force замаскировал бы правку" >&2
		exit 1
	fi
fi

if [[ "$IDENTITY" == "-" ]]; then
	echo "→ ad-hoc подпись $BIN"
else
	echo "→ подпись $BIN идентичностью: $IDENTITY"
fi

# --force перезатирает ad-hoc подпись, которую Go-линкер ставит сам.
codesign --force --sign "$IDENTITY" "$BIN"

echo "→ проверка целостности подписи"
codesign --verify --strict --verbose=2 "$BIN"

echo "→ сводка подписи"
codesign -dvv "$BIN" 2>&1 | grep -E 'Identifier|Signature|TeamIdentifier|flags' || true

# Утверждаем фактический результат, а не только печатаем его: сводка честно показывала
# Signature=adhoc, но скрипт по ней ничего не проверял и завершался успехом в любом случае.
ACTUAL_ADHOC=no
codesign -dvv "$BIN" 2>&1 | grep -q '^Signature=adhoc' && ACTUAL_ADHOC=yes
if [[ "$IDENTITY" == "-" && "$ACTUAL_ADHOC" != "yes" ]] || [[ "$IDENTITY" != "-" && "$ACTUAL_ADHOC" == "yes" ]]; then
	echo "ошибка: фактическая подпись не соответствует запрошенной (adhoc=$ACTUAL_ADHOC, identity='$IDENTITY')" >&2
	exit 1
fi

cat <<'NOTE'

ГОТОВО. Без Developer ID нотаризации нет — Gatekeeper блокирует ТОЛЬКО файлы с
карантином (скачаны через браузер/почту). Установщик/деплой агента должен
ставить бинарь без карантина (через pkg/скрипт под админом) либо снимать его:
  xattr -dr com.apple.quarantine <путь>
Self-update не затрагивается: замена бинаря на месте карантин не ставит.
NOTE
