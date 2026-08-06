#!/bin/sh
# strip-cgo-orphans.sh — вычистить C-family спутники, оставшиеся без своего cgo-файла.
#
# Аргумент: корень дерева (каталог среза). Печатает удалённые пути, по одному на строку.
#
# 🔴 Зачем. export-free.sh режет enterprise-код по `//go:build`, но build-теги бывают
# ТОЛЬКО у .go. Реализация на Objective-C/C/Swift живёт отдельным файлом, тега не имеет и
# счётчиком «удалено enterprise .go» не покрыта вовсе — то есть остаётся в публичном
# срезе, когда её единственный потребитель уже удалён.
#
# Поймано на публикации: internal/agent/screen/notice_cocoa_darwin.m (реализация плашки
# наблюдения на macOS) уехал бы в открытый репозиторий целиком, при том что его companion
# notice_darwin.go с `//go:build enterprise && darwin && cgo` вырезан штатно. Все проверки
# среза были при этом ЗЕЛЁНЫЕ: они ищут теги и известные маркеры, а файл без Go-тега для
# них не существует.
#
# Правило — ПО ГРАФУ СБОРКИ, а не по именам. Спутник компилируется только тогда, когда в
# ТОМ ЖЕ каталоге остался .go с `import "C"`; не осталось — файл не собирается ничем и
# является сиротой. Именами это проверять нельзя: companion зовётся notice_darwin.go, а
# спутник notice_cocoa_darwin.m — общего префикса у них нет, и любое правило склейки имён
# ошиблось бы в обе стороны.
#
# Платформенный суффикс учитывается: `foo_darwin.m` держится только за cgo-файлом с тем же
# суффиксом. Иначе пакет, где cgo-код есть под Linux и был под macOS, сохранил бы
# darwin-спутник за linux-файл.
#
# Обратная сторона правила обязательна к проверке (см. cgo_orphan_test.go в
# internal/agent/screen): internal/agent/lockui/lockui_cocoa_darwin.m оставаться ОБЯЗАН —
# его companion lockui_darwin.go собирается без enterprise-тега, это функция Free-версии.
# Гейт, вырезающий оба, ровно так же плох, как нынешний, не вырезающий ни одного.
set -eu

ROOT=${1:-}
if [ -z "$ROOT" ] || [ ! -d "$ROOT" ]; then
	echo "strip-cgo-orphans.sh: нужен существующий каталог" >&2
	exit 2
fi

# Платформенные суффиксы Go. Список закрытый: это соглашение самого тулчейна, и лишний
# элемент здесь означал бы, что мы считаем платформой то, что ей не является.
PLATFORMS="darwin windows linux ios android js freebsd openbsd netbsd solaris aix plan9"

# suffix_of печатает платформенный суффикс имени файла без расширения (пусто — нет).
suffix_of() {
	stem=$1
	for p in $PLATFORMS; do
		case "$stem" in
		*_"$p") printf '%s' "$p"; return ;;
		esac
	done
	printf ''
}

# has_cgo — файл действительно подключает псевдопакет C.
#
# Проверяются обе формы записи: одиночный `import "C"` и строка "C" внутри группы. Вторая
# в cgo-коде встречается редко, но пропустить её значит удалить живой спутник — а это
# сломанная сборка Free-версии, то есть худший исход из возможных.
has_cgo() {
	grep -qE '^[[:space:]]*import[[:space:]]+"C"[[:space:]]*$' "$1" && return 0
	grep -qE '^[[:space:]]*"C"[[:space:]]*$' "$1" && return 0
	return 1
}

find "$ROOT" -type f \( -name '*.m' -o -name '*.mm' -o -name '*.c' -o -name '*.h' -o -name '*.swift' \) |
	sort |
	while IFS= read -r f; do
		dir=$(dirname "$f")
		base=$(basename "$f")
		plat=$(suffix_of "${base%.*}")

		keep=0
		for g in "$dir"/*.go; do
			[ -f "$g" ] || continue
			case "$g" in *_test.go) continue ;; esac
			gplat=$(suffix_of "$(basename "$g" .go)")
			# Разные платформы — не companion. Файл БЕЗ суффикса подходит любому:
			# ограничение платформы у него может стоять build-тегом внутри.
			if [ -n "$plat" ] && [ -n "$gplat" ] && [ "$plat" != "$gplat" ]; then
				continue
			fi
			if has_cgo "$g"; then
				keep=1
				break
			fi
		done

		if [ "$keep" -eq 0 ]; then
			rm -f "$f"
			printf '%s\n' "$f"
		fi
	done
