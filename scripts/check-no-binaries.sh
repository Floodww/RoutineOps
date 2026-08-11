#!/bin/sh
# Гейт: скомпилированный бинарь не должен лежать в репозитории вне build/.
#
# Зачем. `go build ./cmd/...` кладёт исполняемые файлы в КОРЕНЬ репозитория, под
# именами каталогов команд — publish-release, routineops, seeddev. В `git status`
# они выглядят как обычные новые файлы, `git add -A` забирает их не глядя, а дифф
# не показывает НИЧЕГО: у бинаря нет читаемого содержимого, и ревью проходит мимо.
# Так в main уехали 37 МБ тремя коммитами, и поймано это было глазами на ревью
# 11.08.2026, а не проверкой.
#
# История от этого уже не очистится (переписывать общий main дороже, чем 37 МБ), но
# следующий такой файл дальше этого гейта не пройдёт.
#
# Что разрешено: каталог build/ — там установщики и трекнутый darwin-prebuilt лежат
# ОСОЗНАННО, это отдельная поверхность выдачи («Скачать MSI»), и у неё свои гейты
# версии и редакции (check-installer-versions.sh, agent-edition-guard.sh).
#
# Использование: sh scripts/check-no-binaries.sh [каталог-репозитория]
set -e

repo=${1:-$(git rev-parse --show-toplevel)}
cd "$repo"

command -v file >/dev/null 2>&1 || {
  echo "check-no-binaries: утилиты file нет — гейт НЕ проверен" >&2
  exit 1
}

# Типы, которые означают «это исполняемый файл или библиотека», а не текст. Список
# точный, а не по подстроке: `application/x-object` подстрокой ловит ещё и
# `text/x-objective-c`, то есть весь наш код на Objective-C для Cocoa.
#
# x-pie-executable отдельной строкой: современный file на Linux называет так все
# Go-бинари, собранные с -buildmode=pie, — на macOS этого типа не существует вовсе,
# и гейт, написанный только под свою машину, в CI молчал бы.
found=$(
  git ls-files -z |
    xargs -0 file --mime-type 2>/dev/null |
    awk -F': +' '
      $2 == "application/x-mach-binary"     ||
      $2 == "application/x-executable"      ||
      $2 == "application/x-pie-executable"  ||
      $2 == "application/x-sharedlib"       ||
      $2 == "application/x-dosexec"         ||
      $2 == "application/x-msdownload"      { print $1 ": " $2 }
    ' |
    grep -v '^build/' || true
)

if [ -n "$found" ]; then
  echo "check-no-binaries: в репозитории лежат скомпилированные бинари:" >&2
  echo "$found" | sed 's/^/  /' >&2
  echo "" >&2
  echo "  Это артефакты сборки. Убрать из индекса, оставив файл на диске:" >&2
  echo "    git rm --cached <файл> && echo '/<файл>' >> .gitignore" >&2
  echo "  Если файл нужен в репозитории осознанно — ему место в build/, вместе с" >&2
  echo "  гейтами версии и редакции." >&2
  exit 1
fi

echo "check-no-binaries: скомпилированных бинарей вне build/ нет"
