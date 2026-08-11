#!/usr/bin/env sh
#
# publish-installers.sh — обновляет канонические установщики, которые раздаёт панель.
#
# releases/RoutineOps-agent.{msi,pkg} — это НЕ парк. Парк живёт самообновлением и про эти
# файлы не знает ничего. По ним работают:
#   * кнопки «Скачать MSI» и «Скачать PKG» в карточке устройств;
#   * скрипты миграции с инкумбента (они качают /releases/…), то есть основной путь
#     заведения парка на пилоте.
#
# 🔴 РЕДАКЦИЯ. Трекнутые в git артефакты ОБЯЗАНЫ быть open-core — это гейт
# (check-installer-versions.sh), иначе enterprise-бинарь уехал бы в публичный Free-срез
# байт-в-байт. Значит на enterprise-инсталляции копировать их в releases/ нельзя: свежая
# машина до первого self-update (до 6 часов) живёт с агентом, у которого экран и FileVault
# не выключены, а НЕ СКОМПИЛИРОВАНЫ — создание сеанса ответит agent_unsupported,
# provisioning откажет. Версия при этом верная, гейты зелёные, по внешнему виду не
# отличить.
#
# Это тот же класс, что «darwin на stable был open-core ВСЕГДА» (07.08.2026), только
# перенесённый с канала ОБНОВЛЕНИЯ на канал ПЕРВОЙ УСТАНОВКИ: тогда закрыли один и не
# посмотрели на второй.
#
# Поэтому правило здесь то же, что уже действует для darwin-бинаря в update.sh:
# enterprise берёт установщики из приватного канала (ENTERPRISE_MSI / ENTERPRISE_PKG,
# пути ОТНОСИТЕЛЬНО каталога деплоя), а при их отсутствии файл в releases/ НЕ ТРОГАЕТСЯ.
# Не тронут — значит подложенный руками enterprise-пакет переживает выкат; молчаливое
# копирование open-core поверх него было бы худшим исходом из возможных.
#
# Запускается ВНУТРИ build-контейнера: releases/ после publish-release принадлежит root,
# и host-side cp упал бы Permission denied.
set -eu

BUILD_TAGS=${BUILD_TAGS:-}
ENTERPRISE_MSI=${ENTERPRISE_MSI:-}
ENTERPRISE_PKG=${ENTERPRISE_PKG:-}
RELEASE_CHANNEL=${RELEASE_CHANNEL:-stable}

# Канареечная выкатка НЕ трогает кнопки «Скачать». Смысл beta в том, что новую сборку
# получает небольшая группа машин, а releases/ — это то, что скачивают ВСЕ, включая заведение
# парка с нуля. Подменить их канареечной сборкой значило бы раздать необкатанное всем, то есть
# отменить сам смысл канала.
if [ "$RELEASE_CHANNEL" != stable ]; then
  echo "  канал $RELEASE_CHANNEL — установщики в releases/ не трогаем (их скачивают все)"
  exit 0
fi

mkdir -p releases

# copy_private <переменная> <путь> <расширение> <метка>
copy_private() {
  var=$1; src=$2; ext=$3; label=$4
  dst="releases/RoutineOps-agent.$ext"
  if [ -z "$src" ]; then
    echo "  ⚠ $label: $var не задан — $dst НЕ ТРОНУТ."
    echo "    На enterprise-инсталляции кнопка «Скачать» обязана отдавать enterprise-сборку,"
    echo "    а трекнутый в git артефакт всегда open-core. Путь из приватного канала:"
    echo "    $var=enterprise/RoutineOps-agent-vX.Y.Z-enterprise.$ext ./update.sh"
    return 0
  fi
  if [ ! -f "$src" ]; then
    echo "ОШИБКА: $var=$src не найден в каталоге деплоя." >&2
    exit 1
  fi
  cp "$src" "$dst"
  echo "  $label → $dst обновлён из $src (enterprise)"
}

case "$BUILD_TAGS" in
  *enterprise*)
    copy_private ENTERPRISE_MSI "$ENTERPRISE_MSI" msi MSI
    copy_private ENTERPRISE_PKG "$ENTERPRISE_PKG" pkg PKG
    ;;
  *)
    # Open-core инсталляция: трекнутые артефакты — ровно то, что здесь нужно.
    [ -f build/msi/RoutineOps-agent.msi ] && { cp build/msi/RoutineOps-agent.msi releases/RoutineOps-agent.msi; echo "  MSI → releases/RoutineOps-agent.msi обновлён"; }
    [ -f build/pkg/RoutineOps-agent.pkg ] && { cp build/pkg/RoutineOps-agent.pkg releases/RoutineOps-agent.pkg; echo "  PKG → releases/RoutineOps-agent.pkg обновлён"; }
    ;;
esac
exit 0
