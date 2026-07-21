#!/bin/sh
# preremove для .deb/.rpm: снять службу перед удалением бинаря, но НЕ при апгрейде
# (иначе апгрейд бы разоружал/останавливал агента на каждой новой версии).
#
# Как отличить удаление от апгрейда:
#   dpkg  — $1 = "remove" | "purge" (удаление), "upgrade" (апгрейд);
#   rpm   — $1 = "0" (последнее удаление), "1"+ (апгрейд).
set -e

case "$1" in
    upgrade|1) exit 0 ;;  # апгрейд — службу не трогаем
esac

# Снятие службы генерирует systemctl disable --now + удаление unit-файла
# (internal/agent/service/install_linux.go, Uninstall). Best-effort.
if [ -x /usr/local/bin/RoutineOps-agent ]; then
    /usr/local/bin/RoutineOps-agent uninstall || true
fi
exit 0
