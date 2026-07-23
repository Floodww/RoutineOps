//go:build windows

package decommission

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Константы контракта с MSI (agentImageName, upgradeCode, installDirName, runKeyPath,
// trayRunValue) — в wxs_contract.go (без build-тега, сверяются с .wxs дрейф-тестом).
// Ниже — рантайм-факты Windows, которых в wxs нет, поэтому они здесь (иначе висели бы
// unused на не-Windows сборке).
const (
	// vendorKeyPath — родительская ветка флагов tamper (создаёт tamper.Arm). tamper.Cleanup
	// удаляет подключ Agent, оставляя пустой корень RoutineOps — доснимаем его здесь.
	vendorKeyPath = `SOFTWARE\RoutineOps`

	// serviceName — имя службы в SCM. ДОЛЖНО совпадать с service.Name (пакет service
	// регистрирует службу через enroll -install-service; в wxs службы нет — её ставит сам
	// агент). Дублируем, как это делает tamper со своим svcName.
	serviceName = "RoutineOps-agent"
)

var (
	msiDLL                     = windows.NewLazySystemDLL("msi.dll")
	procMsiEnumRelatedProducts = msiDLL.NewProc("MsiEnumRelatedProductsW")
)

// resolveProductCode находит ProductCode установленного MSI по стабильному
// UpgradeCode (MsiEnumRelatedProducts). ok=false — продукт не найден: ручная/не-MSI
// установка, либо MSI-запись уже снята. Тогда штатное `msiexec /x` пропускается, а
// снос доводится ручными шагами делетера (без снятия ARP-записи, которой в этом
// случае и нет). Берём первый связанный продукт (iProductIndex=0): в норме на
// устройстве одна установка агента.
func resolveProductCode(log *slog.Logger) (string, bool) {
	// Find() вместо прямого Call: LazyProc.Call ПАНИКУЕТ через mustFind, если msi.dll
	// или экспорт не резолвятся. Паника здесь фатальна — resolveProductCode вызывается
	// уже ПОСЛЕ удаления файлов/каталогов, до записи bat-делетера, и осиротила бы бинарь
	// без сноса. msi.dll есть на всех штатных Windows, но самоснос обязан деградировать
	// мягко: не нашли API — просто пропускаем штатное msiexec.
	if err := procMsiEnumRelatedProducts.Find(); err != nil {
		log.Warn("decommission: msi.dll/MsiEnumRelatedProducts недоступны — штатное msiexec /x пропущено",
			slog.Any("error", err))
		return "", false
	}
	uc, err := windows.UTF16PtrFromString(upgradeCode)
	if err != nil {
		return "", false
	}
	// Буфер под GUID вида {8-4-4-4-12}: 38 символов + завершающий null.
	buf := make([]uint16, 39)
	r, _, _ := procMsiEnumRelatedProducts.Call(
		uintptr(unsafe.Pointer(uc)), 0, 0, uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 { // ERROR_SUCCESS==0; ERROR_NO_MORE_ITEMS(259) и прочее → продукт не найден
		log.Info("decommission: MSI-продукт по UpgradeCode не найден — штатное msiexec /x пропущено",
			slog.String("upgrade_code", upgradeCode))
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

// killResidualAgentProcesses снимает процессы агента в пользовательских сессиях
// (трей, оверлей лока), КРОМЕ текущего процесса службы. Трей поднимается отдельным
// процессом (launchTrayInActiveSession) и держит exe открытым — Windows не даёт
// удалить файл работающего процесса, из-за чего отложенный делетер не сносил ни
// бинарь, ни каталог Program Files\RoutineOps. Снятие по имени образа накрывает все
// сессии сразу (надёжнее убийства по конкретному PID при нескольких вошедших).
func killResidualAgentProcesses(log *slog.Logger) {
	filter := fmt.Sprintf("PID ne %d", os.Getpid())
	// Заодно `.exe.old` — запущенный старый бинарь незавершённого self-update (редко,
	// но держал бы файл так же). /F — принудительно; /FI — не тронуть сам процесс сноса.
	for _, image := range []string{agentImageName, agentImageName + ".old"} {
		// Код возврата 1 = «процессов не найдено» (трея нет — никто не залогинен): норма.
		_ = exec.Command("taskkill", "/F", "/IM", image, "/FI", filter).Run()
	}
	log.Info("decommission: остаточные процессы агента (трей/оверлей) сняты",
		slog.Int("keep_pid", os.Getpid()))
}

// removeTrayAutostart удаляет автозапуск трея (Run-ключ) и пустую родительскую ветку
// флагов tamper. Best-effort: провал логируется, но снос не прерывает (частичный
// остаток добьёт подстраховка в bat-делетере / переустановка ОС). Отсутствие
// ключа/значения — не ошибка (могло быть удалено ранее или установка была ручной).
func removeTrayAutostart(log *slog.Logger) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeyPath, registry.SET_VALUE); err == nil {
		if derr := k.DeleteValue(trayRunValue); derr != nil && !os.IsNotExist(derr) {
			log.Warn("decommission: не удалить Run-ключ автозапуска трея",
				slog.String("value", trayRunValue), slog.Any("error", derr))
		}
		k.Close()
	} else if !os.IsNotExist(err) {
		log.Warn("decommission: не открыть ветку Run для снятия автозапуска трея", slog.Any("error", err))
	}
	// Родительский RoutineOps пустеет после tamper.Cleanup (снял подключ Agent):
	// DeleteKey уберёт его, только если подключей не осталось — иначе best-effort no-op.
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, vendorKeyPath); err != nil && !os.IsNotExist(err) {
		log.Warn("decommission: не удалить пустую ветку "+vendorKeyPath, slog.Any("error", err))
	}
}
