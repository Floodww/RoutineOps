package decommission

// Константы-контракт с MSI-манифестом build/msi/mdm-agent.wxs и службой SCM. Живут БЕЗ
// build-тега (это платформенно-нейтральные строки-факты об установщике), чтобы
// кросс-платформенный TestWxsContract мог сверить их с самим .wxs. Дрейф (правка wxs,
// ренейм файла/каталога, смена UpgradeCode) иначе тихо ломал бы resolveProductCode или
// снос каталога — и ARP-хвост/остаток вернулся бы БЕЗ единого сигнала, неотличимо от
// исходного бага. Windows-код (cleanup_windows.go / selfdelete_windows.go) их использует.
const (
	// agentImageName — имя образа процесса агента (== File Name в wxs). Служба и трей —
	// один бинарь, имя образа у них общее.
	agentImageName = "RoutineOps-agent.exe"

	// installDirName — имя каталога установки (== Directory Id="INSTALLFOLDER" Name в wxs).
	// Снос installDir целиком (rmdir /s /q) разрешён ТОЛЬКО когда basename каталога равен
	// этому — иначе снесли бы чужой/системный каталог (место запуска бинаря, не наш путь).
	installDirName = "RoutineOps"

	// upgradeCode — СТАБИЛЬНЫЙ UpgradeCode из wxs. ProductCode генерится на каждую сборку,
	// поэтому в рантайме ищем его по UpgradeCode — только он известен заранее. Фигурные
	// скобки обязательны для MsiEnumRelatedProducts (в wxs UpgradeCode без скобок).
	upgradeCode = "{42488912-25F8-4C42-AE88-DF4D50E17832}"

	// runKeyPath / trayRunValue — автозапуск трея из wxs (компонент TrayAutostart): MSI
	// прописывает Run-значение в HKLM. Без снятия трей поднимался бы на каждом логоне
	// уже снятого устройства.
	runKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Run`
	trayRunValue = "RoutineOpsTray"
)

// vendorKeyPath (родительская ветка флагов tamper, создаёт tamper.Arm) и serviceName
// (имя службы SCM, == service.Name) — рантайм-факты Windows, НЕ из wxs; живут в
// windows-tagged cleanup_windows.go, чтобы не висеть unused на не-Windows сборке.
