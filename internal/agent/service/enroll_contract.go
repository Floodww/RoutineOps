package service

// Константы-контракт с упаковочными скриптами: где оператор кладёт материалы
// авто-энролла (читают build/nfpm/scripts/postinstall.sh и build/pkg/build-pkg.sh)
// и под каким идентификатором регистрируется macOS .pkg. Живут БЕЗ build-тега,
// чтобы кросс-платформенный TestEnrollArtifactsContract сверял их со скриптами:
// перенос enroll.env или смена pkg-identifier иначе тихо разъехались бы с планом
// decommission — токен энролла/receipt переживали бы снос БЕЗ единого сигнала,
// неотличимо от исходного бага (та же схема, что wxs_contract в decommission).
const (
	// Linux (.deb/.rpm): postinstall.sh авто-энроллит по доверенному root-owned
	// enroll.env; bootstrap-CA лежит рядом. Оба переживали decommission.
	linuxEnrollEnvPath   = "/etc/routineops/enroll.env"
	linuxBootstrapCAPath = "/etc/routineops/ca.crt"

	// macOS (.pkg): env-файл в /tmp транзиентен (macOS чистит его на ребуте), но в
	// пределах одной загрузки живёт — сносим и его. CA — в /usr/local/etc/mdm.
	darwinEnrollEnvPath   = "/tmp/mdm-enroll.env"
	darwinBootstrapCAPath = "/usr/local/etc/mdm/ca.crt"

	// pkgReceiptIdentifier — identifier macOS-пакета (pkgbuild --identifier в
	// build-pkg.sh). Uninstall делает по нему pkgutil --forget: без этого receipt
	// числит агента установленным после сноса — аналог ARP-записи на Windows,
	// которую там снимает msiexec /x.
	pkgReceiptIdentifier = "com.routineops.agent"
)
