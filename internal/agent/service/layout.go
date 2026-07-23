package service

// Layout — стабильные пути установки агента-службы для платформ без инсталлятора
// (macOS/Linux: пользователь запускает скачанный бинарь, служба должна жить не в
// /tmp). На Windows установку делает MSI — там Relocate=false и пути пустые.
type Layout struct {
	Relocate bool   // перекладывать ли бинарь и серты в стабильные пути
	BinPath  string // куда положить бинарь (он же в ExecStart/ProgramArguments)
	DataDir  string // изменяемое состояние (outbox, *.seen, forbidden, lock)
	CertDir  string // mTLS-материал (cert/key/ca)
	LogDir   string // каталог логов демона

	// Материалы авто-энролла, которые кладёт оператор/конфиг-менеджмент, а читают
	// упаковочные скрипты (postinstall.sh / build-pkg.sh). Агент их не создаёт, но
	// обязан знать пути: decommission сносит их вместе с устройством — enroll.env
	// несёт ENROLL_TOKEN (multi-use), с которым переустановка пакета молча вернула
	// бы списанную машину в парк. Windows — пусто (MSI env-файлом не пользуется).
	EnrollEnvPath   string // env-файл авто-энролла (ENROLL_URL/TOKEN/SERVER/CA_*)
	BootstrapCAPath string // стартовый CA рядом с env-файлом (не рантайм-копия в CertDir)
}
