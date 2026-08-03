package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Срез системных служб и демонов — для аудита выданных админ-прав:
// что изменилось на машине за время сессии с временными правами администратора.
//
// ГЛАВНЫЙ ИНВАРИАНТ: в снимке нет ни одного волатильного поля. Ни running/stopped,
// ни PID, ни времени старта. Причина не в экономии, а в том, что дельта считается
// между двумя снимками: живое состояние давало бы «изменение» на каждом ребуте по
// всему парку, и сигнал утонул бы в шуме до того, как его кто-нибудь прочитает.
// Сравниваем ОПРЕДЕЛЕНИЕ службы — то, что переживает перезагрузку и остаётся на
// машине после сессии. Тот же инвариант уже держит Software (см. выше по файлу).
//
// Никаких внешних процессов на запись снимка: реестр читается нативно, plist'ы и
// unit-файлы — обычным ReadDir/ReadFile. Один процесс допущен ровно один
// (launchctl print-disabled на macOS) — там иначе не отличить disabled от enabled.

// Service — определение одной службы/демона. Все поля стабильны между ребутами.
type Service struct {
	// Name — машинный ключ: имя службы SCM (Windows), Label демона (macOS),
	// имя unit'а (Linux). По нему сходятся снимки при вычислении дельты.
	Name string
	// Display — человекочитаемое имя; "" там, где источник его не даёт.
	Display string
	// StartType — режим автозапуска, словарь ниже (StartType*). Значения намеренно
	// НЕ приводятся к общему для всех ОС словарю: boot/system у Windows не имеют
	// аналога в systemd, и склейка потеряла бы разницу между «драйвер грузится
	// ядром» и «юнит включён». Нормализация — задача потребителя.
	StartType string
	// Account — под кем запускается: ObjectName (Windows), UserName из plist,
	// User= из unit. "" = источник не указал (значит, дефолт ОС).
	Account string
	// ImagePath — исполняемый файл: ImagePath (Windows), первый элемент
	// ProgramArguments (macOS), ExecStart (Linux). Не нормализуется.
	ImagePath string
	// DefHash — sha256 определения целиком. Ловит изменения, которых не видно в
	// явных полях: правку аргументов запуска, добавление WatchPaths, смену
	// зависимостей. Для Windows считается по значимым значениям подключа реестра.
	DefHash string
	// OSOwned — определение лежит в системном каталоге, то есть службу штатно
	// ставит и обновляет сама ОС. Это ключевой признак для атрибуции: изменение
	// такой службы почти всегда фоновое обновление, а не действие человека.
	OSOwned bool
	// Kind — KindService / KindDriver / KindAgent. Драйвер ядра выделен отдельно:
	// его установка вне системного каталога — сильный сигнал для разбора инцидента.
	Kind string
}

// Режимы автозапуска. Windows-значения соответствуют DWORD Start в реестре,
// unix-значения — состоянию включённости юнита/демона.
const (
	StartTypeBoot        = "boot"         // windows: Start=0, драйвер загрузчика
	StartTypeSystem      = "system"       // windows: Start=1, драйвер ядра
	StartTypeAuto        = "auto"         // windows: Start=2 / systemd: enabled
	StartTypeAutoDelayed = "auto_delayed" // windows: Start=2 + DelayedAutostart=1
	StartTypeManual      = "manual"       // windows: Start=3 / systemd: static
	StartTypeDisabled    = "disabled"     // windows: Start=4 / launchd, systemd: disabled
	StartTypeEnabled     = "enabled"      // unix: определение на месте и включено
	StartTypeUnknown     = ""             // источник не дал ответа
)

// Виды служб.
const (
	KindService = "service"
	KindDriver  = "driver" // Windows Type 1/2 — драйвер ядра или файловой системы
	KindAgent   = "agent"  // macOS LaunchAgent — стартует в сессии пользователя
)

// Health — здоровье сбора снимка. Нужен, чтобы отличить «изменений не было» от
// «мы не смогли посмотреть»: для фичи подотчётности это разные ответы, и пустой
// список при неудачном сборе не имеет права выглядеть как чистая сессия.
type Health string

const (
	HealthOK          Health = "ok"
	HealthPartial     Health = "partial"     // часть источника недоступна (ACCESS_DENIED, битый файл)
	HealthFailed      Health = "failed"      // снимок снять не удалось вовсе
	HealthUnsupported Health = "unsupported" // платформа не умеет (нет systemd и init.d)
)

// Services — снимок определений служб текущей ОС. Список отсортирован по Name,
// чтобы сравнение снимков и их хэш не зависели от порядка обхода файловой
// системы или реестра.
func Services() ([]Service, Health) { return osServices() }

// sortServices приводит снимок к каноническому порядку. Вынесено отдельно, потому
// что вызывается из каждой платформенной реализации, и разъехавшийся порядок дал
// бы ложную дельту, которую крайне трудно объяснить.
func sortServices(svcs []Service) {
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
}

// startTypeFromDWORD переводит значение Start из реестра Windows в наш словарь.
// Живёт в платформенно-независимом файле намеренно: так таблица значений
// проверяется тестами на любой машине, а не только на Windows-боксе, куда тесты
// приходится возить отдельно.
func startTypeFromDWORD(v uint64, delayed bool) string {
	switch v {
	case 0:
		return StartTypeBoot
	case 1:
		return StartTypeSystem
	case 2:
		if delayed {
			return StartTypeAutoDelayed
		}
		return StartTypeAuto
	case 3:
		return StartTypeManual
	case 4:
		return StartTypeDisabled
	default:
		return StartTypeUnknown
	}
}

// kindFromServiceType переводит DWORD Type из реестра Windows: 1 = драйвер ядра,
// 2 = драйвер файловой системы, остальное — обычная служба.
func kindFromServiceType(v uint64) string {
	if v == 1 || v == 2 {
		return KindDriver
	}
	return KindService
}

// hashDefinition — sha256 определения. Принимает уже готовые байты (содержимое
// plist/unit) либо склейку значимых значений реестра.
func hashDefinition(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isUnderAny — лежит ли путь в одном из системных каталогов. Сравнение
// регистронезависимое: на Windows пути приходят из реестра в произвольном
// регистре (C:\Windows против c:\windows), и регистрозависимая проверка
// объявляла бы штатные системные службы «поставленными человеком» — то есть
// ровно наоборот тому, что нужно для атрибуции.
func isUnderAny(path string, prefixes []string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	for _, pref := range prefixes {
		if strings.HasPrefix(p, strings.ToLower(pref)) {
			return true
		}
	}
	return false
}
