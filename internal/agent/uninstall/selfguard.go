package uninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Самозащита: агент не снимает сам себя этой командой.
//
// Почему это первая строчка пакета, а не деталь. Агент виден в собственном
// инвентаре как обычная запись («RoutineOps Agent» в ARP на Windows, пакет
// routineops-agent на Linux). Массовая операция по вендору или по имени —
// ровно тот сценарий, ради которого фичу и просят, — снесла бы агента на всём
// парке, после чего вернуть управление можно только ногами. Причём тихо и
// «успешно»: снос отработал, отчитаться о нём уже некому.
//
// Штатный путь снятия агента существует и другой — команда вывода из
// эксплуатации (Task.decommission): она подтверждает выполнение серверу ДО сноса
// серта, отзывает сертификат и помечает устройство списанным. Здесь же — отказ.
//
// Признаки проверяются НЕЗАВИСИМЫЕ, и достаточно одного: путь, имя, машинный
// ключ, издатель. Один признак может не сработать (переименованный дистрибутив,
// установка мимо пакетного менеджера, пустой InstallLocation в источнике) —
// поэтому их несколько, и они перекрывают друг друга.

// Имена, под которыми агент виден в инвентаре разных ОС. Сравнение
// регистронезависимое.
//
// Список намеренно ШИРЕ, чем текущее имя продукта: сюда входит и историческое
// mdm-agent (репозиторий и бинарь назывались так до ребрендинга, и на части
// парка стоят именно такие установки). Лишнее имя в этом списке стоит одного
// невыполненного удаления чужого одноимённого ПО; недостающее — снесённого агента.
var selfNames = []string{
	"routineops",
	"routineops agent",
	"routineops-agent",
	"routineops-agent.exe",
	"mdm-agent",
	"mdm agent",
	"mdm-agent.exe",
}

// selfVendor — издатель агента (Manufacturer в MSI, Maintainer в пакете Linux,
// Developer ID на macOS). Всё, что издано нами, снимается не этой командой.
const selfVendor = "routineops"

// selfID — то, чем агент опознаёт себя в собственном инвентаре.
type selfID struct {
	exePath string // абсолютный путь бинаря, символические ссылки разрешены
	exeDir  string // каталог установки
}

// resolveSelf устанавливает идентичность процесса. Ошибка здесь ОТКЛЮЧАЕТ фичу
// целиком (см. New): guard без знания о себе не guard.
//
// EvalSymlinks обязателен: на macOS бинарь лежит в /usr/local/bin, который сам
// может быть симлинком, а сравнение путей без разрешения ссылок дало бы
// «не совпадает» на том же самом файле.
func resolveSelf() (selfID, error) {
	exe, err := os.Executable()
	if err != nil {
		return selfID{}, fmt.Errorf("os.Executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	exe = filepath.Clean(exe)
	if exe == "" || exe == "." {
		return selfID{}, fmt.Errorf("пустой путь исполняемого файла")
	}
	return selfID{exePath: exe, exeDir: filepath.Dir(exe)}, nil
}

// matchesRequest проверяет присланный СЕЛЕКТОР. Возвращает признак срабатывания
// (для лога и для оператора) либо "" — не мы.
func (s selfID) matchesRequest(req Request) string {
	return s.match(req.Name, req.UninstallID, req.InstallLocation, "")
}

// matchesSoftware проверяет ФАКТИЧЕСКИ найденную в снимке запись. Здесь доступен
// ещё и издатель, которого в селекторе нет.
func (s selfID) matchesSoftware(sw collector.Software) string {
	return s.match(sw.Name, sw.UninstallID, sw.InstallLocation, sw.Vendor)
}

func (s selfID) match(name, uninstallID, installLocation, vendor string) string {
	if isSelfName(name) {
		return "имя: " + name
	}
	// Машинный ключ: на Linux это имя пакета (routineops-agent), на Windows —
	// имя подключа реестра, на macOS — bundle id. Совпадение с любым из наших
	// имён трактуем как попадание в себя.
	if isSelfName(uninstallID) {
		return "ключ: " + uninstallID
	}
	if vendor != "" && strings.EqualFold(strings.TrimSpace(vendor), selfVendor) {
		return "издатель: " + vendor
	}
	// Путь — самый надёжный признак: он не зависит ни от имени в реестре, ни от
	// того, как продукт зарегистрирован. Срабатывает в обе стороны: цель может
	// быть как каталогом, СОДЕРЖАЩИМ наш бинарь (Program Files\RoutineOps), так
	// и самим бинарём.
	if installLocation != "" {
		if pathCovers(installLocation, s.exePath) || pathCovers(installLocation, s.exeDir) {
			return "путь: " + installLocation
		}
		if samePath(installLocation, s.exePath) || samePath(installLocation, s.exeDir) {
			return "путь: " + installLocation
		}
	}
	return ""
}

func isSelfName(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false
	}
	for _, n := range selfNames {
		if v == n {
			return true
		}
	}
	return false
}

// pathCovers — лежит ли child внутри parent (или это один и тот же путь).
//
// Сравнение ВСЕГДА регистронезависимое, независимо от ОС. Это осознанная
// асимметрия: на Linux пути регистрозависимы, и формально /Opt/RoutineOps —
// не /opt/RoutineOps. Но ошибка guard'а несимметрична по цене. Лишнее
// срабатывание = оператор не смог удалить одну программу и увидел внятную
// причину. Пропуск = снесённый агент на всём парке. Поэтому в спорную сторону
// guard ошибается всегда в пользу отказа.
func pathCovers(parent, child string) bool {
	p, c := normPath(parent), normPath(child)
	if p == "" || c == "" {
		return false
	}
	if p == c {
		return true
	}
	// Разделитель обязателен, иначе /opt/routineops-data накрыл бы /opt/routineops.
	return strings.HasPrefix(c, p+string(filepath.Separator))
}

func samePath(a, b string) bool {
	na, nb := normPath(a), normPath(b)
	return na != "" && na == nb
}

// normPath приводит путь к сравнимому виду: разделители к платформенным, лишние
// сегменты убраны, регистр сложен, хвостовой разделитель снят (ARP-записи
// Windows приезжают и с ним, и без него).
func normPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.Clean(filepath.FromSlash(strings.ReplaceAll(p, `\`, "/")))
	p = strings.TrimSuffix(p, string(filepath.Separator))
	return strings.ToLower(p)
}
