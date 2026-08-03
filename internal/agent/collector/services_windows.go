//go:build windows

package collector

import (
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Срез служб Windows.
//
// Один проход по HKLM\SYSTEM\CurrentControlSet\Services нативным пакетом registry —
// тот же приём, что в collector_windows.go, где от PowerShell отказались из-за
// кириллицы в выводе.
//
// Сознательно НЕ через svc/mgr: ListServices + OpenService + Config + Query это три
// хэндла на каждую из примерно семисот служб, и часть из них отдаёт ACCESS_DENIED
// даже под LocalSystem — снимок получался бы дырявым и медленным. Реестр читается
// целиком одним обходом и содержит ровно определение, которое нам и нужно.

// Системные каталоги: определение под ними означает, что службу ставит и обновляет
// сама ОС. Признак идёт в атрибуцию: изменение такой службы почти всегда фоновое
// обновление, а не действие человека с временными правами.
var windowsSystemPrefixes = []string{
	`%systemroot%\system32`,
	`\systemroot\system32`,
	`c:\windows\system32`,
	`\??\c:\windows\system32`,
	`system32\`,
	`\systemroot\`,
	`%systemroot%\`,
	`c:\windows\`,
}

func osServices() ([]Service, Health) {
	root, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, HealthFailed
	}
	defer root.Close()

	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, HealthFailed
	}
	sort.Strings(names)

	out := make([]Service, 0, len(names))
	var failed int
	for _, name := range names {
		k, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
		if err != nil {
			// Отдельная недоступная служба — деградация снимка, а не провал:
			// пустой список тут был бы хуже неполного, потому что читался бы
			// как «на машине ничего не менялось».
			failed++
			continue
		}
		svc, ok := readWindowsService(k, name)
		k.Close()
		if ok {
			out = append(out, svc)
		}
	}

	sortServices(out)
	switch {
	case len(out) == 0:
		return out, HealthFailed
	case failed > 0:
		return out, HealthPartial
	default:
		return out, HealthOK
	}
}

func readWindowsService(k registry.Key, name string) (Service, bool) {
	// Start обязателен: подключи без него — не службы, а хранилища параметров
	// (Eventlog, WinSock и подобные), и тащить их в дельту значило бы засорять
	// её записями, которые никто не ставил.
	start, _, err := k.GetIntegerValue("Start")
	if err != nil {
		return Service{}, false
	}
	svcType, _, _ := k.GetIntegerValue("Type")
	delayed, _, _ := k.GetIntegerValue("DelayedAutostart")
	imagePath, _, _ := k.GetStringValue("ImagePath")
	display, _, _ := k.GetStringValue("DisplayName")
	account, _, _ := k.GetStringValue("ObjectName")
	group, _, _ := k.GetStringValue("Group")

	svc := Service{
		Name:      name,
		Display:   display,
		StartType: startTypeFromDWORD(start, delayed == 1),
		Account:   account,
		ImagePath: imagePath,
		Kind:      kindFromServiceType(svcType),
		OSOwned:   isUnderAny(imagePath, windowsSystemPrefixes),
	}
	// DefHash по значимым значениям, а не по всему подключу: в подключе живут и
	// волатильные счётчики (например, статистика запусков у части служб), и они
	// давали бы ложную дельту на каждом снимке.
	svc.DefHash = hashDefinition([]byte(strings.Join([]string{
		imagePath, display, account, group,
		svc.StartType, svc.Kind,
	}, "\x00")))
	return svc, true
}
