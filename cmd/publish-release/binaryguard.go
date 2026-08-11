package main

import (
	"debug/buildinfo"
	"fmt"
	"os"
)

// Гейт «то ли мы вообще публикуем».
//
// 🔴 Полевой случай 10.08.2026, и он худшего класса из возможных здесь. На проде забирали
// канареечный бинарь через API с пустым токеном:
//
//	curl -H "Authorization: Bearer $GH_TOKEN" … -o agent_windows_amd64_v2.6.7-enterprise.exe
//
// GitHub ответил 112 байтами `{"message":"Bad credentials"}`, curl честно положил их в файл
// с именем агента — и publish-release ОПУБЛИКОВАЛ ЭТОТ JSON: посчитал sha256, подписал
// релизным ключом, скопировал в releases/ и зарегистрировал версией v2.6.7.
//
// Дальше цепочка защит работает ПРОТИВ нас, потому что каждое её звено исправно: агент
// скачает 112 байт, сверит sha256 (совпадёт — мы сами её и посчитали), проверит подпись
// манифеста (валидна — мы сами и подписали), заменит свой exe и перезапустится. То есть
// подписанный мусор раздаётся парку как настоящий релиз, и ни один гейт по пути не
// возражает. Ровно то, о чём говорит комментарий выше про darwin: «подписанный битый
// бинарь уже не отличить от рабочего».
//
// Поэтому проверка стоит ДО подписи и спрашивает самое дешёвое и самое надёжное: похоже ли
// содержимое на исполняемый файл заявленной ОС. Формат — это не эвристика вроде размера:
// PE, ELF и Mach-O опознаются по первым байтам однозначно.
func requireExecutable(path, goos string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	var head [4]byte
	n, _ := f.Read(head[:])
	if n < 4 {
		return fmt.Errorf("%s: файл %d байт — это не бинарь агента", path, fi.Size())
	}

	ok := false
	switch goos {
	case "windows":
		// PE начинается с DOS-заголовка «MZ».
		ok = head[0] == 'M' && head[1] == 'Z'
	case "linux":
		ok = head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F'
	case "darwin":
		// Mach-O 64-бит (LE/BE) и universal binary.
		switch {
		case head[0] == 0xCF && head[1] == 0xFA && head[2] == 0xED && head[3] == 0xFE,
			head[0] == 0xFE && head[1] == 0xED && head[2] == 0xFA && head[3] == 0xCF,
			head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE:
			ok = true
		}
	default:
		return fmt.Errorf("неизвестный GOOS %q — публиковать нечего", goos)
	}
	if !ok {
		// Первые байты в сообщение: у скачанной ошибки API это «{"me…», и причина
		// становится очевидной прямо здесь, без похода в файл.
		return fmt.Errorf("%s: не похоже на исполняемый файл для %s (%d байт, начинается с %q) — "+
			"вероятно, скачалась ошибка API или HTML вместо бинаря",
			path, goos, fi.Size(), string(head[:]))
	}

	// Вторая проверка: это сборка Go нашего проекта, а не любой чужой exe. Отсекает
	// подмену пути и «положили не тот файл» — buildinfo есть в каждом нашем бинаре.
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: не читается buildinfo — это не сборка Go: %w", path, err)
	}
	if bi.Path == "" && bi.Main.Path == "" {
		return fmt.Errorf("%s: в buildinfo нет модуля — публикуется не наш бинарь", path)
	}
	return nil
}
