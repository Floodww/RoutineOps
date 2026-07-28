package uninstall

import "testing"

// Отрицательные случаи здесь важнее положительных: каждое пропущенное значение
// уезжает в argv процесса, запускаемого от LocalSystem/root.
func TestValidPackageName(t *testing.T) {
	good := []string{
		"routineops-agent", "libc6", "python3.11", "g++", "linux_headers",
		"7zip", "gtk+3.0",
	}
	for _, s := range good {
		if !validPackageName(s) {
			t.Errorf("реальное имя пакета отвергнуто: %q", s)
		}
	}
	bad := []string{
		"",
		"-y",               // опция менеджера, а не пакет
		"--assume-yes",     //
		"пакет",            // не ASCII: настоящих таких имён нет, а кодировка в argv непредсказуема
		"pkg>=1.2",         // спецификатор версии
		"pkg;rm -rf /",     // разделитель команд
		"pkg name",         // два аргумента вместо одного
		"pkg\nname",        //
		"$(whoami)",        // подстановка
		"`id`",             //
		"pkg&&echo",        //
		"../../etc/passwd", // путь
		".hidden",          // первый символ не буква/цифра
		"_pkg",             //
	}
	for _, s := range bad {
		if validPackageName(s) {
			t.Errorf("недопустимое значение пропущено в argv пакетного менеджера: %q", s)
		}
	}
}

func TestLooksLikeProductCode(t *testing.T) {
	good := []string{
		"{42488912-25F8-4C42-AE88-DF4D50E17832}",
		"{00000000-0000-0000-0000-000000000000}",
		"{abcdef01-2345-6789-abcd-ef0123456789}",
	}
	for _, s := range good {
		if !looksLikeProductCode(s) {
			t.Errorf("валидный ProductCode отвергнут: %q", s)
		}
	}
	bad := []string{
		"",
		"42488912-25F8-4C42-AE88-DF4D50E17832",  // без скобок
		"{42488912-25F8-4C42-AE88-DF4D50E1783}", // короче на символ
		"{42488912-25F8-4C42-AE88-DF4D50E178322}", // длиннее
		"{42488912_25F8_4C42_AE88_DF4D50E17832}",  // не те разделители
		"{4248891G-25F8-4C42-AE88-DF4D50E17832}",  // не hex
		"{42488912-25F8-4C42-AE88-DF4D50E17832",   // без закрывающей
		"Google Chrome",                           // имя подключа не-MSI записи
		"{../../evil}",
	}
	for _, s := range bad {
		if looksLikeProductCode(s) {
			t.Errorf("недопустимое значение пропущено в argv msiexec: %q", s)
		}
	}
}

func TestValidRegistryKeyName(t *testing.T) {
	good := []string{"Google Chrome", "{42488912-25F8-4C42-AE88-DF4D50E17832}", "7-Zip_is1"}
	for _, s := range good {
		if !validRegistryKeyName(s) {
			t.Errorf("реальное имя подключа отвергнуто: %q", s)
		}
	}
	// Разделители пути означают выход в чужую ветку реестра: имя подставляется
	// в путь конкатенацией.
	bad := []string{"", "   ", `..\..\Policies`, "Chrome/Sub", `Chrome\Sub`}
	for _, s := range bad {
		if validRegistryKeyName(s) {
			t.Errorf("имя подключа с выходом за ветку пропущено: %q", s)
		}
	}
}
