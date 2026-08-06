package decommission

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWxsContract ловит дрейф констант decommission относительно MSI-манифеста
// build/msi/mdm-agent.wxs. Если правка wxs (смена UpgradeCode, ренейм exe/каталога,
// смена Run-ключа) разойдётся с этими константами, resolveProductCode вернёт ok=false
// (msiexec /x тихо пропустится → ARP-хвост вернётся) или снос каталога перестанет
// узнавать наш путь — симптом неотличим от исходного бага и ничем не сигналит.
// Тест без build-тега: сверка идёт на любом `go test`, не только на Windows.
func TestWxsContract(t *testing.T) {
	root := skipOutsideRepo(t)
	wxsPath := filepath.Join(root, "build", "msi", "mdm-agent.wxs")
	raw, err := os.ReadFile(wxsPath)
	if err != nil {
		t.Fatalf("не прочитать wxs %s: %v", wxsPath, err)
	}
	wxs := string(raw)

	checks := []struct {
		what   string
		expect string // подстрока, обязанная присутствовать в wxs
	}{
		// UpgradeCode в wxs — без фигурных скобок; в константе они есть (нужны MsiEnumRelatedProducts).
		{"upgradeCode", `UpgradeCode="` + strings.Trim(upgradeCode, "{}") + `"`},
		{"agentImageName (File Name)", `Name="` + agentImageName + `"`},
		{"installDirName (Directory INSTALLFOLDER Name)", `Name="` + installDirName + `"`},
		{"runKeyPath (RegistryValue Key)", `Key="` + runKeyPath + `"`},
		{"trayRunValue (RegistryValue Name)", `Name="` + trayRunValue + `"`},
	}
	for _, c := range checks {
		if !strings.Contains(wxs, c.expect) {
			t.Errorf("дрейф %s: в %s нет %q — константа разошлась с MSI-манифестом; "+
				"decommission перестанет узнавать установку (msiexec /x пропустится → ARP-хвост)",
				c.what, wxsPath, c.expect)
		}
	}
}

// Скрипт ручного снятия обязан ЕХАТЬ НА ДИСК и снимать трей перед сносом каталога.
//
// Оба пункта поймано в поле, и оба выглядят одинаково — «удаление не работает»:
//
//  1. Батника в %ProgramFiles%\RoutineOps не было вовсе: MSI его не клал. Администратор
//     шёл искать файл в исходниках и копировал текстом из браузера — а копипаст ломает
//     переносы строк, и cmd.exe разбирает файл со сдвигом (см. проверку CRLF в
//     scripts/check-installer-versions.sh).
//  2. Батник сносил каталог, не сняв трей. Трей не служба, живёт в сессии пользователя и
//     держит RoutineOps-agent.exe открытым — rmdir отвечал «Отказано в доступе», каталог
//     оставался, а скрипт при этом печатал «Готово».
//
// Оба авторинга проверяются вместе: боевой уезжает в поле, валидатор собирается в CI, и
// разойтись они не должны.
func TestUninstallScriptShipsAndKillsTray(t *testing.T) {
	root := skipOutsideRepo(t)

	for _, wxs := range []string{
		filepath.Join(root, "build", "msi", "mdm-agent.wxs"),
		filepath.Join(root, "installer", "windows", "agent.wxs"),
	} {
		raw, err := os.ReadFile(wxs)
		if err != nil {
			t.Fatalf("не прочитать wxs %s: %v", wxs, err)
		}
		if !strings.Contains(string(raw), `Name="uninstall.bat"`) {
			t.Errorf("%s не кладёт uninstall.bat в каталог установки: администратору снова "+
				"придётся искать его в исходниках и копировать из браузера", wxs)
		}
	}

	batPath := filepath.Join(root, "build", "msi", "uninstall.bat")
	bat, err := os.ReadFile(batPath)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", batPath, err)
	}
	text := string(bat)

	kill := strings.Index(text, "taskkill /F /IM "+agentImageName)
	if kill < 0 {
		t.Fatalf("%s не снимает процессы агента: трей держит exe, и rmdir получит "+
			"«Отказано в доступе»", batPath)
	}
	// ПОРЯДОК, а не просто наличие: taskkill после rmdir бесполезен ровно так же, как его
	// отсутствие, — каталог к тому моменту уже не удалился.
	rm := strings.Index(text, `rmdir /s /q "%ProgramFiles%\RoutineOps"`)
	if rm < 0 {
		t.Fatalf("%s не сносит каталог установки", batPath)
	}
	if kill > rm {
		t.Errorf("в %s taskkill стоит ПОСЛЕ rmdir — к моменту снятия трея каталог уже "+
			"не удалился", batPath)
	}
}

// Каждый `goto :метка` в батнике обязан иметь метку.
//
// 🔴 Поймано на ревью этой самой правки, и симптом страшнее любого из тех, что чинились
// выше: cmd.exe на несуществующей метке печатает «The system cannot find the batch label
// specified» и НЕМЕДЛЕННО прекращает обработку файла. Не пропускает шаг — прекращает
// весь скрипт. Служба остаётся, защита остаётся, регистрация остаётся, `exit /b` не
// выполняется, и администратор видит одну строку по-английски посреди русского вывода.
//
// Правка при этом выглядит нормальной в диффе и проходит все проверки на подстроки:
// текст шагов на месте, порядок верный, CRLF верный. Структуру батника не проверял никто.
func TestUninstallScriptLabelsResolve(t *testing.T) {
	root := skipOutsideRepo(t)
	batPath := filepath.Join(root, "build", "msi", "uninstall.bat")
	raw, err := os.ReadFile(batPath)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", batPath, err)
	}

	labels := map[string]bool{}
	var jumps []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if strings.HasPrefix(line, ":") && !strings.HasPrefix(line, "::") {
			// Метка — первое слово строки, начинающейся с двоеточия.
			labels[strings.ToLower(strings.Fields(line)[0][1:])] = true
			continue
		}
		low := strings.ToLower(line)
		if !strings.HasPrefix(low, "goto ") && !strings.Contains(low, " goto ") {
			continue
		}
		fields := strings.Fields(low)
		for i, f := range fields {
			if f != "goto" || i+1 >= len(fields) {
				continue
			}
			target := strings.TrimPrefix(fields[i+1], ":")
			if target != "" && target != "eof" { // :eof — встроенная метка cmd.exe
				jumps = append(jumps, target)
			}
		}
	}

	if len(jumps) == 0 {
		t.Fatalf("%s: не найдено ни одного goto — тест перестал проверять то, ради чего написан", batPath)
	}
	for _, j := range jumps {
		if !labels[j] {
			t.Errorf("%s: `goto :%s` ведёт в никуда — cmd.exe напечатает «cannot find the batch label» "+
				"и ОБОРВЁТ выполнение скрипта: агент не снимется вовсе", batPath, j)
		}
	}
}

// Ручное снятие обязано снимать РЕГИСТРАЦИЮ УСТАНОВЩИКА, а не только службу и файлы.
//
// 🔴 Поймано в поле. Батник снимал службу, файлы и ключи реестра, но не трогал запись
// продукта в базе Windows Installer. Она оставалась сиротой: в «Установка и удаление
// программ» агент числится установленным, хотя на диске от него ничего нет. Следующая
// установка ТОГО ЖЕ пакета видит Installed=true, уходит в режим обслуживания и не
// выполняет ни Launch-условие на пять обязательных свойств (при Installed=true оно
// проходит по левой части), ни EnrollExec (NOT Installed OR REINSTALL). Итог: msiexec
// отдаёт 0, а на машине нет ни службы, ни сертов — молчаливый успех при нулевом
// результате. Самоснос по команде сервера делает это правильно с самого начала
// (buildDeleterScript зовёт msiexec /x по ProductCode из resolveProductCode);
// расходились именно два пути снятия.
func TestUninstallScriptUnregistersMSI(t *testing.T) {
	root := skipOutsideRepo(t)
	batPath := filepath.Join(root, "build", "msi", "uninstall.bat")
	raw, err := os.ReadFile(batPath)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", batPath, err)
	}
	text := string(raw)

	// 🔴 Комментарии ВЫРЕЗАЕМ перед поиском. Иначе тест держит не контракт, а пояснение
	// к нему: удали кто-нибудь сам вызов, оставив REM-абзац про него, — тест остался бы
	// зелёным, а полевой баг вернулся целиком. Обратная беда та же: перенеси этот REM в
	// шапку файла — и проверка порядка заругалась бы на корректный батник.
	var live []string
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); !strings.HasPrefix(strings.ToUpper(trimmed), "REM") {
			live = append(live, line)
		}
	}
	code := strings.Join(live, "\n")

	// Имя подкоманды берём КОНСТАНТОЙ, а не литералом: ренейм в cmd/agent без правки
	// батника дал бы в поле «неизвестная команда» с кодом 2, и снос поехал бы дальше —
	// то есть вернулся бы ровно тот молчаливый провал, который эта команда и чинит.
	if !strings.Contains(code, " "+UnregisterSubcommand) {
		t.Fatalf("%s не снимает регистрацию установщика (нет вызова %q вне комментариев): продукт "+
			"останется числиться установленным при пустом диске, и повторная установка того же "+
			"пакета уйдёт в режим обслуживания — msiexec отдаст 0, а агента не появится",
			batPath, UnregisterSubcommand)
	}
	// Подкоманду обязана запускать КОПИЯ агента под другим именем образа. Запуск
	// установленного exe напрямую убивает сам себя: msiexec /x → UnenrollExec →
	// `agent uninstall` → taskkill /F /IM <имя образа> с фильтром только по своему pid.
	// Регистрация при этом снимается, а батник рапортует отказ — то есть отчёт врёт в
	// обратную сторону, и оператор идёт чинить уже починенное.
	if !strings.Contains(code, `copy /y "%EXE%"`) {
		t.Errorf("%s запускает подкоманду без рабочей копии агента: процесс попадёт под "+
			"собственный `taskkill /F /IM %s` из UnenrollExec", batPath, agentImageName)
	}
	// Точка ПОРЯДКА — место вызова в основном потоке, а не тело подпрограммы: подпрограмма
	// физически лежит в конце файла, после rmdir, и сравнивать позиции с ней бессмысленно.
	unreg := strings.Index(code, "call :unregister")
	if unreg < 0 {
		t.Fatalf("%s: не найден вызов `call :unregister` — проверять порядок шагов не по чему", batPath)
	}

	// ПОРЯДОК, а не наличие. Каждая пара — отдельный способ получить тот же ARP-хвост.
	for _, step := range []struct {
		what   string
		needle string
		before bool // true — шаг обязан идти ДО msi-unregister, false — ПОСЛЕ
		why    string
	}{
		{
			what:   "tamper-cleanup",
			needle: `"%EXE%" tamper-cleanup`,
			before: true,
			why: "msiexec /x удаляет exe — после него tamper-cleanup звать уже нечем, " +
				"и SafeBoot-регистрация останется",
		},
		{
			what:   "sc delete",
			needle: "sc delete RoutineOps-agent",
			before: true,
			why: "до снятия службы она зарегистрирована с FailureActions (рестарт 5с): " +
				"воскресший процесс держал бы exe, и установщику осталось бы только " +
				"отложить удаление до перезагрузки",
		},
		{
			what:   "taskkill трея",
			needle: "taskkill /F /IM " + agentImageName,
			before: true,
			why: "живой трей держит exe открытым — занятый файл msiexec не удаляет, а " +
				"переименовывает в .rbf и откладывает до перезагрузки (тот же порядок " +
				"закреплён в самосносе: msiexec после taskkill)",
		},
		{
			what:   `rmdir каталога установки`,
			needle: `rmdir /s /q "%ProgramFiles%\RoutineOps"`,
			before: false,
			why: "после сноса каталога exe больше нет — вызывать подкоманду нечем, и мы " +
				"возвращаемся ровно к исходному багу: файлов нет, регистрация есть",
		},
	} {
		at := strings.Index(code, step.needle)
		if at < 0 {
			t.Errorf("%s: не найден шаг %s (%q)", batPath, step.what, step.needle)
			continue
		}
		if step.before && at > unreg {
			t.Errorf("в %s шаг %s стоит ПОСЛЕ %s, а обязан до: %s",
				batPath, step.what, UnregisterSubcommand, step.why)
		}
		if !step.before && at < unreg {
			t.Errorf("в %s шаг %s стоит ДО %s, а обязан после: %s",
				batPath, step.what, UnregisterSubcommand, step.why)
		}
	}
}

// Второй Launch-гейт в боевом авторинге: установщик не имеет права молча отдать 0,
// когда свойства энроллмента ПЕРЕДАНЫ, а enroll в этом прогоне не выполнится.
//
// Тест текстовый и намеренно грубый — он не проверяет семантику MSI-условия (её
// проверяет живой прогон в windows-джобе CI), а держит сам факт наличия гейта. Без
// него правка авторинга молча вернула бы «msiexec отдал 0, а ничего не установилось»,
// и отличить это от здоровой установки по коду возврата снова было бы нельзя.
func TestProdWxsFailsLoudOnMaintenanceInstall(t *testing.T) {
	root := skipOutsideRepo(t)
	wxsPath := filepath.Join(root, "build", "msi", "mdm-agent.wxs")
	raw, err := os.ReadFile(wxsPath)
	if err != nil {
		t.Fatalf("не прочитать wxs %s: %v", wxsPath, err)
	}
	wxs := string(raw)

	// Условие целиком, чтобы правка любого конъюнкта была видна. NOT REMOVE и
	// NOT REINSTALL — две независимые оговорки: без первой гейт ронял бы удаление,
	// без второй — штатный повтор enroll через REINSTALL=ALL.
	const gate = `Condition="NOT (Installed AND NOT REINSTALL AND NOT REMOVE AND ` +
		`(ENROLL_URL OR ENROLL_TOKEN OR CA_URL OR CA_SHA256 OR SERVER_ADDR))"`
	if !strings.Contains(wxs, gate) {
		t.Errorf("в %s нет гейта на установку поверх уже зарегистрированного продукта.\n"+
			"Ждали условие:\n  %s\n"+
			"Без него при Installed=true первое Launch-условие проходит по левой части, "+
			"EnrollExec пропускается, и msiexec отдаёт 0 при нулевом результате.", wxsPath, gate)
	}
	// Сообщение обязано вести оператора к рабочей команде, а не просто ругаться:
	// именно REINSTALL=ALL REINSTALLMODE=vomus доводит установку на сиротской записи.
	if !strings.Contains(wxs, "REINSTALL=ALL REINSTALLMODE=vomus") {
		t.Errorf("в %s текст отказа не подсказывает рабочую команду "+
			"(REINSTALL=ALL REINSTALLMODE=vomus) — оператор получит только код 1603", wxsPath)
	}
}
