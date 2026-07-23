package main

// Схема YAML-конфигурации парка. Что версионируется в git и чем управляет apply:
// группы, их софт-правила, скрипты и скрипт-политики.
//
// 🔴 Устройств здесь нет и не будет. Разделение намеренное: YAML описывает ИНТЕНТ
// («что и кому»), а членство устройств в группах решает энроллмент (токен несёт группу)
// и ручные перемещения в UI. Иначе YAML пришлось бы править на каждую новую машину, и
// git-история конфигурации утонула бы в инвентаре.
//
// Идентичность ресурса — ИМЯ (уникальные индексы: device_groups в миграции 026,
// scripts и policies в 033). Поэтому файл переносим между инсталляциями, а diff в git
// читается человеком: id в YAML не попадают.

const apiVersion = "routineops/v1"

type Config struct {
	APIVersion     string         `yaml:"apiVersion"`
	Groups         []Group        `yaml:"groups,omitempty"`
	Scripts        []Script       `yaml:"scripts,omitempty"`
	ScriptPolicies []ScriptPolicy `yaml:"scriptPolicies,omitempty"`
}

type Group struct {
	Name  string `yaml:"name"`
	Color string `yaml:"color,omitempty"`
	// Software — софт-правила, привязанные именно к этой группе. Глобальные правила и
	// правила на конкретное устройство в YAML не выгружаются: первые не принадлежат ни
	// одной группе, вторые — тот же инвентарь, что и членство.
	Software []SoftwareRule `yaml:"software,omitempty"`
	// ScriptPolicies — имена скрипт-политик, назначенных группе. Привязка живёт на
	// стороне группы, а не политики: так в файле одной группы видно всё, что на неё
	// действует, и `apply -f accounting.yaml` остаётся осмысленным сам по себе.
	ScriptPolicies []string `yaml:"scriptPolicies,omitempty"`
}

type SoftwareRule struct {
	Name string `yaml:"name"`
	Rule string `yaml:"rule"` // allowed | forbidden
}

type Script struct {
	Name     string `yaml:"name"`
	Platform string `yaml:"platform"`
	// File — путь к телу скрипта относительно YAML-файла. Тело держим отдельным файлом,
	// а не инлайном: в git diff по скрипту читается построчно, подсветка синтаксиса
	// работает, и правка скрипта не переписывает YAML целиком. Content — запасной путь
	// для маленьких однострочников; заполнено ровно одно из двух.
	File    string `yaml:"file,omitempty"`
	Content string `yaml:"content,omitempty"`
}

type ScriptPolicy struct {
	Name    string `yaml:"name"`
	Script  string `yaml:"script"` // имя скрипта, не id
	Trigger string `yaml:"trigger"`
	// Schedule/Event — конфиги триггера как есть. map, а не типизированная структура:
	// формат задаёт сервер, и CLI не должен разъезжаться с ним на каждое новое поле.
	Schedule map[string]any `yaml:"schedule,omitempty"`
	Event    map[string]any `yaml:"event,omitempty"`
	Active   bool           `yaml:"active"`
}
