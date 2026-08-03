package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
)

// Состояние сессии временных админ-прав на диске.
//
// Зачем на диске. Сегодня всё состояние гранта живёт в полях Manager и не
// переживает даже рестарт агента: после него lastReqID пуст, IsAdmin(user) видит
// УЖЕ выданное членство и ставит wasAdmin=true — а значит revoke() посчитает права
// собственными правами пользователя и не снимет их никогда. Временный грант
// становится постоянным молча.
//
// Второе назначение — базовая линия аудита сессии: срез ПО и служб на момент
// выдачи прав. Без него дельту сессии не от чего считать, а сессия штатно
// переживает и ребут, и сон машины.
//
// ПОЧЕМУ 0600 И DataDir. В файле лежит полный список установленного на машине ПО.
// Каталог обязан быть тем же защищённым DataDir, где живут остальные состояния
// агента (на Windows — ProgramData\RoutineOps\state с admin-only DACL). Если
// вызывающий передал другой каталог, устойчивая базовая линия ВЫКЛЮЧАЕТСЯ целиком
// (см. NewSessionStore) — тот же fail-closed, что уже сделан для durable-памяти
// разблокировки: лучше остаться без базовой линии и честно сказать об этом, чем
// разложить список ПО пользователя там, куда указал произвольный флаг.

// SoftFP — отпечаток одной записи инвентаря ПО. Короткие теги json не ради
// экономии места, а ради предсказуемого размера файла на машинах с тысячами
// пакетов: полные имена полей удваивали бы его.
type SoftFP struct {
	Key     string `json:"k"` // UninstallID, иначе имя+вендор — устойчивый ключ записи
	Name    string `json:"n"`
	Version string `json:"v"`
	Vendor  string `json:"vn"`
	Scope   string `json:"sc"`
}

// SvcFP — отпечаток определения одной службы.
type SvcFP struct {
	Key       string `json:"k"`
	Display   string `json:"d"`
	StartType string `json:"st"`
	Account   string `json:"a"`
	ImagePath string `json:"p"`
	DefHash   string `json:"h"`
	OSOwned   bool   `json:"o"`
	Kind      string `json:"kd"`
}

// SessionState — то, что обязано пережить рестарт агента и ребут машины.
type SessionState struct {
	RequestID string    `json:"rid"`
	User      string    `json:"u"`
	Expires   time.Time `json:"exp"` // нулевое = бессрочная заявка (до логаута)
	WasAdmin  bool      `json:"wa"`  // был ли админом ДО гранта — тогда права не снимаем
	GrantedAt time.Time `json:"ga"`

	// BootTime — время загрузки на момент снятия базовой линии. Расхождение с
	// текущим означает ребут внутри сессии: это не ошибка, но оператор обязан
	// видеть признак, потому что часть изменений могла приехать с обновлениями,
	// применёнными при перезагрузке.
	BootTime int64 `json:"bt"`

	// WindowSeq — номер последнего отправленного окна. Монотонный счётчик нужен
	// только для нумерации; фильтром отбрасывания на сервере он быть НЕ ДОЛЖЕН,
	// иначе одно окно с завышенным номером заглушило бы все последующие.
	WindowSeq int32 `json:"seq"`

	// Collect — сбор улик, ЗАЩЁЛКНУТЫЙ на момент выдачи прав.
	//
	// Флаг сервера читается каждый поллинг, но решение по сессии принимается ровно
	// один раз — в grant() — и дальше не пересматривается. Иначе оператор,
	// щёлкнувший выключателем посреди сессии, ломал бы подотчётность в обе стороны:
	//
	//   выключил на живой сессии — базовая линия уже снята, а финального окна нет;
	//     на сервере это неотличимо от дыры, и выключатель начинает сам производить
	//     тот алерт, ради которого дыры и ищут;
	//   включил на живой сессии — базовой линии нет и взять её неоткуда, дельту
	//     считать не от чего, и окна поехали бы «мы не знаем» на ровном месте.
	//
	// Защёлка false означает и то, что срез инвентаря на выдаче НЕ снимается вовсе:
	// платить обходом реестра и каталогов за данные, которые никто не просил, незачем.
	Collect bool `json:"col"`

	// LastWindowDigest — отпечаток последнего ОТПРАВЛЕННОГО окна. Промежуточное
	// окно с тем же отпечатком не шлётся: окна кумулятивны, повтор того же списка
	// под новым номером не добавляет серверу ни одного факта, зато множит строки
	// улик на каждую тихую сессию. Финального окна это не касается — его
	// отсутствие само по себе событие.
	LastWindowDigest string `json:"wd"`

	// Здоровье сбора базовой линии. Хранится, потому что дельта, посчитанная от
	// неполного среза, недостоверна — и об этом надо сказать, а не показать
	// короткий список как полный.
	SoftwareHealth string `json:"swh"`
	ServicesHealth string `json:"svch"`

	// Базовая линия t0. За сессию НЕ ПЕРЕБАЗИРУЕТСЯ: окна считаются кумулятивно
	// от неё, поэтому потеря промежуточного отчёта самоизлечивается следующим.
	// Инкрементальные окна превращали бы её в невидимую дыру, поверх которой
	// финальное окно нарисовало бы уверенный полный список.
	Software []SoftFP `json:"sw"`
	Services []SvcFP  `json:"svc"`
}

// Rebooted — была ли машина перезагружена с момента снятия базовой линии.
func (s *SessionState) Rebooted(currentBootTime int64) bool {
	if s == nil || s.BootTime == 0 || currentBootTime == 0 {
		return false // не знаем — не утверждаем
	}
	return s.BootTime != currentBootTime
}

// ErrNoDurableState — устойчивое состояние отключено, потому что каталог не
// совпал с защищённым DataDir. Не ошибка выполнения: вызывающий обязан
// продолжить работу, пометив базовую линию потерянной.
var ErrNoDurableState = errors.New("admin: устойчивое состояние сессии отключено (каталог вне DataDir)")

// SessionStore — доступ к состоянию сессии на диске.
type SessionStore struct {
	path string // "" = устойчивое состояние отключено
}

// NewSessionStore проверяет, что каталог состояния — тот самый защищённый DataDir,
// и только тогда включает запись. Несовпадение выключает устойчивость целиком,
// а не «пишет куда сказали»: файл со списком ПО пользователя не должен уезжать
// туда, куда указал переопределяемый оператором флаг.
func NewSessionStore(stateDir, dataDir string) *SessionStore {
	if stateDir == "" || dataDir == "" {
		return &SessionStore{}
	}
	a, err1 := filepath.Abs(stateDir)
	b, err2 := filepath.Abs(dataDir)
	if err1 != nil || err2 != nil || a != b {
		return &SessionStore{}
	}
	return &SessionStore{path: filepath.Join(a, "admin-session.json")}
}

// Durable — включена ли устойчивая базовая линия.
func (s *SessionStore) Durable() bool { return s != nil && s.path != "" }

// Load читает состояние. Отсутствие файла — не ошибка: (nil, nil).
func (s *SessionStore) Load() (*SessionState, error) {
	if !s.Durable() {
		return nil, ErrNoDurableState
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("чтение состояния сессии: %w", err)
	}
	var st SessionState
	if err := json.Unmarshal(body, &st); err != nil {
		// Битый файл не должен блокировать выдачу прав навсегда: сообщаем и
		// работаем как без базовой линии.
		return nil, fmt.Errorf("разбор состояния сессии: %w", err)
	}
	return &st, nil
}

// Save пишет состояние атомарно (tmp + rename) с правами 0600.
//
// Атомарность здесь не украшение: файл читается на старте агента, и оборванная
// запись (ребут ровно в этот момент) оставила бы состояние, по которому права
// уже выданы, но снять их некому.
func (s *SessionStore) Save(st *SessionState) error {
	if !s.Durable() {
		return ErrNoDurableState
	}
	body, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("сериализация состояния сессии: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".admin-session-*.tmp")
	if err != nil {
		return fmt.Errorf("временный файл состояния сессии: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op после успешного rename

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("права на состояние сессии: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("запись состояния сессии: %w", err)
	}
	// Sync до rename: без него ребут сразу после переименования может оставить
	// файл нужной длины с нулевыми байтами внутри.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("сброс состояния сессии на диск: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("закрытие состояния сессии: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("публикация состояния сессии: %w", err)
	}
	return nil
}

// Clear удаляет состояние: сессия закончена.
func (s *SessionStore) Clear() error {
	if !s.Durable() {
		return nil
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("удаление состояния сессии: %w", err)
	}
	return nil
}

// Snapshot снимает базовую линию: ПО и службы одним заходом.
// Здоровье каждого источника возвращается отдельно — «не смогли посмотреть» и
// «ничего не нашли» обязаны различаться.
func Snapshot(software func() ([]collector.Software, error), services func() ([]collector.Service, collector.Health)) ([]SoftFP, string, []SvcFP, string) {
	swHealth := string(collector.HealthOK)
	sw, err := software()
	if err != nil {
		swHealth = string(collector.HealthFailed)
	}
	softFPs := make([]SoftFP, 0, len(sw))
	for _, s := range sw {
		softFPs = append(softFPs, SoftFP{
			Key:     softwareKey(s),
			Name:    s.Name,
			Version: s.Version,
			Vendor:  s.Vendor,
			Scope:   s.Scope,
		})
	}

	svcs, svcHealth := services()
	svcFPs := make([]SvcFP, 0, len(svcs))
	for _, s := range svcs {
		svcFPs = append(svcFPs, SvcFP{
			Key:       s.Name,
			Display:   s.Display,
			StartType: s.StartType,
			Account:   s.Account,
			ImagePath: s.ImagePath,
			DefHash:   s.DefHash,
			OSOwned:   s.OSOwned,
			Kind:      s.Kind,
		})
	}
	return softFPs, swHealth, svcFPs, string(svcHealth)
}

// defaultSnapshot — боевой сбор базовой линии.
//
// collector.InstalledSoftware() ошибку не возвращает: при отказе источника он
// отдаёт пустой список. Для аудита это опасная неоднозначность — пустой срез
// прочитался бы как «на машине не установлено ничего», и вся дельта сессии
// оказалась бы «сотрудник поставил всё, что мы видим в конце». Поэтому пустой
// список трактуем как неудачу сбора: машин без единой записи инвентаря не бывает.
func defaultSnapshot() ([]SoftFP, string, []SvcFP, string) {
	return Snapshot(func() ([]collector.Software, error) {
		sw := collector.InstalledSoftware()
		if len(sw) == 0 {
			return nil, errEmptyInventory
		}
		return sw, nil
	}, collector.Services)
}

var errEmptyInventory = errors.New("admin: инвентарь ПО пуст — считаю сбор неудавшимся")

// softwareKey — устойчивый ключ записи ПО. UninstallID предпочтительнее: он
// переживает смену версии, тогда как имя+версия дали бы «удалено старое,
// установлено новое» на каждом фоновом обновлении.
func softwareKey(s collector.Software) string {
	if s.UninstallID != "" {
		return s.UninstallID
	}
	return s.Name + "\x00" + s.Vendor
}
