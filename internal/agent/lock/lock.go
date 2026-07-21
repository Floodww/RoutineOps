// Package lock реализует «блокировку устройства» — запирание машины сотрудника по
// команде администратора (нарушение ИБ, увольнение): на экран выводится
// полноэкранный замок с полем пароля, и пользоваться машиной нельзя, пока не
// введён пароль разблокировки.
//
// Модель разблокировки — оффлайн по хешу. Сервер при блокировке генерирует
// случайный пароль, показывает его плейнтекстом в админке, а агенту присылает
// только его bcrypt-ХЕШ. Сотрудник звонит в IT, IT диктует пароль, сотрудник
// вводит его на замке — агент сверяет с хешем ЛОКАЛЬНО (bcrypt), поэтому разблок
// работает даже без сети. Сервер по сети плейнтекст не гоняет.
//
// Состояние блокировки персистится на диск (машинный каталог), чтобы пережить
// рестарт агента и перезагрузку: на старте Manager.Load() поднимет замок заново.
package lock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Floodww/RoutineOps/internal/agent/service"
)

// DefaultPath — путь к файлу состояния блокировки в машинном каталоге, доступном
// и службе (пишет по команде), и лок-экрану в юзер-сессии (читает/снимает).
// Windows: %ProgramData%\RoutineOps\lock.json. Прочие ОС: временный каталог.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(service.ProgramDataDir(), "RoutineOps", "lock.json")
	}
	return filepath.Join(os.TempDir(), "RoutineOps-agent-lock.json")
}

// ReadState читает состояние блокировки из path (для лок-экрана). Отсутствие файла
// возвращается как ошибка os.ErrNotExist — вызывающий трактует как «не заблокировано».
func ReadState(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

// ClearState помечает устройство разблокированным (пустое состояние).
//
// ВНИМАНИЕ: lock.json создаёт демон (root/SYSTEM); лок-экран юзер-сессии САМ
// вызвать ClearState не может — общий каталог состояния доступен на запись всем
// (EnsureUserWritableDir), но sticky-бит запрещает непривилегированному
// процессу переименовать/заменить чужой существующий файл (полевой баг v1.5.3:
// запись тихо падала permission denied, пароль казался принят, а блокировка
// возвращалась через несколько секунд). Юзер-сессия должна слать запрос через
// WriteUnlockRequest — демон проверит пароль сам и снимет блокировку авторитетно
// (см. processUnlockRequests). ClearState остаётся для вызовов ОТ ИМЕНИ владельца
// файла (демон/служба) и для платформ, где ACL это разрешает (Windows).
func ClearState(path string) error {
	return writeStateAtomic(path, State{})
}

// MarkUnlocked помечает устройство разблокированным, фиксируя в состоянии hash
// лока, пароль которого был РЕАЛЬНО сверен (LastUnlockedHash). Вызывать вместо
// ClearState там, где снятие происходит в обход демона (Windows-оверлей, см.
// lockui_windows.go): по маркеру detectOfflineUnlock отличает легитимное снятие
// ТЕКУЩЕГО лока от гонки со сменой лока — оверлей, поднятый под старый hash H1,
// мог сверить пароль H1 и затереть файл уже ПОСЛЕ того, как демон применил новый
// лок H2; без маркера демон принял бы это за снятие H2, задурабилил бы
// LastUnlockedHash=H2 и реконсиляция никогда бы не пере-заперла устройство.
func MarkUnlocked(path, verifiedHash string) error {
	return writeStateAtomic(path, State{LastUnlockedHash: verifiedHash})
}

// unlockRequest — запрос на разблокировку от лок-экрана (юзер-сессия) демону
// (владелец lock.json). Пароль плейлекстом, но живёт на диске мгновение: демон
// вычитывает и сразу удаляет файл (см. processUnlockRequests), а сам файл
// создаётся с правами 0o600 — читает либо создавший его юзер, либо root.
type unlockRequest struct {
	Password string `json:"password"`
}

// unlockRequestPrefix — префикс имени файла-запроса в общем каталоге состояния.
const unlockRequestPrefix = "unlock-request-"

// WriteUnlockRequest кладёt в dir (общий каталог состояния) запрос на
// разблокировку паролем — вызывать из лок-экрана юзер-сессии после локальной
// сверки bcrypt (см. package-doc ClearState, почему нельзя писать lock.json
// напрямую). Имя файла уникально (os.CreateTemp) — новый файл процесс создаёт
// сам, поэтому sticky-бит каталога не мешает, в отличие от переименования
// существующего чужого lock.json.
func WriteUnlockRequest(dir, password string) error {
	f, err := os.CreateTemp(dir, unlockRequestPrefix+"*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	err = json.NewEncoder(f).Encode(unlockRequest{Password: password})
	closeErr := f.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	return closeErr
}

// State — персистентное состояние блокировки (на диске машинного каталога).
type State struct {
	Locked    bool   `json:"locked"`
	Hash      string `json:"hash"`       // bcrypt-хеш пароля разблокировки (плейнтекста НЕТ)
	Reason    string `json:"reason"`     // текст для сотрудника на экране замка
	RequestID string `json:"request_id"` // id заявки на блокировку (идемпотентность, отчёт)
	LockedAt  int64  `json:"locked_at"`  // unix-время блокировки
	// LastUnlockedHash — hash лока, снятого ЛОКАЛЬНО (верный пароль/оффлайн-
	// обнаружение). Переживает рестарт/ребут, чтобы реконсиляция после старта не
	// пере-заперла устройство по УСТАРЕВШЕМУ desired=locked, пока сервер не догнал
	// durable UNLOCKED-отчёт (in-memory lastUnlockedHash реконсилятора при ребуте
	// теряется — это и был баг). Безопасно лежит бессрочно: hash уникален на лок
	// (bcrypt случайной соли), тот же самый сервер повторно не выдаст.
	LastUnlockedHash string `json:"last_unlocked_hash,omitempty"`
}

// validateBcryptHash — password_hash приходит от сервера; перед тем как поднять
// по нему блокировку, убеждаемся, что это НЕПУСТОЙ валидный bcrypt-хеш. Пустой/
// битый хеш дал бы офлайн-НЕСНИМАЕМЫЙ лок: bcrypt.CompareHashAndPassword на нём
// всегда возвращает ошибку → verify() всегда false → сотрудник не разблокирует
// НИКАКИМ паролем (fail-safe: лучше не запирать, чем запереть неснимаемо).
func validateBcryptHash(hash string) error {
	if hash == "" {
		return errors.New("пустой password_hash")
	}
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return fmt.Errorf("не bcrypt-хеш: %w", err)
	}
	return nil
}

// Locker — платформенный замок экрана (полноэкранный оверлей с полем пароля).
// Реализации: Windows (оверлей), прочие ОС (заглушка/лог). Вынесен за интерфейс,
// чтобы логику Manager можно было тестировать без GUI.
type Locker interface {
	// Show поднимает блокирующий экран. reason — текст для сотрудника. verify
	// вызывается при вводе пароля; true → разблокировать. Идемпотентно: повторный
	// Show при уже поднятом замке лишь обновляет текст.
	Show(reason string, verify func(password string) bool)
	// Hide снимает блокирующий экран. Идемпотентно.
	Hide()
}

// Manager хранит состояние блокировки, персистит его и управляет платформенным
// замком. Потокобезопасен.
type Manager struct {
	path   string
	log    *slog.Logger
	locker Locker

	mu    sync.Mutex
	state State
}

// New собирает Manager. path — файл состояния (машинный каталог), locker —
// платформенный замок.
func New(path string, locker Locker, log *slog.Logger) *Manager {
	return &Manager{path: path, log: log, locker: locker}
}

// Load читает состояние с диска и, если устройство было заблокировано, поднимает
// замок (вызывать на старте агента — переживание рестарта/ребута). Отсутствие
// файла — не ошибка (никогда не блокировались).
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &m.state); err != nil {
		return err
	}
	if m.state.Locked {
		m.log.Warn("lock: устройство было заблокировано — поднимаю замок после старта",
			slog.String("request_id", m.state.RequestID))
		m.locker.Show(m.state.Reason, m.verify)
	}
	return nil
}

// Locked сообщает, заблокировано ли устройство сейчас.
func (m *Manager) Locked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Locked
}

// CurrentRequestID — id активной заявки на блокировку ("" если не заблокировано).
func (m *Manager) CurrentRequestID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.RequestID
}

// CurrentHash — bcrypt-хеш активной блокировки ("" если не заблокировано).
// Хеш уникален на каждую блокировку (сервер генерирует новый случайный пароль
// при каждом Lock), поэтому используется как идентичность лок-инстанса
// реконсиляцией (см. package lock, Reconciler).
func (m *Manager) CurrentHash() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Hash
}

// LastUnlockedHash — durable-память хеша последнего локально снятого лока
// (переживает рестарт/ребут; см. State.LastUnlockedHash). Реконсиляция сверяет
// с ним desired-хеш, чтобы не пере-запереть устройство по устаревшему
// desired=locked после ребута до доставки UNLOCKED-отчёта.
func (m *Manager) LastUnlockedHash() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.LastUnlockedHash
}

// Lock блокирует устройство: сохраняет состояние и поднимает замок. hash —
// bcrypt-хеш пароля разблокировки (приходит с сервера). Повторный Lock с тем же
// requestID — no-op (идемпотентность доставки команды).
func (m *Manager) Lock(requestID, hash, reason string) error {
	// #13: не поднимать блокировку по невалидному хешу (fail-safe против
	// офлайн-неснимаемого лока). Проверяем ДО mu — чистая функция от аргумента.
	if err := validateBcryptHash(hash); err != nil {
		m.log.Error("lock: ОТКАЗ применять блокировку — невалидный password_hash (fail-safe, не создаём офлайн-неснимаемый лок)",
			slog.String("request_id", requestID), slog.Any("error", err))
		return fmt.Errorf("lock: невалидный password_hash: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.state.Locked && m.state.RequestID == requestID {
		return nil // уже заблокированы этой же заявкой
	}
	m.state = State{
		Locked:    true,
		Hash:      hash,
		Reason:    reason,
		RequestID: requestID,
		LockedAt:  time.Now().Unix(),
	}
	if err := m.persist(); err != nil {
		return err
	}
	m.log.Warn("lock: устройство заблокировано", slog.String("request_id", requestID))
	m.locker.Show(reason, m.verify)
	return nil
}

// Run обслуживает офлайн-разблокировку в фоне службы. На каждом тике:
//  1. processUnlockRequests — разгребает запросы на разблокировку от лок-экрана
//     (WriteUnlockRequest): демон сам сверяет пароль с bcrypt-хешем и, если верно,
//     снимает блокировку авторитетно (владелец lock.json — он же).
//  2. detectOfflineUnlock — защитный резерв для путей, где файл всё же мог
//     измениться в обход (1): например, Windows, где ACL-наследование каталога
//     позволяет ClearState писать напрямую (см. lockui_windows.go).
//
// В обоих случаях вызывается onUnlock(requestID, hash), чтобы caller отчитался
// серверу (ReportLockStatus UNLOCKED) для UI/аудита и запомнил hash снятого лока
// (см. package lock, Reconciler — не даёт реконсиляции пере-заблокировать раньше,
// чем сервер догонит этот отчёт). Интервал короткий (по умолчанию 1с):
// SessionLocker переподнимает оверлей каждые 3с, если считает устройство ещё
// заблокированным — нужно успевать снять состояние раньше этого тика, иначе
// лок-экран на миг мигнёт заново (полевой баг v1.5.3).
func (m *Manager) Run(ctx context.Context, interval time.Duration, onUnlock func(requestID, hash string)) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.processUnlockRequests(onUnlock)
			m.detectOfflineUnlock(onUnlock)
		}
	}
}

// processUnlockRequests вычитывает файлы-запросы (WriteUnlockRequest) из общего
// каталога состояния, сверяет пароль и снимает блокировку при совпадении. Каждый
// запрос удаляется СРАЗУ после чтения независимо от исхода (верный/неверный
// пароль) — не оставляем на диске файлы, которые можно было бы replay'нуть.
func (m *Manager) processUnlockRequests(onUnlock func(requestID, hash string)) {
	dir := filepath.Dir(m.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), unlockRequestPrefix) {
			continue
		}
		reqPath := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(reqPath)
		_ = os.Remove(reqPath) // расходуем запрос сразу, вне зависимости от исхода ниже
		if err != nil {
			continue
		}
		var req unlockRequest
		if json.Unmarshal(data, &req) != nil {
			continue
		}
		reqID := m.CurrentRequestID()
		if reqID == "" {
			continue // уже не заблокированы — verify() тут вернул бы true тривиально
		}
		hash := m.CurrentHash() // до verify() — он же и снимает блокировку при успехе
		if m.verify(req.Password) && onUnlock != nil {
			onUnlock(reqID, hash)
		}
	}
}

// detectOfflineUnlock сверяет память с файлом и реагирует на внешнее снятие блокировки.
//
// Весь тик — под m.mu (как и persist в Lock/verify): снимок состояния, чтение
// файла и запись решения атомарны относительно параллельного Lock/Unlock.
// Прежний код отпускал mu между снимком и записью — новый лок H2, применённый в
// это окно, затирался «разблокированным» состоянием, собранным по устаревшему
// снимку H1 (lost update), причём durably: с диска стиралась и страховка,
// поднимавшая лок после ребута.
func (m *Manager) detectOfflineUnlock(onOfflineUnlock func(requestID, hash string)) {
	m.mu.Lock()
	if !m.state.Locked {
		m.mu.Unlock()
		return
	}
	reqID := m.state.RequestID
	hash := m.state.Hash

	st, err := ReadState(m.path)
	if err != nil || st.Locked {
		m.mu.Unlock()
		return // файл недоступен или всё ещё заблокирован — ничего не делаем
	}
	// Файл разблокирован извне. Если снявший оставил маркер, КАКОЙ лок он сверил
	// (MarkUnlocked, Windows-оверлей), и это НЕ текущий — оверлей жил под старым
	// hash и затёр файл нового лока: снятие нелегитимно, пере-утверждаем текущее
	// состояние на диске и лок не опускаем. Пустой маркер (ClearState старого
	// оверлея, ручная зачистка IT) трактуем по-прежнему как снятие текущего.
	if st.LastUnlockedHash != "" && st.LastUnlockedHash != hash {
		_ = m.persist()
		m.mu.Unlock()
		m.log.Warn("lock: файл состояния затёрт снятием УСТАРЕВШЕГО лока — текущая блокировка пере-утверждена",
			slog.String("request_id", reqID), slog.String("stale_unlocked_hash", st.LastUnlockedHash))
		return
	}
	// Легитимное снятие: синхронизируем память и уведомляем. Перезаписываем
	// внешне-очищенный файл, СОХРАНЯЯ hash снятого лока durably (переживёт ребут —
	// реконсиляция не пере-запрёт по устаревшему desired, #4).
	m.state = State{LastUnlockedHash: hash}
	_ = m.persist()
	m.mu.Unlock()
	m.locker.Hide()
	m.log.Warn("lock: устройство разблокировано оффлайн (верный пароль на лок-экране)",
		slog.String("request_id", reqID))
	if onOfflineUnlock != nil {
		onOfflineUnlock(reqID, hash)
	}
}

// Unlock снимает блокировку по команде сервера (админ нажал «Разблокировать»).
// Идемпотентно.
func (m *Manager) Unlock() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unlockLocked("разблокировано сервером")
}

// verify вызывается замком при вводе пароля сотрудником: сверяет с хешем локально
// (bcrypt) и при совпадении снимает блокировку. Работает оффлайн.
func (m *Manager) verify(password string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.state.Locked {
		return true
	}
	if bcrypt.CompareHashAndPassword([]byte(m.state.Hash), []byte(password)) != nil {
		m.log.Warn("lock: неверный пароль разблокировки", slog.String("request_id", m.state.RequestID))
		return false
	}
	if err := m.unlockLocked("введён верный пароль разблокировки"); err != nil {
		m.log.Error("lock: не удалось снять блокировку после верного пароля", slog.Any("error", err))
		// Замок всё равно опускаем: держать заблокированным после верного пароля
		// нельзя (сотрудник не сможет работать), даже если персист не удался.
	}
	return true
}

// unlockLocked очищает состояние и опускает замок. Вызывать под m.mu.
func (m *Manager) unlockLocked(reason string) error {
	if !m.state.Locked {
		return nil
	}
	reqID := m.state.RequestID
	// Сохраняем hash снятого лока durably (переживёт ребут, #4): реконсиляция
	// после старта не пере-запрёт устройство по устаревшему desired=locked.
	m.state = State{LastUnlockedHash: m.state.Hash}
	err := m.persist()
	m.locker.Hide()
	m.log.Warn("lock: устройство разблокировано", slog.String("request_id", reqID), slog.String("reason", reason))
	return err
}

// persist атомарно пишет текущее состояние на диск. Вызывать под m.mu.
func (m *Manager) persist() error { return writeStateAtomic(m.path, m.state) }

// writeStateAtomic пишет состояние в path через tmp+rename (атомарно), создавая
// каталог. Используется и Manager-ом (служба), и ClearState (лок-экран).
func writeStateAtomic(path string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".lock-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	// best-effort: без этого chmod трей (другой пользователь на macOS) не смог бы
	// прочитать файл состояния, который демон создаёт от root (полевой баг v1.5.1).
	_ = tmp.Chmod(0o644)
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
