// Package admin реализует агентскую сторону временных прав администратора (Этап 4):
// запрос прав сотрудником, поллинг статуса (FetchAdminStatus), применение/снятие
// прав через PrivilegeManager и отчёт серверу (ReportAdminAccess).
//
// Применение прав изолировано за интерфейсом PrivilegeManager (платформенные
// реализации dseditgroup/net localgroup в priv_*.go), чтобы логику можно было
// тестировать без изменения реальной системы.
package admin

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/collector"
	"github.com/Floodww/RoutineOps/internal/agent/outbox"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

const reportTimeout = 30 * time.Second

// PrivilegeManager выдаёт/снимает админ-права пользователю ОС.
//
// IsAdmin сообщает, состоит ли пользователь в группе администраторов ПРЯМО СЕЙЧАС —
// нужен, чтобы при выдаче временных прав снять снимок прежнего состояния и НЕ снять
// у пользователя его собственные постоянные права при истечении гранта.
type PrivilegeManager interface {
	Grant(user string) error
	Revoke(user string) error
	IsAdmin(user string) (bool, error)
}

// dryRunPriv — не трогает систему, только логирует (для тестов/демо без root).
type dryRunPriv struct{ log *slog.Logger }

func (d dryRunPriv) Grant(user string) error {
	d.log.Info("admin(dry-run): выдача прав пропущена", slog.String("user", user))
	return nil
}
func (d dryRunPriv) Revoke(user string) error {
	d.log.Info("admin(dry-run): снятие прав пропущено", slog.String("user", user))
	return nil
}
func (dryRunPriv) IsAdmin(string) (bool, error) { return false, nil }

// Manager поллит статус прав и применяет его локально.
type Manager struct {
	interval time.Duration
	log      *slog.Logger
	priv     PrivilegeManager
	// consoleUser возвращает вошедшего пользователя И флаг успешности пробы.
	// Флаг обязателен: пустая строка при неудачной пробе означает «не знаю», а не
	// «за консолью никого», и путать их нельзя — на этом различии стоит решение
	// снимать ли уже выданные права.
	consoleUser func() (string, bool)
	fetch       func(context.Context) (*pb.FetchAdminStatusResponse, error) // статус с сервера
	report      func(context.Context, *pb.ReportAdminAccessRequest) error   // отчёт серверу

	// store — состояние сессии на диске. Без него грант не переживает рестарт
	// агента (см. restore).
	store    *SessionStore
	snapshot func() ([]SoftFP, string, []SvcFP, string) // базовая линия аудита сессии
	bootTime func() int64

	// Аудит сессии: окна улик (что появилось на машине за время действия прав).
	//
	// sendWindow == nil означает, что отправка не подключена — сборка и решение
	// «пора» работают, окно никуда не уходит. collectChanges приходит с сервера и
	// по умолчанию ЛОЖЬ: агент новее сервера не имеет права копить записи в
	// FIFO-очереди, которую делит с ИБ-алертами и статусами лока.
	windowInterval time.Duration
	nextWindowAt   time.Time
	// collectChanges — ТЕКУЩЕЕ значение флага сервера, читается каждый поллинг.
	// Используется ровно в одном месте — при выдаче прав, где защёлкивается на
	// сессию (см. SessionState.Collect).
	collectChanges bool
	// collectLatched — защёлка этой сессии. Копия SessionState.Collect в памяти:
	// решение обязано пережить и выключение флага оператором, и рестарт агента,
	// а без устойчивого состояния память — единственный носитель.
	collectLatched bool
	sendWindow     func(context.Context, Window) error
	baselineLost   bool
	// collectFlags читает флаги сбора из ответа сервера. Отдельным полем, чтобы
	// тесты могли задать серверную сторону, которой в proto ещё нет.
	collectFlags func(*pb.FetchAdminStatusResponse) (bool, int32)

	// Состояние выданных прав.
	grantedUser     string
	grantedExpires  time.Time
	grantedWasAdmin bool   // был ли пользователь админом ДО гранта — тогда права при отзыве НЕ снимаем
	lastReqID       string // последняя заявка, которую уже обработали (выдали) — не выдавать повторно
}

// EnqueueFunc ставит отчёт в устойчивую очередь доставки (outbox).
type EnqueueFunc func(kind string, data []byte) error

// NewManager собирает Manager с боевыми зависимостями (gRPC через dialer, ОС-права).
// dryRun=true — права не применяются к системе (логируются), остальной флоу полный.
//
// FetchAdminStatus — поллинг: при обрыве просто повторяется на следующем тике,
// поэтому идёт напрямую через dialer. ReportAdminAccess (аудит выдачи/снятия
// прав) терять нельзя — он durably ставится в outbox и до-сылается после связи.
func NewManager(dialer *transport.Dialer, enqueue EnqueueFunc, interval time.Duration, log *slog.Logger, dryRun bool, store *SessionStore) *Manager {
	priv := newOSPrivilegeManager()
	if dryRun {
		priv = dryRunPriv{log: log}
	}
	return &Manager{
		interval:       interval,
		log:            log,
		priv:           priv,
		store:          store,
		snapshot:       defaultSnapshot,
		bootTime:       collector.BootTime,
		consoleUser:    osConsoleUserFull,
		windowInterval: DefaultWindowInterval,
		collectFlags:   sessionCollectFlags,
		fetch: func(ctx context.Context) (*pb.FetchAdminStatusResponse, error) {
			conn, err := dialer.Dial()
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(ctx, reportTimeout)
			defer cancel()
			return pb.NewAgentServiceClient(conn).FetchAdminStatus(ctx, &pb.FetchAdminStatusRequest{})
		},
		report: func(_ context.Context, req *pb.ReportAdminAccessRequest) error {
			data, err := proto.Marshal(req)
			if err != nil {
				return err
			}
			return enqueue(outbox.KindAdmin, data)
		},
		sendWindow: windowSender(dialer, enqueue),
	}
}

// windowSender — доставка окна улик: durable-очередь, а для финального окна ещё
// и прямой вызов, если очередь его не приняла.
//
// KindAdminChanges лежит в ВЫТЕСНЯЕМОМ классе очереди (улики не имеют права
// выдавливать ИБ-сигнал), поэтому Enqueue штатно отвечает ошибкой, когда очередь
// забита защищёнными видами. Что делать дальше, зависит от вида окна:
//
//   - промежуточное — ничего. Окна кумулятивны от t0, следующее несёт всё, что
//     было в непринятом, поэтому фолбэк здесь только добавил бы сетевых вызовов
//     ровно в тот момент, когда связь уже плоха (очередь и переполнилась потому,
//     что ничего не уходит). Номер и отпечаток при ошибке не двигаются
//     (см. emitWindow), так что следующее окно уедет обязательно;
//   - финальное — прямой unary. Второго шанса не будет: сразу после него
//     состояние сессии стирается вместе с базовой линией, и потеря финала
//     оставляет заявку без улик, то есть ровно ту дыру, ради видимости которой
//     на сервере живёт свипер. Пусть лучше дыры не будет.
//
// Прямой вызов — не «доставка мимо очереди»: сервер принимает окна append-only с
// ON CONFLICT DO NOTHING и не использует window_seq как фильтр, поэтому дубль
// финала (очередь всё-таки отдала запись позже) безвреден по построению.
func windowSender(dialer *transport.Dialer, enqueue EnqueueFunc) func(context.Context, Window) error {
	return func(ctx context.Context, w Window) error {
		req := windowToProto(w)
		data, err := proto.Marshal(req)
		if err != nil {
			return err
		}
		enqErr := enqueue(outbox.KindAdminChanges, data)
		if enqErr == nil || !w.Final {
			return enqErr
		}
		conn, err := dialer.Dial()
		if err != nil {
			return err
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(ctx, reportTimeout)
		defer cancel()
		ack, err := pb.NewAgentServiceClient(conn).ReportAdminSessionChanges(ctx, req)
		if err != nil {
			return err
		}
		if !ack.GetReceived() {
			return errWindowNotAccepted
		}
		return nil
	}
}

// errWindowNotAccepted — сервер ответил без подтверждения приёма. Отдельная
// ошибка, а не тихий успех: ack=false на этом пути означает, что улики сессии не
// сохранены, и молчать об этом нельзя.
var errWindowNotAccepted = errors.New("admin: сервер не подтвердил приём окна улик")

func (m *Manager) Run(ctx context.Context) {
	m.restore()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.poll(ctx)
		}
	}
}

// restore поднимает состояние гранта, пережившее рестарт агента или ребут машины.
//
// Без этого поля Manager после рестарта пусты, lastReqID = "", и на следующем же
// тике сработала бы повторная выдача: IsAdmin(user) увидел бы УЖЕ выданное
// членство и записал wasAdmin = true — то есть revoke() посчитал бы временные
// права собственными правами пользователя и не снял бы их никогда. Временный
// грант молча становился постоянным, и заметить это можно было только руками.
func (m *Manager) restore() {
	if m.store == nil || !m.store.Durable() {
		return
	}
	st, err := m.store.Load()
	if err != nil {
		// Битое или нечитаемое состояние: продолжаем с чистого листа, но громко.
		// Тихо проглотить нельзя — это ровно тот случай, когда на машине могут
		// висеть выданные права, о которых мы больше не знаем.
		m.log.Error("admin: состояние сессии не прочитано — выданные ранее права могли остаться",
			slog.Any("error", err))
		return
	}
	if st == nil || st.RequestID == "" {
		return
	}
	m.grantedUser = st.User
	m.grantedExpires = st.Expires
	m.grantedWasAdmin = st.WasAdmin
	m.lastReqID = st.RequestID
	m.collectLatched = st.Collect
	m.baselineLost = false
	m.nextWindowAt = time.Now().Add(m.windowInterval)
	m.log.Info("admin: восстановлена сессия прав после рестарта",
		slog.String("user", st.User), slog.String("request_id", st.RequestID),
		slog.Bool("was_admin", st.WasAdmin), slog.Time("expires_at", st.Expires))
}

func (m *Manager) poll(ctx context.Context) {
	// 1) Локальные причины снять права — работают даже без связи с сервером.
	if m.grantedUser != "" {
		user, probed := m.consoleUser()
		switch {
		case probed && user != m.grantedUser:
			// Проба отработала и показала другого пользователя (или никого) —
			// это настоящий логаут или смена сеанса.
			m.revoke(ctx, "пользователь вышел из системы")
		case !m.grantedExpires.IsZero() && time.Now().After(m.grantedExpires):
			// Срок проверяем в любом случае: он не зависит от того, удалось ли
			// определить пользователя.
			m.revoke(ctx, "истёк срок прав")
		case !probed:
			// Проба не отработала (stat/loginctl/WTS не ответили). Пустая строка
			// здесь значит «не знаю», а не «никого»: снять права по транзиентному
			// сбою значит выбить админа из-под работающего человека и записать в
			// журнал ложную причину «вышел из системы».
			m.log.Debug("admin: консольный пользователь не определён — права держим",
				slog.String("user", m.grantedUser))
		}
	}

	resp, err := m.fetch(ctx)
	if err != nil {
		m.log.Error("admin: FetchAdminStatus", slog.Any("error", err))
		return
	}
	// Сбор улик включает сервер, и только он. Нулевое значение (в том числе от
	// сервера, не знающего этих полей) = не собирать и ничего не класть в очередь.
	if m.collectFlags != nil {
		collect, ivl := m.collectFlags(resp)
		m.collectChanges = collect
		m.windowInterval = ClampWindowInterval(ivl)
	}
	status := resp.GetStatus()
	reqID := resp.GetRequestId()
	// expires_at==0 — бессрочная заявка (действует до логаута). Держим её как
	// нулевое время, иначе time.Unix(0,0)=1970 и локальная проверка истечения
	// ниже сняла бы права на следующем же тике (флип-флоп).
	var expires time.Time
	if resp.GetExpiresAt() != 0 {
		expires = time.Unix(resp.GetExpiresAt(), 0)
	}
	// Заявка одобрена и действует прямо сейчас.
	approvedNow := status == pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED &&
		reqID != "" && (expires.IsZero() || time.Now().Before(expires))

	// Сервер больше не подтверждает нашу выданную заявку: закрыта/истекла/заменена
	// ИЛИ активной заявки нет вовсе (status=UNSPECIFIED, request_id="") — снимаем права.
	if m.grantedUser != "" && (!approvedNow || reqID != m.lastReqID) {
		m.revoke(ctx, "сервер не подтверждает права (status="+status.String()+")")
	}

	// Новая одобренная заявка → выдаём.
	if approvedNow && reqID != m.lastReqID {
		m.grant(ctx, reqID, expires)
	}

	// Промежуточное окно улик — пока сессия жива. Оно нужно ровно на случай, когда
	// финального не будет: машина умерла, уехала в оффлайн навсегда, была
	// переустановлена. Окна кумулятивны, поэтому последнее дошедшее и есть полная
	// дельта на свой момент.
	if m.grantedUser != "" && !m.nextWindowAt.IsZero() && !time.Now().Before(m.nextWindowAt) {
		m.emitWindow(ctx, false, time.Time{})
	}
}

func (m *Manager) grant(ctx context.Context, reqID string, expires time.Time) {
	user, probed := m.consoleUser()
	if !probed {
		// Выдавать права «кому-то» нельзя: имя пользователя — это и есть адресат
		// гранта. Заявка никуда не денется, выдадим на следующем тике.
		m.log.Warn("admin: консольный пользователь не определён — выдачу откладываю",
			slog.String("request_id", reqID))
		return
	}
	if user == "" {
		m.log.Warn("admin: нет вошедшего пользователя — права не выданы", slog.String("request_id", reqID))
		return
	}
	// Снимок прежнего членства ДО выдачи: если пользователь уже был админом (например,
	// это основная учётка машины), при истечении гранта его права снимать НЕЛЬЗЯ.
	wasAdmin, err := m.priv.IsAdmin(user)
	if err != nil {
		// Не смогли определить прежнее состояние — безопаснее считать, что пользователь
		// уже был админом, и НЕ снимать права при отзыве. Лучше оставить лишний грант,
		// чем демоутнуть легитимного администратора.
		m.log.Warn("admin: не удалось определить прежнее членство — считаю пользователя админом (при отзыве прав не сниму)",
			slog.String("user", user), slog.Any("error", err))
		wasAdmin = true
	}
	// Состояние сессии пишем ДО фактической выдачи прав, и это не перестраховка:
	// запись после Grant оставляла бы окно, в котором ребут или падение агента
	// уносят след уже выданных прав — снять их потом было бы некому и нечем.
	// Не смогли записать — прав не выдаём вовсе.
	// Защёлка сбора улик: решение принимается здесь, на t0, и за сессию не
	// пересматривается (см. SessionState.Collect).
	m.collectLatched = m.collectChanges

	if m.store != nil && m.store.Durable() {
		st := &SessionState{
			RequestID: reqID, User: user, Expires: expires,
			WasAdmin: wasAdmin, GrantedAt: time.Now(), Collect: m.collectLatched,
		}
		if m.bootTime != nil {
			st.BootTime = m.bootTime()
		}
		// Базовая линия аудита сессии: срез ПО и служб на момент выдачи прав.
		// Снимается, только если сбор защёлкнут: иначе агент платил бы обходом
		// реестра и каталогов на каждой выдаче прав за данные, которых никто не
		// просил. Неудача самого сбора выдачу не отменяет — она лишь делает дельту
		// недостоверной, и это записывается здоровьем, а не тишиной.
		if m.collectLatched && m.snapshot != nil {
			st.Software, st.SoftwareHealth, st.Services, st.ServicesHealth = m.snapshot()
		}
		if err := m.store.Save(st); err != nil {
			m.log.Error("admin: состояние сессии не записано — права НЕ выдаю",
				slog.String("user", user), slog.String("request_id", reqID), slog.Any("error", err))
			return
		}
		m.baselineLost = false
	} else {
		m.log.Warn("admin: устойчивое состояние сессии выключено — грант не переживёт рестарт агента",
			slog.String("user", user), slog.String("request_id", reqID))
		// Базовой линии нет — дельту сессии считать не от чего. Это не отменяет
		// выдачу прав, но обязано доехать до заявки как «улик нет», а не как
		// пустая дельта (см. BuildWindow).
		m.baselineLost = true
	}

	if err := m.priv.Grant(user); err != nil {
		m.log.Error("admin: выдача прав", slog.String("user", user), slog.Any("error", err))
		// Права не выданы — состояние на диске обязано это отражать, иначе после
		// рестарта restore() поднимет сессию, которой не было.
		if m.store != nil && m.store.Durable() {
			if err := m.store.Clear(); err != nil {
				m.log.Error("admin: состояние сессии не очищено после неудачной выдачи", slog.Any("error", err))
			}
		}
		return
	}
	m.grantedUser = user
	m.grantedExpires = expires
	m.grantedWasAdmin = wasAdmin
	m.lastReqID = reqID
	m.nextWindowAt = time.Now().Add(m.windowInterval)
	m.log.Info("admin: права выданы", slog.String("user", user),
		slog.String("request_id", reqID), slog.Time("expires_at", expires))
	// baselineCaptured считаем по факту: защёлка сбора взведена И базовая линия
	// действительно легла на диск. Сбор, защёлкнутый при выключенном устойчивом
	// состоянии, базовой линии не даёт, и обещать серверу финальное окно с
	// дельтой в этом случае значило бы заказать себе же алерт «улики пропали».
	m.reportStatus(ctx, reqID, pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_APPROVED, "applied on "+user,
		m.collectLatched && !m.baselineLost)
}

func (m *Manager) revoke(ctx context.Context, reason string) {
	user := m.grantedUser
	reqID := m.lastReqID
	wasAdmin := m.grantedWasAdmin
	// Значение защёлки снимаем ДО очистки состояния сессии ниже: отчёт о снятии
	// уходит последним, а к тому моменту collectLatched уже сброшен, и отчёт
	// сообщил бы «базовой линии не было» о сессии, которая её снимала.
	baselineCaptured := m.collectLatched && !m.baselineLost
	switch {
	case wasAdmin:
		// Пользователь был администратором ещё до выдачи гранта — его собственные права
		// не наши, снимать их нельзя. Грант считаем завершённым, из группы НЕ удаляем.
		m.log.Info("admin: пользователь был админом до гранта — из группы НЕ удаляю",
			slog.String("user", user), slog.String("reason", reason))
	default:
		if err := m.priv.Revoke(user); err != nil {
			m.log.Error("admin: снятие прав", slog.String("user", user), slog.Any("error", err))
			// Состояние всё равно очищаем: повторить снятие уже не выйдет, но не
			// зацикливаемся; ошибку залогировали.
		}
	}
	// Финальное окно улик — после фактического снятия прав и ОБЯЗАТЕЛЬНО до
	// очистки состояния: базовая линия лежит ровно в том файле, который Clear()
	// сейчас удалит. Порядок здесь не стилистический, а несущий.
	m.emitWindow(ctx, true, m.sessionEnd())

	m.grantedUser = ""
	m.grantedExpires = time.Time{}
	m.grantedWasAdmin = false
	m.nextWindowAt = time.Time{}
	m.collectLatched = false
	// Сессия закончена — состояние на диске больше не должно поднимать её при
	// следующем старте. lastReqID намеренно НЕ чистим: он не даёт выдать ту же
	// заявку повторно, пока сервер не пришлёт новую.
	if m.store != nil && m.store.Durable() {
		if err := m.store.Clear(); err != nil {
			m.log.Error("admin: состояние сессии не очищено", slog.Any("error", err))
		}
	}
	m.log.Info("admin: права сняты", slog.String("user", user), slog.String("reason", reason))
	m.reportStatus(ctx, reqID, pb.AdminAccessStatus_ADMIN_ACCESS_STATUS_REVOKED, reason, baselineCaptured)
}

// sessionEnd — момент, когда права реально кончились.
//
// Для истёкшей заявки это её срок, а не «сейчас»: агент мог обнаружить истечение
// спустя сутки, если машина всё это время была выключена. Разница между этими
// двумя моментами и есть признак stale_final — финал, датированный концом сессии,
// но снятый заметно позже.
func (m *Manager) sessionEnd() time.Time {
	now := time.Now()
	if !m.grantedExpires.IsZero() && m.grantedExpires.Before(now) {
		return m.grantedExpires
	}
	return now
}

// emitWindow собирает окно улик и отдаёт его отправителю.
//
// Тихо выходит, пока сервер не попросил собирать улики или отправка не
// подключена: сбор стоит обхода реестра/каталогов целиком, и делать его «на
// всякий случай» на парке в тысячу машин незачем.
func (m *Manager) emitWindow(ctx context.Context, final bool, sessionEnd time.Time) {
	// Гейт по ЗАЩЁЛКЕ сессии, а не по текущему флагу: сессия, начатая со сбором,
	// обязана дойти до финального окна, даже если оператор выключил флаг посреди
	// неё, а сессия, начатая без сбора, не имеет базовой линии и начать посреди
	// себя не может.
	if !m.collectLatched || m.sendWindow == nil {
		return
	}
	now := time.Now()
	m.nextWindowAt = now.Add(m.windowInterval)

	// Базовую линию держим на диске, а не в памяти: список ПО парковой машины —
	// это мегабайты, и служба, работающая месяцами, не должна носить их резидентно.
	st, lost := m.loadBaseline()

	var cur Inventory
	if m.snapshot != nil {
		cur.Software, cur.SoftwareHealth, cur.Services, cur.ServicesHealth = m.snapshot()
	}
	cur.At = now
	if m.bootTime != nil {
		cur.BootTime = m.bootTime()
	}

	seq := int32(1)
	if st != nil {
		seq = st.WindowSeq + 1
	}
	w := BuildWindow(st, cur, WindowInput{
		Seq: seq, Final: final, Now: now, SessionEnd: sessionEnd, BaselineLost: lost,
	})

	// Промежуточное окно, ничего не изменившее с прошлого раза, не шлём. Окна
	// кумулятивны: повтор того же списка под новым seq не добавляет серверу ни
	// одного факта, зато множит строки в таблице улик на каждую тихую сессию.
	// Финальное шлём ВСЕГДА, даже пустое и даже идентичное: его отсутствие — это
	// отдельное событие («улик нет»), и подменять его тишиной нельзя.
	digest := windowDigest(w)
	if !final && st != nil && digest == st.LastWindowDigest && st.WindowSeq > 0 {
		m.log.Debug("admin: окно улик без изменений — не шлю",
			slog.String("request_id", w.RequestID), slog.Int("seq", int(seq)))
		return
	}

	if err := m.sendWindow(ctx, w); err != nil {
		m.log.Error("admin: отправка окна улик", slog.String("request_id", w.RequestID),
			slog.Int("seq", int(seq)), slog.Any("error", err))
		return
	}
	m.log.Info("admin: окно улик отправлено", slog.String("request_id", w.RequestID),
		slog.Int("seq", int(seq)), slog.Bool("final", final),
		slog.Int("changes", len(w.Changes)), slog.String("completeness", w.Completeness))

	// Номер и отпечаток двигаем ТОЛЬКО после успешной постановки в очередь —
	// иначе неудачная отправка сожгла бы номер, а сервер отвергает окна, ушедшие
	// вперёд от последнего принятого больше чем на 64.
	if final || st == nil || m.store == nil || !m.store.Durable() {
		return
	}
	st.WindowSeq = seq
	st.LastWindowDigest = digest
	if err := m.store.Save(st); err != nil {
		m.log.Error("admin: номер окна улик не сохранён", slog.Any("error", err))
	}
}

// loadBaseline поднимает состояние сессии с диска. Второе значение — «базовой
// линии нет»: она либо выключена, либо не прочиталась. Возвращаемое состояние в
// этом случае несёт хотя бы идентификатор заявки — окно «мы не знаем» обязано
// доехать до конкретной заявки, иначе оно неотличимо от молчания.
func (m *Manager) loadBaseline() (*SessionState, bool) {
	fallback := &SessionState{RequestID: m.lastReqID, User: m.grantedUser, Expires: m.grantedExpires}
	if m.store == nil || !m.store.Durable() {
		return fallback, true
	}
	st, err := m.store.Load()
	if err != nil {
		m.log.Error("admin: базовая линия сессии не прочитана — дельту не считаю",
			slog.Any("error", err))
		return fallback, true
	}
	if st == nil || st.RequestID == "" {
		return fallback, true
	}
	return st, m.baselineLost
}

// reportStatus отчитывается серверу о фактическом применении/снятии прав.
//
// baselineCaptured — ЗАЩЁЛКА улик, снятая на t0, а не текущее значение флага
// сервера. По ней сервер отличает «улик не ждём» от «улики пропали»: свипер
// поднимает алерт только там, где базовая линия снята, а финального окна нет.
// Текущим значением настройки это не заменяется — включение задним числом
// обвиняло бы старые сессии, выключение стирало бы настоящие дыры.
func (m *Manager) reportStatus(ctx context.Context, reqID string, status pb.AdminAccessStatus, details string, baselineCaptured bool) {
	err := m.report(ctx, &pb.ReportAdminAccessRequest{
		RequestId:        reqID,
		Status:           status,
		OccurredAt:       time.Now().Unix(),
		Details:          details,
		BaselineCaptured: baselineCaptured,
	})
	if err != nil {
		m.log.Error("admin: ReportAdminAccess", slog.String("request_id", reqID), slog.Any("error", err))
	}
}
