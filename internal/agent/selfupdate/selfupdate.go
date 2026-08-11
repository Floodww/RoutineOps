// Package selfupdate реализует безопасное самообновление агента (Этап 7-8).
//
// Агент периодически спрашивает у сервера актуальную версию (manifest), и если
// она новее — скачивает бинарь, ПРОВЕРЯЕТ его целостность (sha256) и ПОДПИСЬ
// (ed25519 публичным ключом релиза, вшитым в агент), атомарно заменяет себя и
// инициирует перезапуск через супервизор службы.
//
// Безопасность — главное: агент работает с правами root/админа на каждом
// устройстве, поэтому скомпрометированный сервер НЕ должен иметь возможности
// подсунуть произвольный бинарь. Применяется только бинарь, подписанный приватным
// ключом релиза (его на сервере нет). Без валидной подписи обновление отклоняется.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Floodww/RoutineOps/internal/version"
)

// Manifest — ответ сервера о доступной версии (см. docs/self-update.md).
type Manifest struct {
	Version   string `json:"version"`   // semver, напр. "v1.4.2"
	URL       string `json:"url"`       // откуда качать бинарь под этот os/arch
	SHA256    string `json:"sha256"`    // hex sha256 бинаря
	Signature string `json:"signature"` // ed25519 над sha256(бинарь) — legacy, verify() её больше не использует

	// ManifestSignature — base64 ed25519-подпись КАНОНА version\nos\narch\nsha256
	// (см. signedMessage), НЕ только sha256 бинаря. Публикуется publish-release
	// (cmd/publish-release/main.go), новое поле — старое signature осталось
	// нетронутым для агентов до этой версии. Пусто → verify() отклоняет (fail-closed,
	// см. migrations/019_agent_release_manifest_sig.sql).
	ManifestSignature string `json:"manifest_signature"`
}

// Updater оркестрирует проверку и применение обновлений.
type Updater struct {
	current   string // текущая версия агента (ldflags); "dev" → автообновление выключено
	interval  time.Duration
	pubKey    ed25519.PublicKey
	floorFile string // high-water mark версии (""=только память, см. loadFloor)
	log       *slog.Logger

	// Сеймы (подменяются в тестах; в проде — HTTP + замена файла + рестарт).
	check    func(ctx context.Context) (*Manifest, error)
	download func(ctx context.Context, url string) ([]byte, error)
	// channelCheck — манифест КАНАЛА этого устройства, по mTLS (Q-52). nil, пока
	// не подключён: тогда работает только check (публичный stable-манифест).
	channelCheck func(ctx context.Context) (*Manifest, error)
	replace      func(newBinary []byte) error // атомарно заменить текущий исполняемый файл
	restart      func()                       // инициировать перезапуск (graceful-shutdown → супервизор)
	// firstDelay — задержка ПЕРВОЙ проверки; nil → startupJitter(interval).
	// Сейм только для тестов: иначе тест первой проверки ждал бы живой jitter.
	firstDelay func() time.Duration

	// hold — гейт §9.1: работа, посреди которой заменять бинарь нельзя (интерактивный
	// сеанс). nil = гейта нет, поведение как раньше. Состояние отсрочки рядом: с какого
	// момента ждём, что именно держит и просили ли уже завершить.
	hold         *Hold
	holdSince    time.Time
	holdWhat     string
	holdReleased bool
	// nowFn — сейм времени для тестов гейта; nil = time.Now.
	nowFn func() time.Time

	// applied — версия, которую ЭТОТ процесс уже положил на диск. Живёт только в
	// памяти, и это принципиально: на диск (в пол) версия попадает лишь после того,
	// как она действительно ЗАПУСТИЛАСЬ (см. confirmRunning). Здесь она нужна ровно
	// для одного — не качать и не применять один и тот же бинарь по кругу, если
	// перезапуск почему-то не случился.
	applied string
	// confirmed — пол уже сверен с работающей версией в этом процессе. Одного раза
	// достаточно: версия по ходу работы не меняется.
	confirmed bool

	// OnReplaceFail (опционально) зовётся, когда замена бинаря ПРОВАЛИЛАСЬ. Нужен
	// Windows: replaceExecutable к этому моменту уже убил трей юзер-сессии taskkill'ом
	// (тот держит блокировку .old), а рестарта службы при ошибке не будет — без
	// реакции иконка пропадает до перелогина на всё время, пока замена падает
	// (AV держит файл, диск полон). Best-effort, выставляется из cmd/agent.
	OnReplaceFail func()
}

// New собирает Updater. pubKey — публичный ключ релиза (ed25519); если пуст,
// автообновление выключено (защита от применения неподписанных бинарей).
// floorFile — файл high-water mark применённой версии (""=без анти-rollback
// защиты, только сравнение с current). restart вызывается после успешной замены
// — обычно отмена корневого контекста агента (graceful shutdown), после чего
// служба перезапускается супервизором (launchd KeepAlive / Windows recovery action).
func New(current string, interval time.Duration, pubKey ed25519.PublicKey, checkURL, caFile, floorFile string, restart func(), log *slog.Logger) *Updater {
	u := &Updater{
		current:   current,
		interval:  interval,
		pubKey:    pubKey,
		floorFile: floorFile,
		log:       log,
		restart:   restart,
	}
	// manifest/бинарь отдаёт тот же сервер (приватная CA) — клиент должен ей
	// доверять, иначе TLS не пройдёт (подлинность бинаря гарантирует подпись).
	client, ok := NewHTTPClient(caFile)
	if !ok {
		log.Warn("selfupdate: CA для проверки эндпоинта обновлений не загружен — используются системные корни", slog.String("ca", caFile))
	}
	u.check = func(ctx context.Context) (*Manifest, error) { return httpCheck(ctx, client, checkURL, current) }
	u.download = func(ctx context.Context, url string) ([]byte, error) { return httpDownload(ctx, client, url) }
	u.replace = replaceExecutable
	return u
}

// SetChannelSource подключает канальный источник манифеста — тот, что ходит по
// mTLS и получает версию КАНАЛА этого устройства (stable/beta, Q-52).
//
// Публичная HTTP-ручка остаётся запасным путём: у неё нет личности спрашивающего,
// поэтому она всегда отдаёт stable. Откат на неё безопасен по построению — он может
// только НЕ ДОДАТЬ канареечной машине beta-версию, но никогда не отдаст beta
// обычной: обратного направления у этого отката нет.
func (u *Updater) SetChannelSource(fetch func(ctx context.Context) (*Manifest, error)) {
	u.channelCheck = fetch
}

// fetchManifest — канальный источник, при его отказе — публичный stable.
//
// Молчаливым откат быть не должен: «канарейка не поехала» и «канарейка поехала, но
// манифест ей отдали не тот» выглядят в панели одинаково, и различить их можно
// только по этой строчке в логе агента.
func (u *Updater) fetchManifest(ctx context.Context) (*Manifest, error) {
	if u.channelCheck == nil {
		return u.check(ctx)
	}
	m, err := u.channelCheck(ctx)
	if err == nil {
		return m, nil
	}
	u.log.Warn("selfupdate: канальный манифест недоступен — беру общедоступный stable",
		slog.Any("error", err))
	return u.check(ctx)
}

// startupJitterCap — потолок задержки первой проверки. Дальше растягивать смысла
// нет: чем позже первая проверка, тем дольше только что перезапущенный агент сидит
// на старой версии, хотя релиз уже опубликован.
const startupJitterCap = 5 * time.Minute

// startupJitterShare — доля интервала, которую занимает потолок jitter'а. Нужна
// ради коротких интервалов: с `ROUTINEOPS_UPDATE_INTERVAL=60s` (так гоняют полевую
// приёмку) ждать 5 минут первой проверки абсурдно — потолок станет 6 секунд.
const startupJitterShare = 10

// startupJitter — полный jitter [0, потолок] перед первой проверкой. Приём тот же,
// что в transport/backoff.go: парк из тысячи агентов после массового ребута не
// должен прийти за манифестом (и тем более за бинарём) в одну секунду.
func startupJitter(interval time.Duration) time.Duration {
	limit := interval / startupJitterShare
	if limit > startupJitterCap {
		limit = startupJitterCap
	}
	if limit <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(limit) + 1))
}

// Run проверяет и применяет обновления: один раз вскоре после старта, дальше — по
// интервалу, пока ctx жив.
func (u *Updater) Run(ctx context.Context) {
	if len(u.pubKey) != ed25519.PublicKeySize {
		u.log.Warn("selfupdate: нет публичного ключа релиза — автообновление отключено")
		return
	}
	if u.current == "dev" || u.current == "" {
		u.log.Info("selfupdate: dev-сборка — автообновление отключено")
		return
	}
	// Первая проверка — вскоре после старта, а не через полный интервал. Иначе
	// перезапуск службы или ребут машины отодвигал бы уже опубликованный релиз на
	// весь интервал (по умолчанию 6 часов): агент жив, хартбиты идут, версия просто
	// не растёт — ровно то, что показала полевая приёмка 2.5.6.
	delay := startupJitter(u.interval)
	if u.firstDelay != nil {
		delay = u.firstDelay()
	}
	u.log.Info("selfupdate: первая проверка после старта", slog.Duration("через", delay))
	if !waitOrDone(ctx, delay) {
		return
	}
	u.report("selfupdate: проверка после старта", u.checkAndApply(ctx))
	ticker := time.NewTicker(u.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.report("selfupdate: цикл обновления", u.checkAndApply(ctx))
		}
	}
}

// report логирует исход итерации.
//
// Отложенное обновление — не ошибка, и печатать его как ошибку нельзя: гейт §9.1
// срабатывает штатно каждый раз, когда релиз совпал с интерактивным сеансом, и если это
// красная строка в логе, то через неделю на красные строки перестанут смотреть вовсе.
func (u *Updater) report(what string, err error) {
	switch {
	case err == nil:
	case errors.Is(err, ErrDeferred):
		u.log.Info(what+": отложено", slog.Any("причина", err))
	default:
		u.log.Error(what, slog.Any("error", err))
	}
}

// waitOrDone ждёт d. true — дождались, false — ctx отменён (агент останавливается,
// и лезть за манифестом на выходе уже незачем).
func waitOrDone(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// checkAndApply — одна итерация: проверить версию, при наличии новее — скачать,
// проверить и применить. Выделено для тестируемости.
func (u *Updater) checkAndApply(ctx context.Context) error {
	m, err := u.fetchManifest(ctx)
	if err != nil {
		return fmt.Errorf("проверка версии: %w", err)
	}
	// Манифест получен — значит эта версия агента не просто «легла на диск», а
	// РАБОТАЕТ: служба поднялась, петля обновления крутится, канал до сервера жив.
	// Единственный момент, когда версию можно записывать в пол.
	u.confirmRunning()

	// Базовая версия для сравнения — не только текущая, но и high-water mark
	// (максимум из них): без этого сервер (или злоумышленник, укравший релизный
	// канал) мог бы подсунуть валидно подписанный, но состарившийся с тех пор
	// манифест устаревшей версии, если она всё ещё формально новее u.current —
	// например, после отката бинаря вручную (SEC-3, аудит 2026-07-01).
	baseline := u.current
	floor := u.loadFloor()
	baseline = newerOf(baseline, floor)
	// applied — то, что этот процесс уже положил на диск, но что ещё не запускалось.
	// В пол оно не идёт (в этом весь фикс), а вот повторно качать и подменять exe тем
	// же бинарём каждый тик, пока супервизор не поднял новую версию, незачем.
	baseline = newerOf(baseline, u.applied)

	newer, err := version.IsNewer(baseline, m.Version)
	if err != nil {
		return fmt.Errorf("сравнение версий (%q vs %q): %w", baseline, m.Version, err)
	}
	if !newer {
		u.reportFloorBlock(floor, m.Version)
		return nil // уже актуальны (или манифест не новее high-water mark)
	}
	u.log.Info("selfupdate: доступна новая версия",
		slog.String("current", u.current), slog.String("available", m.Version))

	// Гейт §9.1 — ДО скачивания. Тянуть 20 МБ по тому же каналу, по которому идёт
	// интерактивный сеанс, значит превратить его в слайд-шоу ещё до всякой замены exe.
	if err := u.applyAllowed(ctx); err != nil {
		return err
	}

	data, err := u.download(ctx, m.URL)
	if err != nil {
		return fmt.Errorf("скачивание: %w", err)
	}
	if err := verify(data, m, u.pubKey, runtime.GOOS, runtime.GOARCH); err != nil {
		return fmt.Errorf("проверка бинаря отклонена: %w", err)
	}
	if err := u.replace(data); err != nil {
		if u.OnReplaceFail != nil {
			u.OnReplaceFail()
		}
		return fmt.Errorf("замена бинаря: %w", err)
	}
	// 🔴 Пол здесь НЕ поднимается. Замена файла удалась — это ещё не значит, что новая
	// версия проработала хоть секунду. Инцидент 10.08.2026: в канал уехали 112 байт
	// JSON, замена прошла штатно, процесс умер сразу после неё — а пол уже стоял на
	// той версии, и машина оказалась заперта вне неё НАВСЕГДА и молча, при том что
	// штатная процедура восстановления (вернуть бинарь из .old) пол не трогает.
	// Пол поднимает первый успешный ЗАПУСК новой версии, см. confirmRunning.
	u.applied = m.Version
	u.log.Info("selfupdate: новая версия применена — перезапуск", slog.String("version", m.Version))
	if u.restart != nil {
		u.restart()
	}
	return nil
}

// loadFloor читает high-water mark версии с диска. Пустая строка — нет флора
// (файла нет, не задан или битый — деградация к сравнению только с current, не отказ).
func (u *Updater) loadFloor() string {
	if u.floorFile == "" {
		return ""
	}
	data, err := os.ReadFile(u.floorFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveFloor персистит пол анти-отката. Зовётся ТОЛЬКО из confirmRunning: единственное
// событие, которое даёт право поднять пол, — успешный запуск версии.
func (u *Updater) saveFloor(version string) {
	if u.floorFile == "" {
		return
	}
	if err := os.WriteFile(u.floorFile, []byte(version), 0o644); err != nil {
		u.log.Warn("selfupdate: не удалось сохранить high-water mark версии", slog.Any("error", err))
	}
}

// confirmRunning поднимает пол до версии, которая СЕЙЧАС РАБОТАЕТ.
//
// 🔴 Смысл пола изменился, и это главное в этой функции. Было: «самая новая версия,
// которую агент когда-либо СКАЧАЛ И ПОЛОЖИЛ НА ДИСК». Стало: «самая новая версия,
// которая на этой машине УЖЕ РАБОТАЛА». Разница вскрылась 10.08.2026, когда в канал
// уехал подписанный мусор: замена файла удалась, процесс после неё не поднялся, а пол
// уже стоял на версии, не прожившей ни секунды. Дальше — тихий вечный отказ принимать
// эту версию, в том числе ИСПРАВЛЕННУЮ пересборку под тем же номером, и штатный откат
// из .old этого не лечит, потому что пола не касается.
//
// Защиту SEC-3 новое определение не ослабляет, а усиливает: ручной откат бинаря после
// того, как высокая версия отработала, пол по-прежнему переживает (она запускалась —
// значит записана), а вот версия, которой машина никогда не видела в работе, в пол
// больше не попадает. Заодно покрывается случай, которого прежнее правило не видело
// вовсе: подмена бинаря мимо self-update (переустановка MSI/PKG, ручная копия) — она
// тоже поднимает пол, потому что версия РАБОТАЕТ.
func (u *Updater) confirmRunning() {
	if u.confirmed || u.floorFile == "" {
		return
	}
	u.confirmed = true

	// Непарсибельная версия (dev-сборка) в пол не пишется: сравнивать её потом не с
	// чем, а записанная — сломала бы сравнение всем последующим манифестам.
	if !version.Valid(u.current) {
		return
	}

	floor := u.loadFloor()
	switch {
	case floor == "":
		u.saveFloor(u.current)
		u.log.Info("selfupdate: версия подтверждена работой — пол анти-отката заведён",
			slog.String("пол", u.current))

	case !version.Valid(floor):
		// Битый пол не «деградирует к отсутствию» молча: он лежит на диске и будет
		// молча игнорироваться каждой проверкой. Чиним работающей версией.
		u.saveFloor(u.current)
		u.log.Warn("selfupdate: пол анти-отката был нечитаем — перезаписан работающей версией",
			slog.String("было", floor), slog.String("стало", u.current),
			slog.String("файл", u.floorFile))

	case isNewer(u.current, floor):
		// Пол ВЫШЕ работающей версии. Два разных случая, и различить их отсюда нельзя:
		//   1) машину откатили вручную после того, как высокая версия отработала —
		//      пол честный, ровно для этого он и заведён (SEC-3);
		//   2) пол поднят агентом ДО этого фикса по факту замены файла — версия могла
		//      не проработать ни секунды.
		// Выбор в пользу безопасности: пол остаётся. Но молчать нельзя — именно
		// молчание и сделало из случая 2 вечную ловушку.
		u.log.Warn("selfupdate: пол анти-отката ВЫШЕ работающей версии — все версии до него включительно приниматься не будут",
			slog.String("работает", u.current), slog.String("пол", floor),
			slog.String("файл", u.floorFile),
			slog.String("если_версия_из_пола_никогда_не_работала",
				"пол записан агентом до фикса 11.08.2026 (поднимался по факту замены файла); "+
					"вписать в файл работающую версию или удалить файл"))

	case floor != u.current:
		u.saveFloor(u.current)
		u.log.Info("selfupdate: версия подтверждена работой — пол анти-отката поднят",
			slog.String("было", floor), slog.String("стало", u.current))
	}

	// Прежний бинарь больше не нужен: работающая версия себя доказала. До этого
	// момента он лежит рядом намеренно — это единственный путь восстановления, если
	// новая версия не поднимается (на Windows им и спасали стенд 10.08).
	DropPrevious()
}

// reportFloorBlock объясняет отказ, который иначе не оставляет НИ ОДНОЙ строки.
//
// 🔴 Полевой случай 10–11.08.2026: `if !newer { return nil }` — это и «мы уже на
// свежей версии» (норма, каждые шесть часов), и «мы заперты полом» (вечный отказ).
// Снаружи оба выглядят одинаково: агент жив, хартбиты идут, версия не растёт.
// Разделяем: про пол говорим вслух и со всеми числами.
func (u *Updater) reportFloorBlock(floor, offered string) {
	if floor == "" || !version.Valid(floor) || !version.Valid(offered) {
		return
	}
	// Интересен ровно один случай: сама по себе версия поехала бы (она новее
	// работающей), и держит её именно пол.
	if !isNewer(u.current, offered) || isNewer(floor, offered) {
		return
	}
	u.log.Warn("selfupdate: версия НЕ применяется — держит пол анти-отката",
		slog.String("предлагают", offered), slog.String("работает", u.current),
		slog.String("пол", floor), slog.String("файл_пола", u.floorFile),
		slog.String("правило", "пол — самая новая версия, которая на этой машине уже работала; ниже и вровень с ним агент не двигается"),
		slog.String("лечится", "выпуском версии СТРОГО новее пола; либо, если версия из пола никогда не работала, правкой файла пола"))
}

// isNewer — версия want строго новее have. Ошибка разбора трактуется как «не новее»:
// все вызовы здесь уже проверили обе стороны через version.Valid.
func isNewer(have, want string) bool {
	newer, err := version.IsNewer(have, want)
	return err == nil && newer
}

// newerOf — большая из двух версий. Непарсибельная или пустая сторона игнорируется:
// база сравнения от неё только уменьшилась бы, а это ослабление защиты.
func newerOf(base, other string) string {
	if other == "" {
		return base
	}
	if isNewer(base, other) {
		return other
	}
	return base
}

// signedMessage — канон, который подписывает release-ключ (publish-release,
// canon = version\nos\narch\nsha256, см. cmd/publish-release/main.go): не только
// sha256 бинаря, как было раньше. Без этого сервер/злоумышленник, укравший канал
// раздачи манифеста, мог бы взять СТАРЫЙ валидно подписанный бинарь+его настоящий
// sha256 (подпись которого покрывала только sha256) и подсунуть его под
// ПРОИЗВОЛЬНОЙ version — агент решил бы, что это новее (SEC-3, аудит 2026-07-01).
// os/arch — свои (runtime.GOOS/GOARCH), НЕ из ответа сервера: агент и так знает,
// под какую платформу просил манифест (см. httpCheck), сервер их не эхо́ит обратно.
func signedMessage(m *Manifest, goos, goarch string) []byte {
	return []byte(m.Version + "\n" + goos + "\n" + goarch + "\n" + m.SHA256)
}

// verify проверяет целостность (sha256) и подпись (ed25519) скачанного бинаря.
func verify(data []byte, m *Manifest, pubKey ed25519.PublicKey, goos, goarch string) error {
	sum := sha256.Sum256(data)
	wantSum, err := hex.DecodeString(m.SHA256)
	if err != nil {
		return fmt.Errorf("битый sha256 в манифесте: %w", err)
	}
	if len(wantSum) != len(sum) || !equalBytes(sum[:], wantSum) {
		return errors.New("sha256 не совпал (бинарь повреждён или подменён)")
	}
	if m.ManifestSignature == "" {
		return errors.New("манифест без manifest_signature — сервер ещё не публикует новую схему подписи (fail-closed, SEC-3)")
	}
	sig, err := base64.StdEncoding.DecodeString(m.ManifestSignature)
	if err != nil {
		return fmt.Errorf("битая manifest_signature: %w", err)
	}
	// Подписывается весь канон (version+os+arch+sha256), не только дайджест бинаря.
	if !ed25519.Verify(pubKey, signedMessage(m, goos, goarch), sig) {
		return errors.New("подпись манифеста невалидна — не от релиза, отклонена")
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
