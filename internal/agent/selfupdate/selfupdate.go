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

	// Базовая версия для сравнения — не только текущая, но и high-water mark
	// (максимум из них): без этого сервер (или злоумышленник, укравший релизный
	// канал) мог бы подсунуть валидно подписанный, но состарившийся с тех пор
	// манифест устаревшей версии, если она всё ещё формально новее u.current —
	// например, после отката бинаря вручную (SEC-3, аудит 2026-07-01).
	baseline := u.current
	if floor := u.loadFloor(); floor != "" {
		if floorNewer, ferr := version.IsNewer(baseline, floor); ferr == nil && floorNewer {
			baseline = floor
		}
	}
	newer, err := version.IsNewer(baseline, m.Version)
	if err != nil {
		return fmt.Errorf("сравнение версий (%q vs %q): %w", baseline, m.Version, err)
	}
	if !newer {
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
	u.saveFloor(m.Version) // best-effort — сбой персиста не должен отменять уже применённое обновление
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

// saveFloor персистит версию только что применённого обновления как новый пол.
func (u *Updater) saveFloor(version string) {
	if u.floorFile == "" {
		return
	}
	if err := os.WriteFile(u.floorFile, []byte(version), 0o644); err != nil {
		u.log.Warn("selfupdate: не удалось сохранить high-water mark версии", slog.Any("error", err))
	}
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
