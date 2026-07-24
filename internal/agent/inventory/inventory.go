// Package inventory реализует Data Collector агента: периодически собирает
// полную инвентаризацию устройства и шлёт её unary-вызовом ReportInventory
// (ОТДЕЛЬНО от heartbeat-стрима — ADR-5).
package inventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/Floodww/RoutineOps/internal/agent/admin"
	"github.com/Floodww/RoutineOps/internal/agent/collector"
	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
	"google.golang.org/protobuf/proto"
)

// initialDelay — задержка перед первым отчётом, чтобы heartbeat успел
// зарегистрировать устройство (сервер делает UpsertInventory по уже
// существующей записи, созданной первым heartbeat).
// Var (а не const), чтобы тесты могли сократить ожидание.
var initialDelay = 3 * time.Second

// reportTimeout — потолок на один unary-вызов ReportInventory.
const reportTimeout = 30 * time.Second

// Reporter периодически отправляет инвентаризацию.
type Reporter struct {
	Interval time.Duration
	Dialer   *transport.Dialer
	Log      *slog.Logger

	// Version — версия агентского бинаря (ldflags main.version), едет в
	// DeviceInfo.agent_version для видимости раскатки в админке.
	Version string

	// lastHash — хэш последнего успешно отправленного снимка. Если снимок не
	// изменился, ReportInventory не шлём (last_seen всё равно держит heartbeat).
	lastHash string

	// sendReport отправляет снимок на сервер. Поле (а не прямой dial+RPC), чтобы
	// тесты могли подставить фейковую отправку. По умолчанию — dialAndSend.
	sendReport func(ctx context.Context, report *pb.InventoryReport) (received bool, err error)
}

// Run шлёт отчёт через initialDelay, затем каждые Interval, пока ctx жив.
func (r *Reporter) Run(ctx context.Context) {
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.reportOnce(ctx)
			timer.Reset(r.Interval)
		}
	}
}

func (r *Reporter) reportOnce(ctx context.Context) {
	report := build(r.Version)
	h, err := hashReport(report)
	if err != nil {
		// Fail-open: без хэша шлём всегда — лишняя отправка честнее снимка,
		// застывшего из-за сломанного дедупа.
		r.Log.Warn("inventory: хэш снимка не построен — отправка без дедупа", slog.Any("error", err))
		h = ""
	}
	if h != "" && h == r.lastHash {
		r.Log.Debug("inventory без изменений — пропуск отправки")
		return
	}

	if r.sendReport == nil {
		r.sendReport = r.dialAndSend
	}
	received, err := r.sendReport(ctx, report)
	if err != nil {
		r.Log.Error("inventory: отправка", slog.Any("error", err))
		return
	}
	r.lastHash = h // запоминаем только после успешной отправки
	r.Log.Info("inventory отправлен",
		slog.Bool("received", received),
		slog.Int("software", len(report.GetSoftware())),
		slog.String("os_version", report.GetDeviceInfo().GetOsVersion()))
}

// dialAndSend — продакшн-реализация sendReport: dial + unary ReportInventory.
func (r *Reporter) dialAndSend(ctx context.Context, report *pb.InventoryReport) (bool, error) {
	conn, err := r.Dialer.Dial()
	if err != nil {
		return false, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()

	ack, err := pb.NewAgentServiceClient(conn).ReportInventory(ctx, report)
	if err != nil {
		return false, err
	}
	return ack.GetReceived(), nil
}

// hashReport — стабильный хэш снимка (поля устройства + список ПО без учёта
// порядка), чтобы пропускать отправку неизменившейся инвентаризации.
//
// DeviceInfo и каждый SoftwareItem сериализуются протобуфом ЦЕЛИКОМ
// (детерминированный маршалинг): новое proto-поле попадает в хэш само.
// Ручное перечисление полей здесь было миной: забытое поле уезжало на сервер
// один раз при первой отправке и после этого застывало навсегда — без ошибки
// и следа в логах (TestHashReport_CoversEveryDeviceInfoField сторожит).
//
// Обратный инвариант — на КОЛЛЕКТОРЕ: раз в хэш входит всё, каждое поле
// DeviceInfo обязано быть стабильным между снимками, пока машина реально не
// изменилась. Поэтому BootTime — абсолютное время загрузки (не uptime), а
// DiskFree огрублён до корзины (diskFreeBucket). Новое волатильное поле
// (счётчик, метрика «сейчас») молча вернёт отправку каждые 5 минут — без
// ошибки и следа в логах.
//
// Каждый блоб пишется с length-префиксом — конкатенация без него склеивала бы
// разные снимки в одинаковый вход хэша. Детерминизм гарантирован в пределах
// одного бинаря; после self-update библиотека может сериализовать иначе — цена
// этого одна лишняя отправка инвентаря, и она уходит всегда (agent_version в
// снимке меняется тем же событием).
func hashReport(r *pb.InventoryReport) (string, error) {
	mo := proto.MarshalOptions{Deterministic: true}
	h := sha256.New()
	writeBlob := func(b []byte) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}

	di, err := mo.Marshal(r.GetDeviceInfo())
	if err != nil {
		return "", fmt.Errorf("marshal device_info: %w", err)
	}
	writeBlob(di)

	// Порядок списка ПО зависит от пакетного менеджера/реестра и не является
	// изменением снимка — сортируем сериализованные записи.
	items := make([][]byte, 0, len(r.GetSoftware()))
	for _, s := range r.GetSoftware() {
		b, err := mo.Marshal(s)
		if err != nil {
			return "", fmt.Errorf("marshal software %q: %w", s.GetSoftwareName(), err)
		}
		items = append(items, b)
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i], items[j]) < 0 })
	for _, b := range items {
		writeBlob(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// build собирает proto.InventoryReport. device_id не заполняется — сервер берёт
// его из mTLS-сертификата (ADR-1). agentVersion — версия бинаря (ldflags).
// console_user и console_user_sid приходят из пакета admin (ConsoleIdentity)
// одной атомарной парой, а не из collector: collector собирает факты о
// железе/ОС, «кто за консолью» — знание admin-слоя.
func build(agentVersion string) *pb.InventoryReport {
	d := collector.Collect()
	sw := collector.InstalledSoftware()
	consoleUser, consoleUserSID := admin.ConsoleIdentity()

	items := make([]*pb.SoftwareItem, 0, len(sw))
	for _, s := range sw {
		items = append(items, &pb.SoftwareItem{SoftwareName: s.Name, Version: s.Version})
	}
	return &pb.InventoryReport{
		DeviceInfo: &pb.DeviceInfo{
			Hostname:     d.Hostname,
			Os:           d.OS,
			OsVersion:    d.OSVersion,
			Cpu:          d.CPU,
			Ram:          d.RAMMegabytes, // МБ (колонка devices.ram — INTEGER)
			Disk:         d.Disk,
			IpAddress:    d.IP,
			MacAddress:   d.MAC,
			SerialNumber: d.SerialNumber,
			AgentVersion: agentVersion,

			Arch:           d.Arch,
			ConsoleUser:    consoleUser,
			ConsoleUserSid: consoleUserSID,
			DiskEncryption: d.DiskEncryption,
			OsPatchDate:    d.OSPatchDate,
			BootTime:       d.BootTime,
			DiskFree:       d.DiskFree,
			DomainJoined:   d.DomainJoined,
			Tpm:            d.TPM,
			SecureBoot:     d.SecureBoot,
		},
		Software: items,
	}
}
