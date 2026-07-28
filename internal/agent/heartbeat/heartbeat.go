// Package heartbeat реализует Heartbeat-горутину агента: периодический сигнал
// "я живой" + текущий IP в Connect-стрим (ADR-5). Запускается транспортом на
// каждое установленное соединение; при обрыве возвращает ошибку, и транспорт
// переподключается.
package heartbeat

import (
	"context"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/Floodww/RoutineOps/internal/agent/transport"
	pb "github.com/Floodww/RoutineOps/proto"
)

// Heartbeater шлёт heartbeat-сообщения в стрим с заданным интервалом.
type Heartbeater struct {
	Interval time.Duration
	// IPFunc отдаёт текущий IP устройства на момент отправки (collector.LocalIP).
	IPFunc func() string
	// OnTask вызывается на каждый Task из стрима (Command Listener). Должна быть
	// неблокирующей — обработка задачи идёт асинхронно. Может быть nil.
	OnTask func(task *pb.Task)
	// OnConnect вызывается один раз при установке каждого Connect-стрима (Этап 5,
	// триггер on_connect скрипт-политик). Должна быть неблокирующей. Может быть nil.
	OnConnect func()
	// OnBeat вызывается после каждого успешно отправленного heartbeat — для
	// индикатора статуса в трее (обновление status-файла). Должна быть
	// неблокирующей. Может быть nil.
	OnBeat func()
	// DegradedFunc отдаёт признак недоступности durable-очереди и причину
	// (outbox.Queue.Unavailable). Может быть nil — тогда признак не шлётся.
	//
	// Почему это едет heartbeat'ом: об умершей очереди нельзя отчитаться через
	// очередь. Когда outbox мёртв, разом и молча теряются результаты задач,
	// статусы лока и security-события, а сервер видит живое устройство, у
	// которого ничего не происходит. Heartbeat — единственный канал, не
	// зависящий от неё.
	DegradedFunc func() (bool, string)
	Log          *slog.Logger
}

// Session обслуживает один Connect-стрим до обрыва. Сигнатура совпадает с
// transport.SessionFunc — передаётся в transport.Client.Run.
func (h *Heartbeater) Session(ctx context.Context, stream transport.Stream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Дренаж входящих Task: на Этапе 1 не выполняем (см. Command Listener, Этап 2),
	// но обязаны читать стрим, чтобы обнаружить обрыв соединения.
	recvErr := make(chan error, 1)
	go func() {
		for {
			task, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			if h.OnTask != nil {
				h.OnTask(task) // Command Listener; обработка асинхронна
			} else {
				h.Log.Info("получена задача (обработчик не задан)",
					slog.String("task_id", task.GetTaskId()))
			}
		}
	}()

	ticker := time.NewTicker(h.Interval)
	defer ticker.Stop()

	// Первый heartbeat — сразу, не дожидаясь тика, чтобы сервер увидел устройство.
	if err := h.send(stream); err != nil {
		return err
	}
	// Стрим установлен — триггерим on_connect скрипт-политики (дедуп — в обработчике).
	if h.OnConnect != nil {
		h.OnConnect()
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			return err
		case <-ticker.C:
			if err := h.send(stream); err != nil {
				return err
			}
		}
	}
}

func (h *Heartbeater) send(stream transport.Stream) error {
	hb := &pb.HeartbeatRequest{
		IpAddress: h.IPFunc(),
		Timestamp: time.Now().Unix(),
	}
	if h.DegradedFunc != nil {
		if down, detail := h.DegradedFunc(); down {
			hb.OutboxUnavailable = true
			// Причина режется: heartbeat идёт каждые несколько секунд, и полный
			// текст ошибки ФС в каждом кадре — это трафик и шум в логе сервера.
			hb.DegradedDetail = truncateDetail(detail)
		}
	}
	if err := stream.Send(hb); err != nil {
		return err
	}
	h.Log.Debug("heartbeat отправлен", slog.String("ip", hb.GetIpAddress()))
	if h.OnBeat != nil {
		h.OnBeat()
	}
	return nil
}

// maxDetailBytes — потолок причины деградации в кадре heartbeat. Признак важен,
// подробности — нет: полный текст ошибки ФС уезжал бы в каждом кадре.
const maxDetailBytes = 200

func truncateDetail(s string) string {
	if len(s) <= maxDetailBytes {
		return s
	}
	// По границе руны: proto3 string обязан быть валидным UTF-8, а сообщения
	// Windows приезжают на русском.
	cut := maxDetailBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
