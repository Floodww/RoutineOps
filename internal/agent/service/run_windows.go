//go:build windows

package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

// Run запускает work под SCM, если процесс стартован как служба, иначе — в
// консольном режиме (для отладки) с обработкой Ctrl-C.
func Run(work func(ctx context.Context) error) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !isSvc {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return work(ctx)
	}
	return svc.Run(Name, &handler{work: work})
}

// handler связывает события SCM (Stop/Shutdown) с отменой ctx рабочей функции.
type handler struct {
	work func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	// AcceptSessionChange запрашивается ЯВНО. Без него WTS_SESSION_LOCK/UNLOCK/LOGOFF/
	// DISCONNECT не приходят вовсе, а при Win+L сессия остаётся WTSActive и токен
	// по-прежнему выдаётся — то есть отличить заблокированный экран от рабочего изнутри
	// службы нечем (§9.11 контракта удалённого стола).
	const accepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange
	s <- svc.Status{State: svc.StartPending, WaitHint: 60_000} // 60с: AV (Kaspersky и т.д.) может задержать старт

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // подстраховка для ветки <-done (work завершился сам); в Stop cancel() зовётся явно раньше
	done := make(chan error, 1)
	go func() { done <- h.work(ctx) }()

	s <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.SessionChange:
				// EventData — это WTSSESSION_NOTIFICATION.dwSessionId. Подписчики
				// разбирают код события сами; здесь только разослать и вернуться:
				// пока обработчик не вернулся, служба не отвечает SCM.
				publishSessionChange(SessionEvent{
					Event:     c.EventType,
					SessionID: uint32(c.EventData),
				})
			case svc.Stop, svc.Shutdown:
				cancel()
				s <- svc.Status{State: svc.StopPending}
				<-done
				return false, 0
			}
		case err := <-done:
			if err != nil {
				// work() вышел сам с ошибкой (например, самообновление:
				// work возвращает "перезапуск для применения" → нужен новый
				// процесс на свежем exe). Отдаём SCM ненулевой код выхода,
				// чтобы сработали FailureActions и служба поднялась заново.
				// Важно: os.Exit(1) делает обрыв процесса (краш), что
				// гарантированно триггерит recovery-actions в SCM, в отличие
				// от штатного возврата с exitCode 1 и статусом STOPPED.
				os.Exit(1)
			}
			return false, 0
		}
	}
}
