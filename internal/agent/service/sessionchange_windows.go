//go:build windows

package service

import "sync"

var (
	sessionMu   sync.RWMutex
	sessionSubs = map[int]func(SessionEvent){}
	sessionSeq  int
)

// OnSessionChange подписывает f на события сессии. Возвращает отписку.
//
// Подписчиков может быть несколько: захватчик экрана — не единственный, кому это нужно
// (лок-оверлей и трей живут в той же сессии), и делать одного «главного» слушателя значит
// заранее заложить драку за него.
//
// f зовётся из горутины обработчика SCM, поэтому обязана возвращаться быстро: пока она не
// вернулась, служба не отвечает на Interrogate и остальные команды. Всю работу — в свою
// горутину, здесь только сигнал.
func OnSessionChange(f func(SessionEvent)) (cancel func()) {
	sessionMu.Lock()
	sessionSeq++
	id := sessionSeq
	sessionSubs[id] = f
	sessionMu.Unlock()

	return func() {
		sessionMu.Lock()
		delete(sessionSubs, id)
		sessionMu.Unlock()
	}
}

func publishSessionChange(ev SessionEvent) {
	sessionMu.RLock()
	subs := make([]func(SessionEvent), 0, len(sessionSubs))
	for _, f := range sessionSubs {
		subs = append(subs, f)
	}
	sessionMu.RUnlock()

	for _, f := range subs {
		f(ev)
	}
}
