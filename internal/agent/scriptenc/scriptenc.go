// Package scriptenc содержит общие хелперы кодировки для исполнения скриптов
// агентом: backstop валидации UTF-8 вывода и UTF-8-префикс для Windows
// PowerShell.
//
// Вынесено в отдельный пакет, чтобы ОБА пути исполнения — ad-hoc задачи
// (internal/agent/command) и скрипт-политики (internal/agent/scripts) —
// использовали один источник правды и не расходились: рассинхрон этих путей и
// был причиной молчаливой потери результатов политик на RU-Windows (proto3
// string обязан быть валидным UTF-8, иначе Marshal/ReportTaskResult падает, а
// результат теряется навсегда).
package scriptenc

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// utf8Replacement — символ-заглушка (U+FFFD) для невалидных UTF-8 байт.
const utf8Replacement = "�"

// PSUTF8Prefix заставляет Windows PowerShell 5.1 отдавать stdout нативных
// командлетов в UTF-8. Без этого на русской Windows вывод приезжает в OEM
// (cp866) / ANSI (cp1251) и ломает proto3-сериализацию результата.
// Легаси-EXE (whoami, ipconfig) всё равно могут писать в OEM — их добивает
// backstop SanitizeUTF8 уже на стороне Go.
const PSUTF8Prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " +
	"$OutputEncoding=[System.Text.Encoding]::UTF8; "

// SanitizeUTF8 заменяет невалидные UTF-8 последовательности на U+FFFD, чтобы
// строка всегда сериализовалась в proto3 string. stdlib-only, без транскода
// кодпейджа.
func SanitizeUTF8(s string) string {
	return strings.ToValidUTF8(s, utf8Replacement)
}

// MaxOutputBytes — потолок stdout/stderr одного отчёта. Сервер отвергает gRPC-кадр
// больше 4 МБ (grpc.MaxRecvMsgSize) кодом ResourceExhausted; отчёт с замороженным
// payload остаётся в голове FIFO-очереди outbox и намертво блокирует доставку ВСЕГО
// остального — security-событий, статусов лока, других результатов. Поэтому режем на
// источнике: 256 КиБ хватает на диагностику, а дампы логов агент возить не обязан.
const MaxOutputBytes = 256 * 1024

// TruncateOutput обрезает вывод до MaxOutputBytes по границе руны и дописывает
// пометку, чтобы обрезание было видно человеку, а не выглядело как конец скрипта.
// Общий объём для пометки берёт из len(s) — вызывающий не сообщил реальный (см.
// TruncateTotal для источников из CaptureBuffer, знающих истинный объём).
func TruncateOutput(s string) string {
	return TruncateTotal(s, len(s))
}

// TruncateTotal — как TruncateOutput, но total задаёт РЕАЛЬНЫЙ объём вывода,
// произведённого скриптом. CaptureBuffer отбрасывает всё сверх captureCap ещё во
// время выполнения, поэтому len(s) — уже усечённая величина: пометка «отброшено N
// из M», построенная на ней, всегда показывала ~4 КиБ из ~260 КиБ, хоть 300 КиБ
// реального вывода, хоть 5 ГБ (#1.6). Передав CaptureBuffer.Total(), получаем
// честное M. total<=len(s) и len(s)<=Max → обрезки не было, возвращаем как есть.
func TruncateTotal(s string, total int) string {
	if len(s) <= MaxOutputBytes && total <= len(s) {
		return s
	}
	return truncateTo(s, MaxOutputBytes, total)
}

// truncateTo режет s до max байт по границе руны и дописывает пометку об обрезке.
// total — реальный объём произведённого вывода (для честного «из M»); при total<=0
// или total<cut берётся фактически показанный объём. Итог может превышать max на
// длину пометки (~80 байт) — вызывающие закладывают запас (см. noteReserve).
func truncateTo(s string, max, total int) string {
	cut := max
	if cut > len(s) {
		cut = len(s)
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if total < cut {
		total = cut // санитайз мог расширить строку выше реального объёма (U+FFFD)
	}
	return s[:cut] + fmt.Sprintf("\n\n[вывод обрезан: показано %d, отброшено ~%d из ~%d байт]", cut, total-cut, total)
}

// WaitDelayNote — пометка обоих путей исполнения при exec.ErrWaitDelay. Текст
// обязан быть ЧЕСТНЫМ: по контракту os/exec WaitDelay закрывает пайпы, и фоновый
// потомок, пишущий в унаследованный stdout/stderr, на следующей записи получает
// EPIPE (unix: SIGPIPE, по умолчанию — смерть процесса; Windows: ошибка записи).
// Выживает только потомок, который держит пайп, но не пишет. Прежняя формулировка
// («потомки продолжают работать») обещала обратное.
const WaitDelayNote = "[пайпы вывода закрыты принудительно (WaitDelay): фоновые потомки, " +
	"пишущие в унаследованный stdout/stderr, будут прерваны на следующей записи; их вывод не захвачен]"

// noteReserve — запас под пометку truncateTo при подрезке в AppendNote: длина
// «[вывод обрезан: отброшено N байт из M]» с двумя int64-числами.
const noteReserve = 128

// AppendNote дописывает note в хвост s так, чтобы пометка ГАРАНТИРОВАННО пережила
// потолок MaxOutputBytes: при переполнении режется сам вывод, а не пометка.
// Прямое `s += note` с последующим TruncateOutput теряло пометку на выводе
// ≥ MaxOutputBytes — обрезка режет именно хвост. Результат не превышает
// MaxOutputBytes, поэтому повторный TruncateOutput поверх — no-op.
func AppendNote(s, note string) string {
	suffix := "\n" + note
	if len(s)+len(suffix) <= MaxOutputBytes {
		return s + suffix
	}
	keep := MaxOutputBytes - len(suffix) - noteReserve
	if keep < 0 {
		keep = 0
	}
	return truncateTo(s, keep, len(s)) + suffix
}

// PipeWaitDelay — потолок ожидания EOF на stdout/stderr-пайпах ПОСЛЕ выхода
// прямого потомка (os/exec Cmd.WaitDelay). Когда Stdout/Stderr — не *os.File
// (наш CaptureBuffer), exec заводит os.Pipe и горутину-копир, а Wait ждёт EOF —
// то есть закрытия ПОСЛЕДНЕГО пишущего дескриптора. Скрипт, оставивший фонового
// потомка с унаследованным stdout (`bash -c "daemon &"`, nohup, Start-Process
// без -Wait), подвешивал cmd.Run() навсегда: отмена контекста убивает только
// прямого потомка, копира она не трогает. Для ad-hoc задач это означало вечно
// занятый слот семафора executor'а — 8 таких задач глушили скрипт-канал машины
// до рестарта службы. WaitDelay по истечении потолка принудительно закрывает
// пайпы, и Wait возвращает exec.ErrWaitDelay (ТОЛЬКО вместо nil — т.е. сам
// скрипт вышел успешно); оба пути исполнения обязаны трактовать его как успех.
// Цена закрытия пайпов: потомок, пишущий в унаследованный stdout/stderr, на
// следующей записи получает EPIPE (unix — SIGPIPE, по умолчанию смерть) — для
// MDM-агента ограниченное ожидание слота важнее выживания чужого демона. Оба
// пути обязаны честно дописывать WaitDelayNote (через AppendNote) туда, где её
// увидит оператор.
//
// Константа общая по той же причине, что и весь пакет: третий путь исполнения
// не должен появиться без WaitDelay и разойтись с этими двумя.
const PipeWaitDelay = 5 * time.Second

// captureCap — потолок буферизации stdout/stderr ВО ВРЕМЯ выполнения. Чуть выше
// MaxOutputBytes, чтобы итоговый TruncateOutput всё же увидел превышение и
// дописал человекочитаемую пометку об обрезке.
const captureCap = MaxOutputBytes + 4*1024

// CaptureBuffer — io.Writer с жёстким потолком памяти для stdout/stderr скрипта.
// Прежде оба пути исполнения писали в неограниченный bytes.Buffer, а обрезка
// (TruncateOutput) применялась лишь ПОСЛЕ cmd.Run(): скрипт от сервера с
// многогигабайтным выводом за окно maxRuntime накапливал всё в RAM до обрезки —
// OOM агента, работающего под root. CaptureBuffer принимает Write целиком (не
// блокирует и не роняет процесс сообщением об ошибке записи в пайп), но в память
// кладёт не больше captureCap, остальное молча отбрасывает.
type CaptureBuffer struct {
	buf   bytes.Buffer
	total int // всего байт, пришедших в Write (включая отброшенные сверх captureCap)
}

// Write реализует io.Writer: сообщает len(p) как записанное (иначе exec посчитал
// бы это ошибкой пайпа), но реально буферизует лишь до captureCap. total считает
// ВЕСЬ поток — по нему TruncateTotal строит честную пометку об обрезке (#1.6).
func (c *CaptureBuffer) Write(p []byte) (int, error) {
	c.total += len(p)
	if room := captureCap - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// String возвращает накопленное (в пределах потолка); дальше обычно идёт
// SanitizeUTF8 + TruncateTotal(…, Total()).
func (c *CaptureBuffer) String() string { return c.buf.String() }

// Total — сколько байт всего произвёл скрипт (включая отброшенные при захвате).
// Передаётся в TruncateTotal, чтобы пометка об обрезке показывала реальный объём.
func (c *CaptureBuffer) Total() int { return c.total }
