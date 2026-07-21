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
func TruncateOutput(s string) string {
	if len(s) <= MaxOutputBytes {
		return s
	}
	cut := MaxOutputBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n\n[вывод обрезан: отброшено %d байт из %d]", len(s)-cut, len(s))
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
	buf bytes.Buffer
}

// Write реализует io.Writer: сообщает len(p) как записанное (иначе exec посчитал
// бы это ошибкой пайпа), но реально буферизует лишь до captureCap.
func (c *CaptureBuffer) Write(p []byte) (int, error) {
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
// SanitizeUTF8 + TruncateOutput.
func (c *CaptureBuffer) String() string { return c.buf.String() }
