package uninstall

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// shell возвращает команду-обёртку той ОС, на которой идёт тест: сам runCommand
// платформенно-нейтрален, и проверять его надо там же, где он будет работать.
//
// Скрипты пишутся ТОЛЬКО в пересечении диалектов: в cmd `;` командой не
// разделяет (строка целиком уезжает в echo, код возврата остаётся нулевым, и
// тест на ненулевой код молча проверял пустоту), разделитель — `&`. Ожидаемые
// строки — ТОЛЬКО ASCII: `cmd /c echo` печатает в OEM-кодировке консоли, и
// поиск кириллицы в UTF-8 не нашёл бы её никогда — красный тест на здоровом
// продукте. Кириллицу из вывода деинсталлятора добивает SanitizeUTF8 уже на
// уровне Result (uninstall.go), здесь проверяется захват как таковой.
func shell(script string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd.exe", []string{"/c", script}
	}
	return "/bin/sh", []string{"-c", script}
}

func TestRunCommand_CapturesOutput(t *testing.T) {
	name, args := shell("echo removed-marker")
	out, err := runCommand(context.Background(), name, args, nil)
	if err != nil {
		t.Fatalf("runCommand: %v (вывод %q)", err, out)
	}
	if !strings.Contains(out, "removed-marker") {
		t.Fatalf("вывод не захвачен: %q", out)
	}
}

// Ненулевой код возврата обязан ехать оператору вместе с выводом: без кода
// причина отказа деинсталлятора неразбираема (1603 и 1605 требуют разных
// действий), а без вывода непонятно, на чём он споткнулся.
func TestRunCommand_ExitCodeAndOutputBothReported(t *testing.T) {
	name, args := shell("echo detail-marker & exit 3")
	out, err := runCommand(context.Background(), name, args, nil)
	if err == nil {
		t.Fatal("ожидали ошибку на ненулевом коде возврата")
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("в ошибке нет кода возврата: %v", err)
	}
	if !strings.Contains(out, "detail-marker") {
		t.Errorf("вывод потерян при ошибке: %q", out)
	}
}

func TestRunCommand_MissingBinary(t *testing.T) {
	_, err := runCommand(context.Background(), "заведомо-нет-такого-бинаря", nil, nil)
	if err == nil {
		t.Fatal("ожидали ошибку запуска")
	}
	if !strings.Contains(err.Error(), "не запустился") {
		t.Errorf("ошибка не отличает «не запустился» от «отработал с ошибкой»: %v", err)
	}
}

// Истечение потолка должно называться своим именем: «прервали, продукт мог
// остаться снятым частично» — это не то же самое, что «деинсталлятор отказал»,
// и оператору нужно понимать разницу перед повторной попыткой.
func TestRunCommand_TimeoutSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("на Windows нет sleep в cmd — поведение прерывания одинаково, проверяем на unix")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	name, args := shell("sleep 5")
	_, err := runCommand(ctx, name, args, nil)
	if err == nil {
		t.Fatal("ожидали ошибку по таймауту")
	}
	if !strings.Contains(err.Error(), "не уложился") {
		t.Errorf("таймаут не отличим от обычного отказа: %v", err)
	}
}

// Болтливый деинсталлятор не должен съедать память агента. При этом Write обязан
// сообщать ПОЛНУЮ длину: короткий ответ exec.Cmd трактует как ошибку записи и
// прерывает сам процесс — деинсталляция оборвалась бы на середине из-за
// многословности лога.
func TestCapWriter_CapsWithoutBreakingTheProcess(t *testing.T) {
	var buf bytes.Buffer
	w := &capWriter{buf: &buf, limit: 10}

	n, err := w.Write([]byte("0123456789ABCDEF"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 16 {
		t.Fatalf("Write вернул %d, обязан вернуть полную длину 16", n)
	}
	if buf.Len() != 10 {
		t.Fatalf("в буфер записано %d байт, потолок 10", buf.Len())
	}

	n, err = w.Write([]byte("ещё"))
	if err != nil || n != len("ещё") {
		t.Fatalf("Write после переполнения = (%d, %v)", n, err)
	}
	if buf.Len() != 10 {
		t.Fatalf("буфер вырос после переполнения: %d", buf.Len())
	}
}
