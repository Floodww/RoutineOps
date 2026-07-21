package command

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestInterpreterByPlatform фиксирует регистронезависимый выбор интерпретатора:
// UI шлёт строчное "windows", справочник скриптов — "Windows"; оба обязаны уйти в
// powershell. Регресс сюда (строгое сравнение) ронял все Windows-скрипты в bash.
func TestInterpreterByPlatform(t *testing.T) {
	cases := map[string]string{
		"windows": "powershell", "Windows": "powershell", "WINDOWS": "powershell",
		"macOS": "bash", "darwin": "bash", "linux": "bash", "": "bash",
	}
	for platform, want := range cases {
		got := interpreterCmd(context.Background(), platform, "echo x").Args[0]
		if got != want {
			t.Errorf("platform=%q → %q, ожидали %q", platform, got, want)
		}
	}
}

func TestRunScriptSuccess(t *testing.T) {
	stdout, stderr, err := runScript(context.Background(), "macOS", "echo hello")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if strings.TrimSpace(stdout) != "hello" {
		t.Errorf("stdout=%q", stdout)
	}
	if stderr != "" {
		t.Errorf("stderr=%q", stderr)
	}
}

func TestRunScriptError(t *testing.T) {
	stdout, stderr, err := runScript(context.Background(), "macOS", "echo oops 1>&2; exit 3")
	if err == nil {
		t.Fatal("ожидали ошибку при exit 3")
	}
	if !strings.Contains(stderr, "oops") {
		t.Errorf("stderr=%q (ожидали 'oops')", stderr)
	}
	_ = stdout
}

func TestRunScriptTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := runScript(ctx, "macOS", "sleep 5"); err == nil {
		t.Fatal("ожидали прерывание по таймауту")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("скрипт не был убит по контексту вовремя")
	}
}

// Скрипт, оставивший фонового потомка с унаследованным stdout, НЕ подвешивает
// runScript до смерти потомка: WaitDelay принудительно закрывает пайпы, а сам
// скрипт (вышел с кодом 0) считается успешным. Без фикса Run() ждал EOF пайпа
// ~30с (до смерти sleep), а в бою — навсегда, вместе со слотом семафора.
func TestRunScriptBackgroundChildDoesNotHang(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash-скрипт: unix-платформы")
	}
	start := time.Now()
	stdout, _, err := runScript(context.Background(), "macOS", "sleep 30 & echo started")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ErrWaitDelay должен трактоваться как успех, получили err=%v", err)
	}
	if !strings.Contains(stdout, "started") {
		t.Errorf("stdout=%q, ожидали вывод до фонового потомка", stdout)
	}
	if elapsed >= 20*time.Second {
		t.Fatalf("runScript висел %v — WaitDelay не сработал", elapsed)
	}
}

func TestCombineErr(t *testing.T) {
	if got := combineErr("", errTest{}); got != "boom" {
		t.Errorf("без stderr: %q", got)
	}
	if got := combineErr("stderr-text", errTest{}); !strings.Contains(got, "stderr-text") || !strings.Contains(got, "boom") {
		t.Errorf("с stderr: %q", got)
	}
}

type errTest struct{}

func (errTest) Error() string { return "boom" }
