//go:build !darwin && !windows

package collector

import (
	"bufio"
	"runtime"
	"strings"
)

// parseCPUModel достаёт имя процессора из /proc/cpuinfo. Строка "model name" есть
// только на x86: на aarch64 ядро её не печатает вовсе, там имя SoC лежит в
// "Hardware" (или "Model" у Raspberry Pi). Пустой CPU в инвентаре бесполезен,
// поэтому последний рубеж — архитектура. Общий для linux и прочих unix
// (collector_linux.go/collector_other.go), чтобы cpuModel не расходился между
// ними (нецелевой unix прежде не имел ни Hardware/Model-фолбэка, ни GOARCH-флора).
func parseCPUModel(cpuinfo string) string {
	var hardware, model string
	sc := bufio.NewScanner(strings.NewReader(cpuinfo))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		switch strings.TrimSpace(key) {
		case "model name":
			return val
		case "Hardware":
			if hardware == "" {
				hardware = val
			}
		case "Model":
			if model == "" {
				model = val
			}
		}
	}
	switch {
	case hardware != "":
		return hardware
	case model != "":
		return model
	}
	return runtime.GOARCH
}
