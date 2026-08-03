package main

import (
	"fmt"

	pb "github.com/Floodww/RoutineOps/proto"
)

// Массовая часть парка.
//
// Двенадцати машин из fleet() хватало показать, что три ОС уживаются, но не хватало
// показать РАЗМЕР: список, который целиком помещается на экран, выглядит как стенд, а не
// как парк. Здесь добавляются ещё несколько десятков, и именно они дают то, ради чего
// открывают список: страницы, фильтры, разброс по версиям ОС и по свежести обновлений.
//
// Всё детерминировано и без случайностей: один и тот же прогон обязан давать один и тот же
// парк, иначе повторный запуск после сбоя разойдётся с уже заведённым.

// bulkFleet собирает вторую, массовую часть парка.
func bulkFleet() []spec {
	win := []*pb.SoftwareItem{
		{SoftwareName: "Google Chrome", Version: "141.0.7390.55", Vendor: "Google LLC"},
		{SoftwareName: "7-Zip", Version: "24.09", Vendor: "Igor Pavlov"},
		{SoftwareName: "Microsoft 365 Apps", Version: "16.0.18324.20168", Vendor: "Microsoft"},
	}
	winOld := []*pb.SoftwareItem{
		{SoftwareName: "Google Chrome", Version: "126.0.6478.127", Vendor: "Google LLC"},
		{SoftwareName: "Microsoft Office 2016", Version: "16.0.4266.1001", Vendor: "Microsoft"},
	}
	mac := []*pb.SoftwareItem{
		{SoftwareName: "Google Chrome", Version: "141.0.7390.55", Vendor: "Google LLC"},
		{SoftwareName: "Visual Studio Code", Version: "1.99.2", Vendor: "Microsoft"},
		{SoftwareName: "Slack", Version: "4.41.98", Vendor: "Slack Technologies"},
	}
	lin := []*pb.SoftwareItem{
		{SoftwareName: "nginx", Version: "1.26.2", Vendor: "nginx.org"},
		{SoftwareName: "Docker Engine", Version: "27.4.1", Vendor: "Docker Inc."},
	}

	// Владельцы берутся по кругу из каталога: карточек одиннадцать, машин больше, и в
	// живом парке у человека вполне бывает и ноутбук, и рабочая станция.
	owners := []string{
		"m.lebedeva@example.com", "o.morozova@example.com", "i.novikov@example.com",
		"e.popova@example.com", "a.sokolov@example.com", "d.kuznetsov@example.com",
		"p.ivanov@example.com", "s.volkov@example.com", "n.zaytseva@example.com",
		"a.smirnova@example.com",
	}
	// Короткие имена для console_user — из тех же адресов, до собаки.
	shortOf := func(email string) string {
		for i := 0; i < len(email); i++ {
			if email[i] == '@' {
				return email[:i]
			}
		}
		return email
	}

	// Разброс по версиям и «свежести» обновлений. Индекс машины гоняется по этим
	// наборам, поэтому парк получается неровным, но воспроизводимым.
	winVers := []string{"11 24H2", "11 23H2", "10 22H2"}
	patches := []string{"2026-08-01", "2026-07-22", "2026-06-03", "2026-04-18", "2026-02-27"}
	cpus := []string{"Intel Core i5-12400", "Intel Core i7-13700", "AMD Ryzen 5 7530U", "Intel Core i5-1335U"}
	rams := []int64{8192, 16384, 16384, 32768}

	var out []spec

	// ── Офис: рабочие станции Windows по отделам.
	type dept struct {
		prefix string
		group  string
		subnet int
		count  int
	}
	for _, dp := range []dept{
		{"WS-BUH", "Бухгалтерия", 10, 6},
		{"WS-SALES", "Отдел продаж", 20, 8},
		{"NB-SALES", "Отдел продаж", 21, 4},
		{"WS-OFFICE", "", 11, 9},
	} {
		for i := 0; i < dp.count; i++ {
			n := i + 3 // 01–02 заняты первой частью парка
			idx := len(out)
			owner := owners[idx%len(owners)]
			ver := winVers[idx%len(winVers)]
			patch := patches[idx%len(patches)]
			// Старые версии Windows логично идут в паре с просроченными обновлениями и
			// выключенным шифрованием: так «проблемные» машины группируются, как в жизни.
			crypt, secure, tpm := "enabled", "true", "2.0"
			soft := win
			if ver == "10 22H2" {
				crypt, secure, tpm = "disabled", "false", "1.2"
				soft = winOld
			}
			out = append(out, spec{
				Hostname: fmt.Sprintf("%s-%02d", dp.prefix, n),
				OS:       "Windows", OSVer: ver,
				CPU: cpus[idx%len(cpus)], RAMMB: rams[idx%len(rams)],
				Disk: "512 GB NVMe", DiskFree: fmt.Sprintf("%d GB", 40+idx*13%420),
				IP:     fmt.Sprintf("192.168.%d.%d", dp.subnet, 40+i),
				MAC:    fmt.Sprintf("3c:52:82:%02x:%02x:%02x", dp.subnet, n, idx),
				Serial: fmt.Sprintf("5CG%05dQK", 24170+idx),
				Arch:   "amd64", User: "CORP\\" + shortOf(owner),
				Crypt: crypt, Patch: patch, Domain: "true", TPM: tpm, Secure: secure,
				Group: dp.group, Owner: owner, Soft: soft,
			})
		}
	}

	// ── Разработка: маки.
	macVers := []string{"26.0.1", "15.6.1", "14.7.2"}
	for i := 0; i < 6; i++ {
		idx := len(out)
		owner := owners[idx%len(owners)]
		ver := macVers[i%len(macVers)]
		out = append(out, spec{
			Hostname: fmt.Sprintf("MB-DEV-%02d", i+5),
			OS:       "macOS", OSVer: ver,
			CPU:   []string{"Apple M3 Pro", "Apple M2", "Apple M1 Pro", "Apple M4"}[i%4],
			RAMMB: []int64{16384, 24576, 36864, 32768}[i%4],
			Disk:  "1 TB SSD", DiskFree: fmt.Sprintf("%d GB", 120+idx*17%600),
			IP:     fmt.Sprintf("192.168.30.%d", 50+i),
			MAC:    fmt.Sprintf("f0:2f:4b:%02x:%02x:%02x", 30, i, idx),
			Serial: fmt.Sprintf("C02XK%05dNV", 10000+idx),
			Arch:   "arm64", User: shortOf(owner),
			Crypt: map[bool]string{true: "enabled", false: "disabled"}[i%4 != 2],
			Patch: patches[idx%len(patches)], Domain: "false", TPM: "", Secure: "true",
			Group: "Разработка", Owner: owner, Soft: mac,
		})
	}

	// ── Инфраструктура: линуксовые серверы.
	srv := []struct {
		name, osver, cpu string
		ram              int64
	}{
		{"SRV-WEB-04", "Ubuntu 24.04.1 LTS", "Intel Xeon Silver 4310", 32768},
		{"SRV-WEB-05", "Ubuntu 24.04.1 LTS", "Intel Xeon Silver 4310", 32768},
		{"SRV-BACKUP-06", "Debian 12.8", "Intel Xeon E-2388G", 65536},
		{"SRV-MAIL-07", "Ubuntu 22.04.5 LTS", "Intel Xeon Silver 4214", 16384},
		{"SRV-MON-08", "Debian 12.8", "Intel Xeon E-2288G", 32768},
	}
	for i, s := range srv {
		idx := len(out)
		out = append(out, spec{
			Hostname: s.name, OS: "Linux", OSVer: s.osver,
			CPU: s.cpu, RAMMB: s.ram,
			Disk: "2 TB NVMe", DiskFree: fmt.Sprintf("%d GB", 300+idx*29%1500),
			IP:     fmt.Sprintf("192.168.40.%d", 20+i),
			MAC:    fmt.Sprintf("0c:c4:7a:%02x:%02x:%02x", 40, i, idx),
			Serial: fmt.Sprintf("SRV-%04d", 1000+idx),
			Arch:   "amd64", User: "", Crypt: "enabled",
			Patch: "", Domain: "false", TPM: "2.0", Secure: "true",
			Group: "Серверы", Owner: "", Soft: lin,
		})
	}

	return out
}
