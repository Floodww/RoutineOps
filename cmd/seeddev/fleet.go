package main

import pb "github.com/Floodww/RoutineOps/proto"

// fleet — демонстрационный парк.
//
// Состав подобран не «побольше строк», а так, чтобы на скриншотах было видно то, ради чего
// продукт покупают: три ОС рядом, шифрование диска включено не везде, обновления местами
// просрочены, часть машин в домене, на одной есть запрещённое ПО из уже заведённых политик.
// Ровный парк, где всё зелёное, не показывает ничего.
//
// Имена машин и учёток — синтетические, под уже существующие в каталоге карточки
// сотрудников (@example.com) и заведённые группы.
func fleet() []spec {
	win := []*pb.SoftwareItem{
		{SoftwareName: "Google Chrome", Version: "141.0.7390.55", Vendor: "Google LLC"},
		{SoftwareName: "7-Zip", Version: "24.09", Vendor: "Igor Pavlov"},
		{SoftwareName: "Microsoft 365 Apps", Version: "16.0.18324.20168", Vendor: "Microsoft"},
	}
	mac := []*pb.SoftwareItem{
		{SoftwareName: "Google Chrome", Version: "141.0.7390.55", Vendor: "Google LLC"},
		{SoftwareName: "Visual Studio Code", Version: "1.99.2", Vendor: "Microsoft"},
		{SoftwareName: "Docker Desktop", Version: "4.38.0", Vendor: "Docker Inc."},
	}
	lin := []*pb.SoftwareItem{
		{SoftwareName: "nginx", Version: "1.26.2", Vendor: "nginx.org"},
		{SoftwareName: "PostgreSQL", Version: "17.2", Vendor: "PGDG"},
		{SoftwareName: "Docker Engine", Version: "27.4.1", Vendor: "Docker Inc."},
	}

	return []spec{
		// ── Бухгалтерия: типовые офисные Windows, домен, BitLocker включён.
		{Hostname: "WS-BUH-01", OS: "Windows", OSVer: "11 24H2", CPU: "Intel Core i5-12400", RAMMB: 16384,
			Disk: "512 GB NVMe", DiskFree: "231 GB", IP: "192.168.10.21", MAC: "3c:52:82:11:04:a1",
			Serial: "5CG2417XQK", Arch: "amd64", User: "CORP\\m.lebedeva", Crypt: "enabled",
			Patch: "2026-07-29", Domain: "true", TPM: "2.0", Secure: "true",
			Group: "Бухгалтерия", Owner: "m.lebedeva@example.com", Soft: win},
		{Hostname: "WS-BUH-02", OS: "Windows", OSVer: "11 24H2", CPU: "Intel Core i5-12400", RAMMB: 16384,
			Disk: "512 GB NVMe", DiskFree: "88 GB", IP: "192.168.10.22", MAC: "3c:52:82:11:04:b7",
			Serial: "5CG2417XRM", Arch: "amd64", User: "CORP\\o.morozova", Crypt: "enabled",
			Patch: "2026-06-11", Domain: "true", TPM: "2.0", Secure: "true",
			Group: "Бухгалтерия", Owner: "o.morozova@example.com", Soft: win},

		// ── Отдел продаж: ноутбук без шифрования и с просроченными обновлениями —
		// на такой машине и должен зажигаться compliance.
		{Hostname: "NB-SALES-07", OS: "Windows", OSVer: "10 22H2", CPU: "Intel Core i7-1165G7", RAMMB: 8192,
			Disk: "256 GB SSD", DiskFree: "19 GB", IP: "192.168.20.37", MAC: "a4:bb:6d:2f:91:0c",
			Serial: "PF3KX8N2", Arch: "amd64", User: "CORP\\i.novikov", Crypt: "disabled",
			Patch: "2026-03-04", Domain: "true", TPM: "1.2", Secure: "false",
			Group: "Отдел продаж", Owner: "i.novikov@example.com",
			Soft: append(append([]*pb.SoftwareItem{}, win...),
				&pb.SoftwareItem{SoftwareName: "uTorrent", Version: "3.6.0", Vendor: "BitTorrent Inc."})},
		{Hostname: "NB-SALES-08", OS: "Windows", OSVer: "11 24H2", CPU: "AMD Ryzen 5 7530U", RAMMB: 16384,
			Disk: "512 GB NVMe", DiskFree: "301 GB", IP: "192.168.20.38", MAC: "a4:bb:6d:2f:91:5e",
			Serial: "PF3KX8N9", Arch: "amd64", User: "CORP\\e.popova", Crypt: "enabled",
			Patch: "2026-07-31", Domain: "true", TPM: "2.0", Secure: "true",
			Group: "Отдел продаж", Owner: "e.popova@example.com", Soft: win},

		// ── Разработка: маки и один Linux-десктоп.
		{Hostname: "MB-DEV-03", OS: "macOS", OSVer: "26.0.1", CPU: "Apple M3 Pro", RAMMB: 36864,
			Disk: "1 TB SSD", DiskFree: "412 GB", IP: "192.168.30.13", MAC: "f0:2f:4b:7c:12:9d",
			Serial: "C02XK1YZQ6NV", Arch: "arm64", User: "a.sokolov", Crypt: "enabled",
			Patch: "2026-08-01", Domain: "false", TPM: "", Secure: "true",
			Group: "Разработка", Owner: "a.sokolov@example.com", Soft: mac},
		{Hostname: "MB-DEV-04", OS: "macOS", OSVer: "15.6.1", CPU: "Apple M2", RAMMB: 16384,
			Disk: "512 GB SSD", DiskFree: "97 GB", IP: "192.168.30.14", MAC: "f0:2f:4b:7c:13:22",
			Serial: "C02XK1YZR1PL", Arch: "arm64", User: "d.kuznetsov", Crypt: "disabled",
			Patch: "2026-05-19", Domain: "false", TPM: "", Secure: "true",
			Group: "Разработка", Owner: "d.kuznetsov@example.com", Soft: mac},
		{Hostname: "WS-DEV-11", OS: "Linux", OSVer: "Ubuntu 24.04.1 LTS", CPU: "AMD Ryzen 7 5800X", RAMMB: 32768,
			Disk: "1 TB NVMe", DiskFree: "604 GB", IP: "192.168.30.41", MAC: "b4:2e:99:04:7a:31",
			Serial: "0000-0000-0000-0011", Arch: "amd64", User: "p.ivanov", Crypt: "enabled",
			Patch: "", Domain: "false", TPM: "2.0", Secure: "true",
			Group: "Разработка", Owner: "p.ivanov@example.com", Soft: lin},

		// ── Серверы: Linux и один Windows Server.
		{Hostname: "SRV-APP-01", OS: "Linux", OSVer: "Ubuntu 24.04.1 LTS", CPU: "Intel Xeon Silver 4310", RAMMB: 65536,
			Disk: "2 TB NVMe", DiskFree: "1.4 TB", IP: "192.168.40.11", MAC: "0c:c4:7a:88:1e:02",
			Serial: "SRV-APP-0001", Arch: "amd64", User: "", Crypt: "enabled",
			Patch: "", Domain: "false", TPM: "2.0", Secure: "true",
			Group: "Серверы", Owner: "", Soft: lin},
		{Hostname: "SRV-DB-02", OS: "Linux", OSVer: "Debian 12.8", CPU: "Intel Xeon Silver 4310", RAMMB: 131072,
			Disk: "4 TB NVMe", DiskFree: "2.1 TB", IP: "192.168.40.12", MAC: "0c:c4:7a:88:1e:44",
			Serial: "SRV-DB-0002", Arch: "amd64", User: "", Crypt: "enabled",
			Patch: "", Domain: "false", TPM: "2.0", Secure: "true",
			Group: "Серверы", Owner: "", Soft: lin},
		{Hostname: "SRV-FILE-03", OS: "Windows", OSVer: "Server 2022", CPU: "Intel Xeon Gold 5318Y", RAMMB: 65536,
			Disk: "8 TB RAID10", DiskFree: "3.2 TB", IP: "192.168.40.13", MAC: "0c:c4:7a:88:1e:77",
			Serial: "SRV-FILE-0003", Arch: "amd64", User: "", Crypt: "enabled",
			Patch: "2026-07-30", Domain: "true", TPM: "2.0", Secure: "true",
			Group: "Серверы", Owner: "", Soft: win},

		// ── Канареечная группа: сюда едут обновления первыми.
		{Hostname: "WS-CANARY-01", OS: "Windows", OSVer: "11 24H2", CPU: "Intel Core i7-13700", RAMMB: 32768,
			Disk: "1 TB NVMe", DiskFree: "742 GB", IP: "192.168.50.11", MAC: "e8:6a:64:3b:00:12",
			Serial: "CNRY-0001", Arch: "amd64", User: "CORP\\s.volkov", Crypt: "enabled",
			Patch: "2026-08-02", Domain: "true", TPM: "2.0", Secure: "true",
			Group: "Канареечная группа", Owner: "s.volkov@example.com", Soft: win},
		{Hostname: "MB-CANARY-02", OS: "macOS", OSVer: "26.0.1", CPU: "Apple M4", RAMMB: 24576,
			Disk: "512 GB SSD", DiskFree: "355 GB", IP: "192.168.50.12", MAC: "e8:6a:64:3b:00:88",
			Serial: "CNRY-0002", Arch: "arm64", User: "n.zaytseva", Crypt: "enabled",
			Patch: "2026-08-02", Domain: "false", TPM: "", Secure: "true",
			Group: "Канареечная группа", Owner: "n.zaytseva@example.com", Soft: mac},
	}
}
