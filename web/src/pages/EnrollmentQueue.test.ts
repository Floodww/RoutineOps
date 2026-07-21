import { describe, it, expect } from "vitest"
import { bulkTokenBody } from "./EnrollmentQueue"
import { DEVICE_STATUS, DeviceStatus } from "@/lib/api"

const base = { groupID: "none", maxUses: "", ttlHours: "168", requireApproval: true }

describe("bulkTokenBody", () => {
  it("пустой лимит → ключа max_uses нет вообще (0 сервер отбивает 400-й)", () => {
    expect("max_uses" in bulkTokenBody(base)).toBe(false)
  })

  it("«0» и мусор в лимите тоже не отправляются", () => {
    expect("max_uses" in bulkTokenBody({ ...base, maxUses: "0" })).toBe(false)
    expect("max_uses" in bulkTokenBody({ ...base, maxUses: "-5" })).toBe(false)
    expect("max_uses" in bulkTokenBody({ ...base, maxUses: "abc" })).toBe(false)
    expect("max_uses" in bulkTokenBody({ ...base, maxUses: "0.5" })).toBe(false)
  })

  it("дробное режется до целого: Go-шный *int на 2.5 отвечает 400 «invalid json»", () => {
    expect(bulkTokenBody({ ...base, maxUses: "2.7" }).max_uses).toBe(2)
    expect(bulkTokenBody({ ...base, ttlHours: "2.5" }).ttl_hours).toBe(2)
  })

  it("заданный лимит уезжает числом, а не строкой", () => {
    expect(bulkTokenBody({ ...base, maxUses: "50" }).max_uses).toBe(50)
  })

  it("сентинел «без группы» схлопывается в пустую строку", () => {
    expect(bulkTokenBody(base).group_id).toBe("")
    expect(bulkTokenBody({ ...base, groupID: "g-1" }).group_id).toBe("g-1")
  })

  it("снятая галочка одобрения шлётся явным false, а не пропадает", () => {
    // nil на сервере означает true — молчаливое исчезновение ключа развернуло бы
    // выбор админа в противоположный и открыло парк без очереди.
    expect(bulkTokenBody({ ...base, requireApproval: false }).require_approval).toBe(false)
  })

  it("пустой/нулевой TTL падает на серверный дефолт, а не на 0", () => {
    expect(bulkTokenBody({ ...base, ttlHours: "" }).ttl_hours).toBe(168)
    expect(bulkTokenBody({ ...base, ttlHours: "0" }).ttl_hours).toBe(168)
    expect(bulkTokenBody({ ...base, ttlHours: "24" }).ttl_hours).toBe(24)
  })
})

describe("DEVICE_STATUS", () => {
  // Карта общая на весь UI: пропуск статуса раньше означал сырую латиницу в бейдже и
  // невидимую точку на дашборде. Список сверен с серверными значениями.
  const serverStatuses: DeviceStatus[] = [
    "active", "enrolled", "pending", "pending_approval", "rejected", "blocked", "decommissioned",
  ]

  it("покрывает все серверные статусы и ничего не теряет", () => {
    for (const s of serverStatuses) {
      expect(DEVICE_STATUS[s]?.label, `нет лейбла для ${s}`).toBeTruthy()
      expect(DEVICE_STATUS[s]?.dot, `нет цвета точки для ${s}`).toBeTruthy()
    }
    expect(Object.keys(DEVICE_STATUS).sort()).toEqual([...serverStatuses].sort())
  })

  it("лейблы русские — латиница в UI означала бы непереведённый статус", () => {
    for (const s of serverStatuses) {
      expect(DEVICE_STATUS[s].label, `${s} не переведён`).toMatch(/[а-яА-Я]/)
    }
  })
})
