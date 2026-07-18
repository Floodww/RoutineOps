import { describe, it, expect } from "vitest"
import { scriptPlatformFromFilename, agentPlatform, deviceRunsScript, errMessage, errStatus } from "./api"

describe("scriptPlatformFromFilename", () => {
  it(".ps1 → Windows", () => {
    expect(scriptPlatformFromFilename("grant-admin.ps1")).toBe("Windows")
  })
  it(".sh → macOS (shell-семейство)", () => {
    expect(scriptPlatformFromFilename("setup.sh")).toBe("macOS")
  })
  it(".py → macOS", () => {
    expect(scriptPlatformFromFilename("collect.py")).toBe("macOS")
  })
  it("регистр расширения не важен", () => {
    expect(scriptPlatformFromFilename("X.PS1")).toBe("Windows")
  })
})

describe("agentPlatform", () => {
  it("Windows → windows", () => expect(agentPlatform("Windows")).toBe("windows"))
  it("macOS → darwin", () => expect(agentPlatform("macOS")).toBe("darwin"))
  it("linux → linux", () => expect(agentPlatform("linux")).toBe("linux"))
})

describe("deviceRunsScript", () => {
  it("Windows-устройство запускает только Windows (.ps1)", () => {
    expect(deviceRunsScript("Windows 11", "Windows")).toBe(true)
    expect(deviceRunsScript("Windows 11", "macOS")).toBe(false)
    expect(deviceRunsScript("Windows 11", "linux")).toBe(false)
  })
  it("macOS-устройство — shell-семейство, не .ps1", () => {
    expect(deviceRunsScript("macOS 14", "macOS")).toBe(true)
    expect(deviceRunsScript("macOS 14", "linux")).toBe(true)
    expect(deviceRunsScript("macOS 14", "Windows")).toBe(false)
  })
  it("linux-устройство — shell-семейство, не .ps1", () => {
    expect(deviceRunsScript("Ubuntu 22.04", "linux")).toBe(true)
    expect(deviceRunsScript("Ubuntu 22.04", "macOS")).toBe(true)
    expect(deviceRunsScript("Ubuntu 22.04", "Windows")).toBe(false)
  })
})

describe("errMessage", () => {
  it("Error → message", () => expect(errMessage(new Error("boom"))).toBe("boom"))
  it("строка ответа сервера (axios-подобная ошибка)", () => {
    const axiosLike = { isAxiosError: true, message: "Request failed", response: { data: "token expired" } }
    expect(errMessage(axiosLike)).toBe("token expired")
  })
  it("неизвестное → дефолт", () => expect(errMessage(123)).toBe("Неизвестная ошибка"))
})

// errStatus отличает «роута нет в этой сборке» от настоящего сбоя: по нему страница
// «Лицензия» решает, показать «недоступно в редакции Free» или ошибку загрузки.
// Спутать эти случаи — значит нарисовать enterprise-админу чужую редакцию.
describe("errStatus", () => {
  it("ответ сервера → его код", () => {
    expect(errStatus({ isAxiosError: true, message: "Request failed", response: { status: 404 } })).toBe(404)
  })
  it("сеть легла (ответа нет) → 0, а не 404", () => {
    expect(errStatus({ isAxiosError: true, message: "Network Error" })).toBe(0)
  })
  it("не-axios → 0", () => expect(errStatus(new Error("boom"))).toBe(0))
})
