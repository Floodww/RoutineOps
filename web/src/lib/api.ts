import axios from "axios"
import { toast } from "./toast"

const api = axios.create({ baseURL: "/api/v1" })

// errMessage достаёт человекочитаемый текст ошибки из ответа сервера/axios.
export function errMessage(e: unknown): string {
  if (axios.isAxiosError(e)) {
    const data = e.response?.data
    if (typeof data === "string" && data.trim()) return data.trim()
    return e.message
  }
  if (e instanceof Error) return e.message
  return "Неизвестная ошибка"
}

// errStatus — HTTP-код ошибки (0, если ответа не было). Нужен, чтобы отличить
// «роута нет в этой сборке» (404) от настоящего сбоя.
export function errStatus(e: unknown): number {
  return axios.isAxiosError(e) ? (e.response?.status ?? 0) : 0
}

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem("session")
      window.location.href = "/login"
      return Promise.reject(err)
    }
    // Авто-тост только для мутаций (POST/PUT/PATCH/DELETE) — действий пользователя.
    // Фоновые GET обрабатываются страницами (loading/catch), их не шумим.
    const method = (err.config?.method ?? "get").toLowerCase()
    if (method !== "get") {
      toast({ title: "Ошибка", description: errMessage(err), variant: "destructive" })
    }
    return Promise.reject(err)
  }
)

export default api

// Types

// DeviceGroupRef — группа в строке/карточке устройства. Цвет приезжает вместе с именем,
// чтобы покрасить рамку не дожидаясь отдельного запроса за группами.
export interface DeviceGroupRef {
  id: string
  name: string
  color: string
}

// Статусы устройства. Держим ПОЛНЫЙ список серверных значений (см. isCutOff в
// internal/server/gateway): раньше юнион знал только четыре, а сервер уже отдавал
// pending_approval / rejected / decommissioned — и каждый новый статус приезжал в UI
// дырявым: бейдж рисовал сырую латиницу среди русского, а точка на дашборде получала
// className "... undefined" (Record без фолбэка) и становилась невидимой. Молча.
export type DeviceStatus =
  | "active" | "enrolled" | "pending"
  | "pending_approval" | "rejected" | "blocked" | "decommissioned"

// Единая карта статусов. До неё их было три частичных и несогласованных: лейблы в
// DeviceDetail, цвета в Dashboard, счётчики там же — новый статус надо было не забыть
// вписать в каждую. Record<DeviceStatus, …> заставляет компилятор ловить это за нас,
// поэтому НЕ ослаблять до Record<string, …>: тогда дыра вернётся и снова молча.
export const DEVICE_STATUS: Record<DeviceStatus, {
  label: string
  variant: "success" | "default" | "secondary" | "destructive" | "outline"
  dot: string
}> = {
  active:           { label: "Активен",              variant: "success",     dot: "bg-emerald-500" },
  enrolled:         { label: "Зарегистрирован",      variant: "default",     dot: "bg-blue-500"    },
  pending:          { label: "Ожидает",              variant: "secondary",   dot: "bg-slate-400"   },
  pending_approval: { label: "Ожидает одобрения",    variant: "secondary",   dot: "bg-amber-500"   },
  rejected:         { label: "Отклонено",            variant: "destructive", dot: "bg-rose-600"    },
  blocked:          { label: "Заблокирован",         variant: "destructive", dot: "bg-red-500"     },
  decommissioned:   { label: "Выведен из эксплуатации", variant: "outline",  dot: "bg-slate-500"   },
}

export interface Device {
  id: string
  hostname: string
  os: string
  os_version: string
  ip_address: string
  status: DeviceStatus
  lock_status: "unlocked" | "locked"
  // Что агент ФАКТИЧЕСКИ доложил про лок (lock_status — желаемое). Отдаётся только
  // карточкой устройства; сервер старой версии поля не пришлёт. Расхождение с
  // lock_status — единственный признак того, что лок выдан, но не применился.
  lock_actual_state?: "" | "lock_failed" | "filevault_revoked" | "filevault_revoke_failed"
  lock_actual_at?: string | null
  last_seen_at: string | null
  created_at: string
  cert_cn: string
  enrolled_at: string | null
  cpu: string
  ram_mb: number
  disk: string
  mac_address?: string
  public_ip?: string
  serial_number?: string
  agent_version?: string
  // Устройство может состоять в нескольких группах. Может отсутствовать: сервер старой
  // версии поля не отдаёт, а только что созданное pending-устройство держим локально.
  groups?: DeviceGroupRef[]
}

// GROUP_PALETTE — те же 8 цветов, которыми миграция 027 бэкфилит существующие группы.
// Читаемы и на светлой, и на тёмной теме; hex, а не токены темы, потому что цвет
// хранится в БД и уезжает в inline-style.
export const GROUP_PALETTE = [
  "#ef4444", "#f97316", "#eab308", "#22c55e",
  "#14b8a6", "#3b82f6", "#8b5cf6", "#ec4899",
] as const

export const DEFAULT_GROUP_COLOR = "#3b82f6"

export interface CreateDeviceResponse {
  device: Device
  enrollment_token: string
  expires_at: string
  ca_sha256: string
}

export interface EnrollmentTokenResponse {
  token: string
  expires_at: string
}

// Массовый токен энроллмента: одна партия машин — один токен, устройство создаётся само.
// 🔴 Поле называется enrollment_token, а НЕ token как в EnrollmentTokenResponse выше —
// разные ручки, переиспользовать тот интерфейс нельзя, тип сойдётся, а значение будет undefined.
// ca_sha256 приезжает пустым, если сервер поднят без CA — это не ошибка, просто нечего пинить.
export interface BulkEnrollmentTokenResponse {
  enrollment_token: string
  expires_at: string
  ca_sha256: string
  require_approval: boolean
}

export interface ReenrollResponse {
  enrollment_token: string
  expires_at: string
}

export interface Software {
  name: string
  version: string
}

export interface DeviceDetailResponse {
  device: Device
  software: Software[] | null
}

export interface Task {
  id: string
  device_id: string
  script_content: string
  platform: string
  priority: string
  status: "pending" | "acked" | "completed" | "failed"
  output: string | null
  error_log: string | null
  created_at: string
}

export interface Alert {
  id: string
  device_id: string
  device_hostname: string
  alert_type: string
  details: string
  created_at: string
  acknowledged_at: string | null
}

export interface AdminAccessRequest {
  id: string
  device_id: string
  device_hostname: string
  requested_by: string
  requester_email: string
  status: "pending" | "approved" | "rejected" | "expired" | "revoked"
  reason: string
  requested_at: string
  pending_expires_at: string
  decided_at: string | null
  granted_at: string | null
  expires_at: string | null
  revoked_at: string | null
}

export interface PolicyRule {
  id: string
  software_name: string
  rule_type: "allowed" | "forbidden"
  device_id: string | null
  group_id: string | null
  platforms: string[] | null
  updated_at: string
}

export type ScriptPlatform = "macOS" | "Windows" | "linux"

export interface Script {
  id: string
  name: string
  platform: ScriptPlatform
  content: string
  created_at: string
  updated_at: string
}

// scriptPlatformFromFilename выводит платформу по расширению файла (как во Fleet):
// .ps1 → Windows, .sh/.py → shell-семейство (по умолчанию macOS, правится в форме).
export function scriptPlatformFromFilename(name: string): ScriptPlatform {
  if (/\.ps1$/i.test(name)) return "Windows"
  return "macOS"
}

// agentPlatform мапит платформу скрипта в значение platform для задачи агента
// (агент выбирает интерпретатор по нему: bash/powershell).
export function agentPlatform(p: ScriptPlatform): "darwin" | "windows" | "linux" {
  if (p === "Windows") return "windows"
  if (p === "linux") return "linux"
  return "darwin"
}

// deviceRunsScript решает, доступен ли скрипт для устройства с данной ОС.
// Windows-устройство запускает только Windows/.ps1; macOS и Linux — shell-семейство
// (macOS + linux), как «macOS & Linux» во Fleet.
export function deviceRunsScript(deviceOS: string, platform: ScriptPlatform): boolean {
  const isWindows = /win/i.test(deviceOS)
  return isWindows ? platform === "Windows" : platform !== "Windows"
}

export interface ScriptPolicy {
  id: string
  name: string
  script_id: string
  script_name: string
  trigger_type: "schedule" | "event_trigger" | "on_connect"
  schedule_config: Record<string, unknown> | null
  event_trigger_config: Record<string, unknown> | null
  is_active: boolean
  created_at: string
  group_names: string[]
}

export interface ScriptResult {
  id: string
  policy_id: string
  device_id: string
  device_hostname: string
  run_id: string
  exit_code: number
  stdout: string
  stderr: string
  trigger: string
  started_at: string
  finished_at: string
  created_at: string
}

export interface GroupSoftwareRule {
  id: string
  software_name: string
  rule_type: "allowed" | "forbidden"
}

export interface DeviceGroup {
  id: string
  name: string
  color: string
  created_at: string
  device_ids: string[]
  policy_ids: string[]
  software_rules: GroupSoftwareRule[]
}

// PolicyDeviceCompliance — разрез одного софт-правила по устройствам
// (GET /policies/{id}/compliance): кто в области действия, у кого что совпало.
export interface PolicyDeviceCompliance {
  device_id: string
  hostname: string
  os: string
  status: string
  installed: boolean
  matched_software: string
  matched_version: string
}

// SoftwarePolicyCompliance — счётчики Pass/Fail софт-правила (GET /policies/compliance).
// checked=false у правил-разрешений: агент проверяет только forbidden-список, так что
// pass/fail для них не считаются и в UI показывается прочерк, а не выдуманный ноль.
export interface SoftwarePolicyCompliance {
  rule_id: string
  in_scope: number
  pass: number
  fail: number
  checked: boolean
}

// ScriptPolicyCompliance — Pass/Fail скрипт-политики по последнему прогону на устройстве
// (GET /script-policies/compliance). unknown — назначено, но результата ещё нет.
export interface ScriptPolicyCompliance {
  policy_id: string
  in_scope: number
  pass: number
  fail: number
  unknown: number
}

// LicenseStatus — снимок энтайтлмента (GET/POST /license, только enterprise-сборка;
// в open-core роута нет → 404). Два флага, а не один: configured=лицензия валидно
// подписана и активирована, valid=она ещё и в сроке. Их пара различает «истекла»
// (configured && !valid) и «не задана» (!configured) — состояния с разным текстом и
// разными действиями в UI. Пустой features = вся редакция (семантика Claims.Has).
// persist_warning приходит только с POST: лицензия применена live, но не легла на
// диск и не переживёт рестарт — это не ошибка запроса, но молчать о ней нельзя.
export interface LicenseStatus {
  configured: boolean
  valid: boolean
  licensee?: string
  edition?: string
  features?: string[]
  // Не опционально, хотя в Go у поля стоит omitempty: encoding/json игнорирует omitempty
  // на структурах, а time.Time — структура. Лицензия без срока приезжает не как
  // отсутствующее поле, а как "0001-01-01T00:00:00Z" (см. hasExpiry в License.tsx).
  expires_at: string
  seats?: number
  persist_warning?: string
}
