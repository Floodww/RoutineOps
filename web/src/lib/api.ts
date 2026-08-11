import i18n from "@/i18n/config"
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
  return i18n.t("common.unknownError")
}

// errStatus — HTTP-код ошибки (0, если ответа не было). Нужен, чтобы отличить
// «роута нет в этой сборке» (404) от настоящего сбоя.
export function errStatus(e: unknown): number {
  return axios.isAxiosError(e) ? (e.response?.status ?? 0) : 0
}

// PAGE_SIZE — размер страницы постраничных списков. Совпадает с серверным дефолтом
// (storage.DefaultPageLimit): расхождение выглядело бы как «пагинация врёт».
export const PAGE_SIZE = 50

// totalCount — общее число записей под фильтром из заголовка X-Total-Count.
// Заголовка нет (старый сервер, прокси его срезал) — считаем, что всё уместилось
// на текущей странице: пагинатор тогда просто не рисуется, а не врёт нулём.
export function totalCount(headers: unknown, fallback: number): number {
  const raw = (headers as Record<string, unknown> | undefined)?.["x-total-count"]
  const n = Number(raw)
  return Number.isFinite(n) && n >= 0 ? n : fallback
}

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem("session")
      // 🔴 На публичных страницах редирект НЕ делаем. Иначе 401 от фонового запроса
      // самой такой страницы даёт бесконечную перезагрузку: страница логина
      // спрашивает список SSO-провайдеров, а ручка /api/v1/oidc/providers сидит под
      // requireRole("it_admin") → 401 → редирект на /login → страница снова
      // спрашивает провайдеров. Поймано на проде 30.07 сразу после перехода на
      // enterprise-сборку: в open-core этой ручки нет вовсе, 404 редирект не
      // вызывал, и петля не проявлялась. Свой .catch() у страницы не спасает —
      // интерсептор срабатывает раньше.
      const PUBLIC_PATHS = ["/login", "/forgot-password", "/reset-password", "/accept-invite"]
      if (!PUBLIC_PATHS.some((p) => window.location.pathname.startsWith(p))) {
        window.location.href = "/login"
      }
      return Promise.reject(err)
    }
    // Авто-тост только для мутаций (POST/PUT/PATCH/DELETE) — действий пользователя.
    // Фоновые GET обрабатываются страницами (loading/catch), их не шумим.
    const method = (err.config?.method ?? "get").toLowerCase()
    if (method !== "get") {
      toast({ title: i18n.t("common.error"), description: errMessage(err), variant: "destructive" })
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
  active: { label: "deviceStatus.active",              variant: "success",     dot: "bg-emerald-500" },
  enrolled: { label: "deviceStatus.enrolled",      variant: "default",     dot: "bg-blue-500"    },
  pending: { label: "deviceStatus.pending",              variant: "secondary",   dot: "bg-slate-400"   },
  pending_approval: { label: "deviceStatus.pending_approval",    variant: "secondary",   dot: "bg-amber-500"   },
  rejected: { label: "deviceStatus.rejected",            variant: "destructive", dot: "bg-rose-600"    },
  blocked: { label: "deviceStatus.blocked",         variant: "destructive", dot: "bg-red-500"     },
  decommissioned: { label: "deviceStatus.decommissioned", variant: "outline",  dot: "bg-slate-500"   },
}

export interface Device {
  id: string
  hostname: string
  os: string
  os_version: string
  ip_address: string
  status: DeviceStatus
  // Заполняется в GET /devices/across-tenants (и может отсутствовать в обычном списке).
  tenant_id?: string
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
  // Кто сейчас за консолью (Windows — DOMAIN\user; darwin/linux — логин активной сессии).
  // "" / отсутствует = за консолью никого либо сервер старой версии поля не отдаёт.
  console_user?: string
  // Владелец — карточка человека (Person), а не аккаунт панели. В Enterprise её приносит
  // синк AD, во Free оператор заводит руками; поле одно и то же.
  // Отсутствуют у сервера старой версии.
  owner_person_id?: string
  owner_person_name?: string
  owner_person_email?: string
  // Устройство может состоять в нескольких группах. Может отсутствовать: сервер старой
  // версии поля не отдаёт, а только что созданное pending-устройство держим локально.
  groups?: DeviceGroupRef[]
  // Durable-очередь агента недоступна: отчёты, статусы лока и security-события с этой
  // машины НЕ доходят. Приходит и в списке, и в карточке — в отличие от инвентарных
  // полей. Отсутствует у сервера старой версии; трактуем отсутствие как «всё в порядке»
  // (агент старой версии признак тоже не шлёт, и выдумывать деградацию нельзя).
  outbox_unavailable?: boolean
  degraded_detail?: string
  degraded_since?: string | null
}

// Каталог (LDAP) — только enterprise-сборка; в open-core ручки /directory/* → 501, а
// страница «Каталог» показывает «недоступно в этой редакции». Bind-пароль сюда НЕ входит
// (секрет, живёт в rw-томе сервера); has_password лишь говорит, задан ли он.
export interface DirectoryConfig {
  enabled: boolean
  url: string
  bind_dn: string
  base_dn: string
  user_filter: string
  sync_interval_min: number
  has_password: boolean
  // Транспорт. ldaps:// в url = неявный TLS; ldap:// + start_tls = апгрейд открытого
  // соединения. Корневой сертификат отправляется write-only полем ca_cert_pem, наружу
  // возвращается только признак has_ca_cert — как и bind-пароль.
  start_tls: boolean
  has_ca_cert: boolean
  // Вход в панель по паролю каталога. Отдельно от enabled: синк персон и приём пароля
  // на вход — разные по риску вещи. Сервер требует шифрованного канала (ldaps:// либо
  // ldap:// + start_tls) и отбивает флаг при выключенном каталоге.
  login_enabled: boolean
}

export interface DirectorySyncResult {
  synced: number
  disabled: number
  matched: number
}

// Person — человек, за которым числятся устройства. Входа в панель у него НЕТ: аккаунты
// (users) нужны тем, кто в неё ходит. source различает происхождение: "ldap" — принёс
// синк каталога (правится в AD), "manual" — завёл оператор (правится здесь).
export interface Person {
  id: string
  object_guid: string
  object_sid: string
  sam_account: string
  user_principal: string
  display_name: string
  email: string
  distinguished_name: string
  disabled: boolean
  source: "ldap" | "manual"
}

/** @deprecated историческое имя Person — сущность одна, наполняется и синком, и вручную. */
export type DirectoryPerson = Person

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

// Выпущенный массовый токен в списке. Самого секрета тут НЕТ (в БД только хеш) —
// показываем то, что нужно оператору: куда заводит, сколько раз сработал, когда умрёт.
export interface BulkEnrollmentToken {
  id: string
  group_id: string
  group_name: string
  max_uses: number | null
  uses: number
  require_approval: boolean
  expires_at: string
  created_at: string
}

export interface ReenrollResponse {
  enrollment_token: string
  expires_at: string
}

export interface Software {
  name: string
  version: string
  vendor?: string
  install_location?: string
  arch?: string           // в диалекте источника: amd64 / x86_64 / noarch / universal
  uninstall_id?: string
  uninstall_method?: string // пусто = снять нечем
  scope?: string            // machine / user; user снять нечем даже с правами
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
  // Исход удаления ПО — отдельным полем, а не текстом в output: разные исходы требуют
  // РАЗНЫХ действий оператора (обновить инвентарь / уточнить цель / делать нечего), и
  // по прозе это не разбирается. Пусто — задача не про удаление либо отчёта ещё не было.
  uninstall_outcome?: string
  // Что именно сносили. Заполнено только у uninstall-задач.
  uninstall?: {
    software_name: string
    version?: string
    uninstall_id?: string
    install_location?: string
    uninstall_method?: string
    scope?: string
    reason?: string
  }
}

// UNINSTALL_OUTCOME — человеческие подписи к исходам. 🔴 still_present против failed —
// различие безопасности, а не формулировки: деинсталлятор мог отчитаться успехом, а ПО
// осталось (msiexec возвращает 0 на снос, отложенный до перезагрузки; pkgutil --forget
// чистит только квитанцию). Агент отчитывается по ПОВТОРНОМУ снимку, а не по коду
// возврата, и подпись обязана это сохранить.
export const UNINSTALL_OUTCOME: Record<string, { label: string; hint: string }> = {
  removed: { label: "uninstallOutcome.removed", hint: "uninstallOutcome.removedHint" },
  already_absent: { label: "uninstallOutcome.already_absent", hint: "uninstallOutcome.already_absentHint" },
  target_changed: { label: "uninstallOutcome.target_changed", hint: "uninstallOutcome.target_changedHint" },
  ambiguous: { label: "uninstallOutcome.ambiguous", hint: "uninstallOutcome.ambiguousHint" },
  not_removable: { label: "uninstallOutcome.not_removable", hint: "uninstallOutcome.not_removableHint" },
  self_protected: { label: "uninstallOutcome.self_protected", hint: "uninstallOutcome.self_protectedHint" },
  failed: { label: "uninstallOutcome.failed", hint: "uninstallOutcome.failedHint" },
  still_present: { label: "uninstallOutcome.still_present", hint: "uninstallOutcome.still_presentHint" },
}

export type AlertSeverity = "critical" | "high" | "medium" | "low"

export interface Alert {
  id: string
  device_id: string
  device_hostname: string
  alert_type: string
  // severity фиксируется сервером в момент создания (миграция 041). Тип строкой,
  // а не AlertSeverity: сервер хранит её свободным TEXT под CHECK, и агент новее
  // сервера может прислать событие, которому сервер выдаст значение вне шкалы.
  // Клиент обязан это пережить, а не упасть на сужении типа.
  severity: string
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
  baseline_captured_at: string | null
  changes_final_at: string | null
  changes_completeness: string
  changes_rebooted: boolean
  changes_truncated: boolean
  software_health: string
  services_health: string
  last_window_seq: number
}

export interface AdminSessionChange {
  window_seq: number
  kind: string
  subject: string
  display_name: string
  identity_key: string
  old_value: string
  new_value: string
  vendor: string
  scope: string
  attribution: string
  attribution_reason: string
  observed_at: string
}

export interface AdminAccessEvidence {
  baseline_captured_at: string | null
  changes_final_at: string | null
  changes_summary: Record<string, unknown>
  changes_completeness: string
  changes_rebooted: boolean
  changes_truncated: boolean
  software_health: string
  services_health: string
  last_window_seq: number
}

export interface AdminSessionChangesResponse {
  evidence: AdminAccessEvidence
  changes: AdminSessionChange[]
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

// Канон совпадает с политиками ПО: macOS | Windows | Linux. Раньше здесь была строчная
// "linux", а /policies требовал "Linux" — две соседние ручки отвечали 400 на вариант
// соседа. Сервер теперь принимает любой регистр и нормализует (canonicalPlatform).
export type ScriptPlatform = "macOS" | "Windows" | "Linux"

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
// Регистр сравнивается нечувствительно НАМЕРЕННО: канон теперь "Linux", но в БД до
// одноразовой миграции остаются скрипты со старым значением "linux". При точном сравнении
// такой скрипт уезжал бы на устройство как darwin — то есть Linux-скрипт с чужим
// интерпретатором. Поймано тестом при смене канона.
export function agentPlatform(p: ScriptPlatform | string): "darwin" | "windows" | "linux" {
  const v = String(p).toLowerCase()
  if (v === "windows") return "windows"
  if (v === "linux") return "linux"
  return "darwin"
}

// deviceRunsScript решает, доступен ли скрипт для устройства с данной ОС.
// Windows-устройство запускает только Windows/.ps1; macOS и Linux — shell-семейство
// (macOS + linux), как «macOS & Linux» во Fleet.
// platform принимает и строку: до миграции данных в БД лежат скрипты со старым значением
// "linux", и они обязаны оставаться доступными Linux- и macOS-устройствам (сравнение идёт
// с "Windows", поэтому логика от регистра не зависит — а вот тип зависел бы).
export function deviceRunsScript(deviceOS: string, platform: ScriptPlatform | string): boolean {
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

// Заэскроенный секрет FileVault (Enterprise). В свободной редакции ручек нет вовсе —
// GET отвечает 404, и карточка просто не показывает раздел.
// Уязвимость, найденная на устройстве (Q-50). Поля — как их отдаёт
// GET /devices/{id}/vulnerabilities: сама CVE плюс имя ПО, из-за которого она сюда
// попала (одна CVE может прийти от разных пакетов).
export interface Vulnerability {
  cve_id: string
  software_name: string
  detected_at: string
  description: string
  cvss_score?: number | null
}

export interface EscrowRecord {
  id: string
  secret_type: string   // prk | secondary_cred
  recipient_fpr: string
  key_scheme: string
  agent_version?: string
  escrowed_at: string
  revealed_at?: string
  revealed_by?: string  // email того, кто выгружал
  latest: boolean       // именно эта строка отдастся на выгрузку
}

export interface EscrowReveal extends EscrowRecord {
  device_id: string
  ciphertext_b64: string
}

// Интерактивный сеанс с рабочим столом (ADR-8). Только Enterprise: в open-core ручек
// /screen-sessions нет вовсе, и вкладка это увидит по 404, а не по флагу редакции.
export interface ScreenSession {
  id: string
  device_id: string
  operator_id?: string
  operator_email: string
  reason: string
  mode: string // unattended | consent_required
  profile: string
  status: string // requested | active | ended
  end_reason?: string
  end_detail?: string
  task_id?: string
  width?: number
  height?: number
  frames: number
  bytes: number
  has_recording: boolean
  // Запись оборвана до конца сеанса. Видно ДО скачивания намеренно: узнать о неполноте
  // улики, уже открыв её, — поздно, а в режиме unattended запись это единственное, чем
  // восстанавливают, что видел оператор.
  recording_truncated?: boolean
  recording_truncated_reason?: string
  // Размер файла записи. Нужен оператору до скачивания: запись часового сеанса и
  // запись, оборвавшаяся на первой минуте, в списке выглядят одинаково.
  recording_bytes?: number
  // Агент не опознал запрошенный профиль и взял low — расхождение версий сервера и
  // агента. Без этого признака оно выглядит как «удалёнка стала хуже показывать».
  profile_fallback?: boolean
  // Когда агент последний раз отчитывался о ходе сеанса.
  telemetry_at?: string
  created_at: string
  started_at?: string
  ended_at?: string
  // Пусто = вопрос не задавался (режим unattended). Это НЕ «нет ответа»: сеанс без
  // спрошенного согласия и сеанс, где сотрудник промолчал, — разные события.
  consent_state?: string
  consent_at?: string
  // Сеанс запрошен С УПРАВЛЕНИЕМ (Ф3). Объявляется приглашением один раз: расширить
  // область на лету нельзя, поэтому «взять управление» — это всегда новый сеанс.
  control?: boolean
  // Момент возврата управления сотруднику. Закрывает окно, за которое отвечает оператор,
  // раньше конца сеанса.
  control_returned_at?: string
}

// Одна строка журнала ввода (§9.21). Печатные символы здесь ОТСУТСТВУЮТ по построению:
// для kind="text" едет только количество символов, потому что пароль, введённый
// оператором в чужую машину, не должен лежать у нас в базе открытым текстом.
export interface ScreenInputEntry {
  kind: string
  detail?: string
  events: number
  offset_ms: number
  at?: string
}

// Коды завершения сеанса (§7 контракта). Ключ i18n, а не готовая строка: причина едет
// кодом ровно затем, чтобы её можно было отрисовать на языке оператора, а не подстрокой
// из агентского сообщения.
export const SCREEN_END_REASON: Record<string, string> = {
  USER_TERMINATED: "screenSession.end.userTerminated",
  OPERATOR_STOPPED: "screenSession.end.operatorStopped",
  CONSENT_DENIED: "screenSession.end.consentDenied",
  CONSENT_TIMEOUT: "screenSession.end.consentTimeout",
  CONSENT_UNAVAILABLE: "screenSession.end.consentUnavailable",
  NOTICE_UNAVAILABLE: "screenSession.end.noticeUnavailable",
  SESSION_LOCKED: "screenSession.end.sessionLocked",
  USER_SWITCHED: "screenSession.end.userSwitched",
  SESSION_DISCONNECTED: "screenSession.end.sessionDisconnected",
  AGENT_UPDATE: "screenSession.end.agentUpdate",
  MAX_DURATION: "screenSession.end.maxDuration",
  SCOPE_VIOLATION: "screenSession.end.scopeViolation",
  WAYLAND_UNSUPPORTED: "screenSession.end.waylandUnsupported",
  NO_CONSOLE_USER: "screenSession.end.noConsoleUser",
  SECURE_DESKTOP: "screenSession.end.secureDesktop",
  SCREEN_RECORDING_DENIED: "screenSession.end.screenRecordingDenied",
  PLATFORM_UNSUPPORTED: "screenSession.end.platformUnsupported",
  BLANK_SCREEN: "screenSession.end.blankScreen",
  WORKER_LOST: "screenSession.end.workerLost",
  CAPTURE_FAILED: "screenSession.end.captureFailed",
  SESSION_BUSY: "screenSession.end.sessionBusy",
  VIEWER_GONE: "screenSession.end.viewerGone",
  DEVICE_CUT_OFF: "screenSession.end.deviceCutOff",
  OPERATOR_REVOKED: "screenSession.end.operatorRevoked",
  AGENT_GONE: "screenSession.end.agentGone",
  PROTOCOL_ERROR: "screenSession.end.protocolError",
  RECORDING_FAILED: "screenSession.end.recordingFailed",
  RECORDING_QUOTA: "screenSession.end.recordingQuota",
  INPUT_UNAVAILABLE: "screenSession.end.inputUnavailable",
  ACCESSIBILITY_DENIED: "screenSession.end.accessibilityDenied",
}

// Почему запись неполная. Ключи i18n, как и коды завершения: причина едет кодом, чтобы
// её показать на языке оператора.
export const SCREEN_TRUNCATION: Record<string, string> = {
  quota: "screenSession.truncated.quota",
  tenant_quota: "screenSession.truncated.tenantQuota",
  io_error: "screenSession.truncated.ioError",
}

// Исход согласия сотрудника (§4). Пустая строка сюда не попадает намеренно: «вопрос не
// задавался» — это не исход, и рисовать его как исход значит утверждать, что сотрудника
// спросили.
export const SCREEN_CONSENT: Record<string, string> = {
  GRANTED: "screenSession.consent.granted",
  DENIED: "screenSession.consent.denied",
  TIMEOUT: "screenSession.consent.timeout",
  UNAVAILABLE: "screenSession.consent.unavailable",
}

// Режим доступа к экрану, потолок профиля и состояние квоты записей — свойства ТЕНАНТА
// (§4, §5, §10).
export interface ScreenAccessPolicy {
  mode: "unattended" | "consent_required"
  // profile_cap — ПОТОЛОК, а не значение: сервер выдаёт профиль в приглашении не выше
  // него. Отсутствует у сервера до 075 — трактуем как low, то есть как поведение до
  // появления настройки, а не как «потолок неизвестен».
  profile_cap?: "low" | "medium"
  recording_used: number
  recording_quota: number
  recording_retention: number
}

// Отзываемый грант на просмотр записей. До появления ручки колонка не имела ни одного
// места записи: записи велись, а открыть их не мог никто.
export interface ScreenRecordingGrant {
  user_id: string
  email: string
  role: string
  can_view_session_recording: boolean
}

export const ESCROW_SECRET_TYPE: Record<string, string> = {
  prk: "escrowSecret.prk",
  secondary_cred: "escrowSecret.secondary_cred",
}

// Отсрочки перезагрузки. «Немедленно» — это 10 секунд, а не ноль: ноль на проводе
// означает «дефолт агента» (минута), и посылать его как «сейчас» значило бы сделать
// нулевое значение самым деструктивным вариантом. Ноль в списке не предлагаем вовсе —
// отсрочка и есть защита несохранённой работы сотрудника.
export const REBOOT_DELAYS = [
  { value: 60, label: "rebootDelay.m1" },
  { value: 300, label: "rebootDelay.m5" },
  { value: 900, label: "rebootDelay.m15" },
  { value: 3600, label: "rebootDelay.h1" },
  { value: 10, label: "rebootDelay.now" },
]

// REBOOT_GROUP_MAX_DEVICES — тот же потолок, что и на сервере (rebootGroupMaxDevices).
// Дубль осознанный: без него оператор узнавал бы о лимите из сырого 422 в тосте.
export const REBOOT_GROUP_MAX_DEVICES = 50

export interface DeviceGroup {
  id: string
  name: string
  color: string
  // Канал обновлений участников группы (Q-52). Устройство в beta-группе получает
  // канареечный релиз раньше остального парка. Отсутствует у сервера до 065 —
  // трактуем как stable, а не как «канал неизвестен»: единственный безопасный дефолт.
  update_channel?: UpdateChannel
  created_at: string
  device_ids: string[]
  policy_ids: string[]
  software_rules: GroupSoftwareRule[]
}

export type UpdateChannel = "stable" | "beta"

export const UPDATE_CHANNEL_LABEL: Record<UpdateChannel, string> = {
  stable: "updateChannel.stable",
  beta: "updateChannel.beta",
}

// VersionCount — сколько машин канала сидит на этой версии агента.
export interface VersionCount {
  version: string
  count: number
}

// ChannelTarget — что канал отдаст агенту этой платформы прямо сейчас.
export interface ChannelTarget {
  os: string
  arch: string
  version: string
}

export interface ChannelRollout {
  channel: UpdateChannel
  groups: number
  devices: number
  versions: VersionCount[]
  targets: ChannelTarget[]
}

export interface AgentReleaseRow {
  os: string
  arch: string
  version: string
  channel: UpdateChannel
  sha256: string
  created_at: string
}

export interface UpdateRollout {
  channels: ChannelRollout[]
  releases: AgentReleaseRow[]
}

// Отчёт соответствия (Q-62). Считает сервер: страница только показывает.
export interface DeviceCompliance {
  device_id: string
  hostname: string
  os: string
  os_version: string
  agent_version: string
  update_channel: UpdateChannel
  status: string
  last_seen_at: string | null
  vulnerable_count: number
  unverified_count: number
  compliant: boolean
  reasons: string[]
}

export interface ComplianceSummary {
  devices: number
  compliant: number
  non_compliant: number
  by_reason: Record<string, number>
  generated_at: string
  stale_after_days: number
}

export interface ComplianceReport {
  summary: ComplianceSummary
  devices: DeviceCompliance[]
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
  matched_scope: string // 'user' = установка в профиль, снять нельзя
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
