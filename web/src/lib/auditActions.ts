import i18n from "@/i18n/config"

// Единый словарь действий журнала: подписи и категории.
//
// Раньше карта жила ДВУМЯ копиями — в Dashboard.tsx и AuditLog.tsx. Они успели
// разойтись и в наборе (в ленте обзора было `delete_device`, в журнале нет), и в
// падеже. Хуже другое: неизвестное действие обе страницы рисуют как есть, то есть
// СЫРЫМ английским именем и без категории — серым. Так журнал и оказался наполовину
// английским: подписи просто не поспевали за новыми действиями (тенанты,
// переключение, удаление ПО, OIDC, владельцы). Одна карта на оба места убирает
// расхождение как класс.
//
// Подписи хранятся в нижнем регистре: лента обзора читает их фразой
// («админ <действие>»), журналу нужна заглавная — берётся actionLabelCap().
//
// Значения карты — КЛЮЧИ словаря, а не готовый текст: t() на уровне модуля
// недоступен, а сам текст обязан следовать выбранному языку. Перевод берётся в
// момент вызова через инстанс i18n; экраны журнала и ленты вызывают
// useTranslation, поэтому смена языка перерисовывает их вместе с подписями.

export type EventCategory = "security" | "auth" | "admin" | "device" | "content"

export const ACTION_LABELS: Record<string, string> = {
  // --- устройства ---
  create_device: "auditAction.create_device",
  delete_device: "auditAction.delete_device",
  reenroll_device: "auditAction.reenroll_device",
  decommission_device: "auditAction.decommission_device",
  approve_device: "auditAction.approve_device",
  reject_device: "auditAction.reject_device",
  block_device: "auditAction.block_device",
  unblock_device: "auditAction.unblock_device",
  lock_device: "auditAction.lock_device",
  unlock_device: "auditAction.unlock_device",
  reboot_device: "auditAction.reboot_device",
  reboot_group: "auditAction.reboot_group",
  set_device_owner: "auditAction.set_device_owner",
  uninstall_software: "auditAction.uninstall_software",

  // --- энроллмент ---
  create_bulk_token: "auditAction.create_bulk_token",
  revoke_enrollment_token: "auditAction.revoke_enrollment_token",
  approve_pending_bulk: "auditAction.approve_pending_bulk",
  reject_pending_bulk: "auditAction.reject_pending_bulk",

  // --- группы ---
  create_device_group: "auditAction.create_device_group",
  update_device_group: "auditAction.update_device_group",
  delete_device_group: "auditAction.delete_device_group",
  add_device_to_group: "auditAction.add_device_to_group",
  remove_device_from_group: "auditAction.remove_device_from_group",
  assign_policy_to_group: "auditAction.assign_policy_to_group",
  unassign_policy_from_group: "auditAction.unassign_policy_from_group",
  assign_software_policy_to_group: "auditAction.assign_software_policy_to_group",
  unassign_software_policy_from_group: "auditAction.unassign_software_policy_from_group",

  // --- скрипты и политики ---
  create_script: "auditAction.create_script",
  update_script: "auditAction.update_script",
  delete_script: "auditAction.delete_script",
  run_script: "auditAction.run_script",
  run_script_on_group: "auditAction.run_script_on_group",
  create_policy: "auditAction.create_policy",
  delete_policy: "auditAction.delete_policy",
  create_script_policy: "auditAction.create_script_policy",
  delete_script_policy: "auditAction.delete_script_policy",
  enable_script_policy: "auditAction.enable_script_policy",
  disable_script_policy: "auditAction.disable_script_policy",

  // --- доступ и аутентификация ---
  login: "auditAction.login",
  logout: "auditAction.logout",
  login_failed: "auditAction.login_failed",
  change_password: "auditAction.change_password",
  password_reset_requested: "auditAction.password_reset_requested",
  password_reset: "auditAction.password_reset",
  invite_user: "auditAction.invite_user",
  accept_invite: "auditAction.accept_invite",
  create_api_token: "auditAction.create_api_token",
  revoke_api_token: "auditAction.revoke_api_token",
  approve_admin_request: "auditAction.approve_admin_request",
  reject_admin_request: "auditAction.reject_admin_request",
  revoke_admin_request: "auditAction.revoke_admin_request",

  // --- тенанты (ADR-6/ADR-7) ---
  // 🔴 Имена с точкой — как их пишет сервер. Переименовывать нельзя: в журнале уже
  // лежит история с этими строками, а журнал tamper-evident и правке не подлежит.
  "tenant.create": "auditAction.tenant_create",
  "tenant.rename": "auditAction.tenant_rename",
  "tenant.delete": "auditAction.tenant_delete",
  "devices.list_across_tenants": "auditAction.devices_list_across_tenants",
  switch_tenant: "auditAction.switch_tenant",
  switch_tenant_denied: "auditAction.switch_tenant_denied",
  move_device_tenant: "auditAction.move_device_tenant",

  // --- SSO / OIDC ---
  create_oidc_provider: "auditAction.create_oidc_provider",
  update_oidc_provider: "auditAction.update_oidc_provider",
  delete_oidc_provider: "auditAction.delete_oidc_provider",
  create_saml_provider: "auditAction.create_saml_provider",
  update_saml_provider: "auditAction.update_saml_provider",
  delete_saml_provider: "auditAction.delete_saml_provider",
  create_siem_integration: "auditAction.create_siem_integration",
  update_siem_integration: "auditAction.update_siem_integration",
  delete_siem_integration: "auditAction.delete_siem_integration",
  test_siem_integration: "auditAction.test_siem_integration",

  // --- удалённый рабочий стол (ADR-8) ---
  screen_session_requested: "auditAction.screen_session_requested",
  screen_recording_viewed: "auditAction.screen_recording_viewed",
  screen_recording_view_denied: "auditAction.screen_recording_view_denied",
  screen_session_foreign_claim: "auditAction.screen_session_foreign_claim",
  screen_session_operator_revoked: "auditAction.screen_session_operator_revoked",
  screen_event_foreign_session: "auditAction.screen_event_foreign_session",

  // --- владельцы и пользователи ---
  delete_person: "auditAction.delete_person",
  update_person: "auditAction.update_person",
  delete_user: "auditAction.delete_user",
  update_script_policy: "auditAction.update_script_policy",

  // --- второй фактор и каталог ---
  login_mfa_pending: "auditAction.login_mfa_pending",
  mfa_disabled: "auditAction.mfa_disabled",
  mfa_recovery_code_used: "auditAction.mfa_recovery_code_used",
  scim_create_user: "auditAction.scim_create_user",
  scim_update_user: "auditAction.scim_update_user",
  scim_deactivate_user: "auditAction.scim_deactivate_user",
  scim_delete_user: "auditAction.scim_delete_user",
  set_directory_config: "auditAction.set_directory_config",
  sync_directory: "auditAction.sync_directory",

  // --- удалённый стол: доступ и управление ---
  screen_access_mode_changed: "auditAction.screen_access_mode_changed",
  screen_profile_cap_changed: "auditAction.screen_profile_cap_changed",
  screen_recording_grant_granted: "auditAction.screen_recording_grant_granted",
  screen_recording_grant_revoked: "auditAction.screen_recording_grant_revoked",
  screen_session_consent: "auditAction.screen_session_consent",
  screen_session_control_granted: "auditAction.screen_session_control_granted",
  screen_session_control_returned: "auditAction.screen_session_control_returned",

  // --- события от агента и FileVault ---
  admin_session_changes_final: "auditAction.admin_session_changes_final",
  late_task_result: "auditAction.late_task_result",
  lock_failed: "auditAction.lock_failed",
  arm_lock_secrets: "auditAction.arm_lock_secrets",
  filevault_revoked: "auditAction.filevault_revoked",
  filevault_revoke_failed: "auditAction.filevault_revoke_failed",
  filevault_not_armed: "auditAction.filevault_not_armed",
  filevault_secret_mismatch: "auditAction.filevault_secret_mismatch",
  reveal_escrow: "auditAction.reveal_escrow",
  reveal_escrow_denied: "auditAction.reveal_escrow_denied",

  // --- прочее ---
  create_person: "auditAction.create_person",
  acknowledge_alert: "auditAction.acknowledge_alert",
  set_notify_min_severity: "auditAction.set_notify_min_severity",
  apply_license: "auditAction.apply_license",
  deactivate_license: "auditAction.deactivate_license",
}

export const ACTION_CATEGORY: Record<string, EventCategory> = {
  // security — то, что расширяет доступ или сигнализирует о попытке его получить.
  login_failed: "security",
  block_device: "security",
  lock_device: "security",
  create_bulk_token: "security",
  revoke_enrollment_token: "security",
  approve_device: "security",
  approve_pending_bulk: "security",
  create_api_token: "security",
  revoke_api_token: "security",
  // Чужой тенант — граница доступа, а не «контент».
  switch_tenant_denied: "security",
  uninstall_software: "security",
  // 🔴 devices.list_across_tenants СОЗНАТЕЛЬНО не security и не в ленте (FEED_HIDDEN).
  // Это ЧТЕНИЕ надзорного списка своим же provider_admin: строка пишется на каждый
  // GET, а поиск на странице дебаунсится — то есть одно уточнение запроса давало
  // отдельное красное «событие безопасности» про самого оператора. Красный цвет,
  // который загорается от собственной навигации, обесценивает красный цвет вообще.
  // В журнале запись остаётся: кто и когда смотрел парк целиком — это аудит.
  "devices.list_across_tenants": "admin",

  login: "auth",
  logout: "auth",
  change_password: "auth",
  password_reset: "auth",
  password_reset_requested: "auth",
  switch_tenant: "auth",

  invite_user: "admin",
  accept_invite: "admin",
  approve_admin_request: "admin",
  reject_admin_request: "admin",
  revoke_admin_request: "admin",
  "tenant.create": "admin",
  "tenant.rename": "admin",
  "tenant.delete": "admin",
  apply_license: "admin",
  deactivate_license: "admin",
  set_notify_min_severity: "admin",
  create_oidc_provider: "admin",
  update_oidc_provider: "admin",
  delete_oidc_provider: "admin",
  create_saml_provider: "admin",
  update_saml_provider: "admin",
  delete_saml_provider: "admin",
  create_siem_integration: "security",
  update_siem_integration: "security",
  delete_siem_integration: "security",
  test_siem_integration: "security",
  // Наблюдение за экраном сотрудника и доступ к записи — расширение доступа, а не
  // рутина по устройству: в режиме unattended аудит остаётся ЕДИНСТВЕННЫМ механизмом
  // подотчётности, и в ленте это должно быть видно категорией.
  screen_session_requested: "security",
  screen_recording_viewed: "security",
  screen_recording_view_denied: "security",
  screen_session_foreign_claim: "security",
  screen_session_operator_revoked: "security",
  screen_event_foreign_session: "security",

  // Раскрытие ключа восстановления, второй фактор и права на записи сеансов — это
  // расширение доступа либо попытка его получить, а не рутина: в ленте они обязаны быть
  // видны категорией, а не теряться серым «контентом».
  reveal_escrow: "security",
  reveal_escrow_denied: "security",
  mfa_disabled: "security",
  mfa_recovery_code_used: "security",
  screen_access_mode_changed: "security",
  screen_profile_cap_changed: "security",
  screen_recording_grant_granted: "security",
  screen_recording_grant_revoked: "security",
  screen_session_consent: "security",
  screen_session_control_granted: "security",
  screen_session_control_returned: "security",
  arm_lock_secrets: "security",
  filevault_revoked: "security",
  filevault_secret_mismatch: "security",

  login_mfa_pending: "auth",

  delete_person: "admin",
  update_person: "admin",
  delete_user: "admin",
  scim_create_user: "admin",
  scim_update_user: "admin",
  scim_deactivate_user: "admin",
  scim_delete_user: "admin",
  set_directory_config: "admin",
  sync_directory: "admin",

  create_device: "device",
  delete_device: "device",
  reenroll_device: "device",
  unblock_device: "device",
  unlock_device: "device",
  reject_device: "device",
  reject_pending_bulk: "device",
  decommission_device: "device",
  reboot_device: "device",
  reboot_group: "device",
  set_device_owner: "device",
  move_device_tenant: "device",
  run_script: "device",
  run_script_on_group: "device",
  create_device_group: "device",
  update_device_group: "device",
  delete_device_group: "device",
  add_device_to_group: "device",
  remove_device_from_group: "device",
  create_person: "device",
  lock_failed: "device",
  filevault_revoke_failed: "device",
  filevault_not_armed: "device",
  late_task_result: "device",
  admin_session_changes_final: "device",
  // всё остальное (скрипты/политики/алерты) — content по умолчанию
}

/** actionLabel — подпись действия в нижнем регистре; неизвестное отдаём как есть. */
export function actionLabel(action: string): string {
  const key = ACTION_LABELS[action]
  return key ? i18n.t(key) : action
}

/** actionLabelCap — то же с заглавной буквы (журнал показывает действие колонкой). */
export function actionLabelCap(action: string): string {
  const s = actionLabel(action)
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** actionCategory — категория для иконки и цвета; по умолчанию content. */
export function actionCategory(action: string): EventCategory {
  return ACTION_CATEGORY[action] ?? "content"
}

/**
 * FEED_HIDDEN — действия, которые не показываются в ленте дашборда.
 *
 * Лента отвечает на вопрос «что происходит с парком», а не «куда я только что
 * кликнул». Сюда попадает ЧТЕНИЕ, которое аудит обязан записать (кросс-тенантный
 * просмотр — это доступ ко всем тенантам сразу), но которое порождается самой
 * навигацией оператора и потому вытесняет из ленты реальные события.
 *
 * Скрытие только на этой поверхности: страница журнала показывает всё.
 */
export const FEED_HIDDEN = new Set<string>(["devices.list_across_tenants"])

/** hiddenFromFeed — фильтр ленты дашборда. */
export function hiddenFromFeed(action: string): boolean {
  return FEED_HIDDEN.has(action)
}

/**
 * eventNumber — человекочитаемый номер события журнала.
 *
 * Формат `00000000-00000000-00000000-00000001`: десятичный счётчик, разбитый по
 * восемь цифр. Берётся из `seq` — номера записи в хеш-цепочке ТЕНАНТА, а не из
 * uuid: uuid не продиктуешь по телефону и не сверишь на слух, а «событие
 * ...-00000001» сверяется. Нумерация пер-тенантная — как и сама цепочка, поэтому
 * один и тот же номер в разных тенантах это разные события.
 *
 * Переполнения не бывает: seq — bigint, его потолок (~9.2·10^18) на порядки ниже
 * ёмкости формата (10^32), поэтому «сброс счётчика после 99999999-…» — правило,
 * которое не может сработать, и обнуления здесь нет намеренно: счётчик, который
 * когда-либо повторяется, ломает и ссылку на событие, и порядок цепочки.
 *
 * seq = null — строка старше цепочки (миграция 042 нумерует с момента введения).
 * Такие показываем прочерком: ноль был бы неотличим от настоящего первого события.
 */
export function eventNumber(seq: number | null | undefined): string {
  if (seq === null || seq === undefined) return "—"
  const digits = String(seq).padStart(32, "0")
  return [0, 8, 16, 24].map((i) => digits.slice(i, i + 8)).join("-")
}
