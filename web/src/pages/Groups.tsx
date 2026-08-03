import i18n from "@/i18n/config"
import { useTranslation, Trans } from "react-i18next"
import { useEffect, useState } from "react"
import { Plus, Trash2, Users, Play, ShieldCheck, RotateCw, FlaskConical } from "lucide-react"
import api, { Script, ScriptPolicy, DeviceGroup, Device, UpdateChannel, UPDATE_CHANNEL_LABEL, GROUP_PALETTE, DEFAULT_GROUP_COLOR, REBOOT_DELAYS, REBOOT_GROUP_MAX_DEVICES } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Select } from "@/components/ui/select"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { toast } from "@/lib/toast"

// ColorPalette — выбор цвета группы. Цветом обводятся рамки её устройств в списке,
// поэтому он часть создания группы, а не косметическая настройка «потом».
function ColorPalette({ value, onChange }: { value: string; onChange: (c: string) => void }) {
  const { t } = useTranslation()
  return (
    <div className="flex flex-wrap gap-2">
      {GROUP_PALETTE.map((c) => (
        <button
          type="button"
          key={c}
          aria-label={t("groups.colorAria", { color: c })}
          aria-pressed={value === c}
          onClick={() => onChange(c)}
          className={
            "h-7 w-7 rounded-full transition-transform hover:scale-110 " +
            (value === c ? "ring-2 ring-offset-2 ring-offset-background ring-foreground" : "")
          }
          style={{ backgroundColor: c }}
        />
      ))}
    </div>
  )
}

export default function Groups() {
  const { t } = useTranslation()
  const [groups, setGroups] = useState<DeviceGroup[]>([])
  const [devices, setDevices] = useState<Device[]>([])
  const [scriptPolicies, setScriptPolicies] = useState<ScriptPolicy[]>([])
  const [scripts, setScripts] = useState<Script[]>([])
  const [loading, setLoading] = useState(true)

  const [createOpen, setCreateOpen] = useState(false)
  const [groupName, setGroupName] = useState("")
  const [groupColor, setGroupColor] = useState<string>(DEFAULT_GROUP_COLOR)
  const [groupChannel, setGroupChannel] = useState<UpdateChannel>("stable")

  const [manageGroupId, setManageGroupId] = useState<string | null>(null)
  // Список устройств в диалоге рендерится целиком; на парке в сотни машин без фильтра
  // нужную не найти.
  const [deviceQuery, setDeviceQuery] = useState("")
  const [softwareForm, setSoftwareForm] = useState<{ software_name: string; rule_type: "allowed" | "forbidden" }>({
    software_name: "",
    rule_type: "forbidden",
  })

  const [runGroupId, setRunGroupId] = useState<string | null>(null)
  const [runForm, setRunForm] = useState<{ script_id: string; priority: "low" | "medium" | "high" }>({
    script_id: "",
    priority: "medium",
  })

  const [submitting, setSubmitting] = useState(false)
  const [rebootGroupId, setRebootGroupId] = useState<string | null>(null)
  const [rebootReason, setRebootReason] = useState("")
  const [rebootDelay, setRebootDelay] = useState(REBOOT_DELAYS[0].value)

  async function load() {
    try {
      const [g, d, sp, s] = await Promise.all([
        api.get<DeviceGroup[]>("/device-groups"),
        api.get<Device[]>("/devices"),
        api.get<ScriptPolicy[]>("/script-policies"),
        api.get<Script[]>("/scripts"),
      ])
      setGroups(g.data ?? [])
      setDevices(d.data ?? [])
      setScriptPolicies(sp.data ?? [])
      setScripts(s.data ?? [])
    } catch {
      toast({ title: t("groups.failedToLoadThe"), variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleCreateGroup() {
    setSubmitting(true)
    try {
      await api.post("/device-groups", { name: groupName, color: groupColor, update_channel: groupChannel })
      setCreateOpen(false)
      setGroupName("")
      setGroupColor(DEFAULT_GROUP_COLOR)
      setGroupChannel("stable")
      await load()
      toast({ title: t("groups.groupCreated"), variant: "success" })
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
    }
  }

  // Цвет меняется прямо в карточке управления: перекрашивать группу не должно стоить
  // пересоздания. Оптимистично не обновляем — цвет уезжает в рамки устройств, пусть
  // источником правды останется сервер.
  async function handleChangeColor(groupId: string, color: string) {
    try {
      await api.patch(`/device-groups/${groupId}`, { color })
      await load()
    } catch {
      // авто-тост интерсептора
    }
  }

  // Канал обновлений — то же место, что цвет: свойство группы, меняемое на месте.
  // Перевод в канареечный означает, что эти машины поедут на новую версию раньше
  // остального парка, поэтому подтверждаем словами, а не полагаемся на переключатель.
  async function handleChangeChannel(groupId: string, channel: UpdateChannel) {
    try {
      await api.patch(`/device-groups/${groupId}`, { update_channel: channel })
      await load()
      toast({
        title: channel === "beta" ? t("groups.theGroupIsNow") : t("groups.theGroupIsBack"),
        description: channel === "beta"
          ? t("groups.itsDevicesGetA")
          : t("groups.itsDevicesUpdateTogether"),
        variant: "success",
      })
    } catch {
      // авто-тост интерсептора
    }
  }

  async function handleDeleteGroup(id: string) {
    try {
      await api.delete(`/device-groups/${id}`)
      setGroups((prev) => prev.filter((g) => g.id !== id))
    } catch {
      // авто-тост интерсептора
    }
  }

  async function handleAddDevice(groupId: string, deviceId: string) {
    try {
      await api.post(`/device-groups/${groupId}/members`, { device_id: deviceId })
      await load()
    } catch {
      // авто-тост интерсептора
    }
  }

  async function handleRemoveDevice(groupId: string, deviceId: string) {
    try {
      await api.delete(`/device-groups/${groupId}/members/${deviceId}`)
      await load()
    } catch {
      // авто-тост интерсептора
    }
  }

  async function handleAssignPolicy(groupId: string, policyId: string) {
    try {
      await api.post(`/device-groups/${groupId}/policies`, { policy_id: policyId })
      await load()
    } catch {
      // авто-тост интерсептора
    }
  }

  async function handleUnassignPolicy(groupId: string, policyId: string) {
    try {
      await api.delete(`/device-groups/${groupId}/policies/${policyId}`)
      await load()
    } catch {
      // авто-тост интерсептора
    }
  }

  async function handleAddSoftwareRule(groupId: string) {
    if (!softwareForm.software_name.trim()) return
    setSubmitting(true)
    try {
      await api.post(`/device-groups/${groupId}/software-policies`, {
        software_name: softwareForm.software_name.trim(),
        rule_type: softwareForm.rule_type,
      })
      setSoftwareForm({ software_name: "", rule_type: softwareForm.rule_type })
      await load()
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRemoveSoftwareRule(groupId: string, ruleId: string) {
    try {
      await api.delete(`/device-groups/${groupId}/software-policies/${ruleId}`)
      await load()
    } catch {
      // авто-тост интерсептора
    }
  }

  // Групповая перезагрузка — самая крупнокалиберная кнопка после вывода из
  // эксплуатации. expected_devices = число, которое видел оператор: если группа
  // изменилась между показом и кликом, сервер ответит 409, а не перезагрузит лишних.
  async function handleRebootGroup() {
    if (!rebootGroupId) return
    setSubmitting(true)
    try {
      const res = await api.post<{ created: number; in_scope: number }>(
        `/device-groups/${rebootGroupId}/reboot`,
        { reason: rebootReason, delay_seconds: rebootDelay, expected_devices: rebootTargets.length },
      )
      setRebootGroupId(null)
      toast({
        title: res.data.created === 0
          ? t("groups.noNewRebootsWere")
          : t("groups.rebootScheduled", { count: res.data.created }),
        description: res.data.created < res.data.in_scope
          ? t("groups.someMachinesAlreadyHave")
          : t("groups.theCommandIsExecuted"),
        variant: "success",
      })
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRunScript() {
    if (!runGroupId || !runForm.script_id) return
    setSubmitting(true)
    try {
      const res = await api.post<{ created: number }>(`/device-groups/${runGroupId}/run-script`, {
        script_id: runForm.script_id,
        priority: runForm.priority,
      })
      setRunGroupId(null)
      setRunForm({ script_id: "", priority: "medium" })
      toast({ title: t("groups.taskCreated", { count: res.data.created }), variant: "success" })
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
    }
  }

  // Команду получат только active-машины группы — ровно их сервер и считает.
  // Списанные/заблокированные/неодобренные Connect не примет, обещать их в UI нельзя.
  function activeMembers(g: DeviceGroup): Device[] {
    return devices.filter((d) => g.device_ids.includes(d.id) && d.status === "active")
  }

  const managedGroup = groups.find((g) => g.id === manageGroupId) ?? null
  const rebootGroup = groups.find((g) => g.id === rebootGroupId) ?? null
  const rebootTargets = rebootGroup ? activeMembers(rebootGroup) : []

  const dq = deviceQuery.trim().toLowerCase()
  const visibleDevices = dq
    ? devices.filter((d) =>
        [d.hostname, d.ip_address, d.serial_number, d.mac_address, d.os]
          .some((v) => (v ?? "").toLowerCase().includes(dq)),
      )
    : devices

  if (loading) {
    return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">{t("groups.loading")}</div>
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">{t("groups.deviceGroups")}</h1>
        <Button size="sm" onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" strokeWidth={2} />
          {t("groups.newGroup")}
        </Button>
      </div>

      {groups.length === 0 && (
        <p className="text-sm text-muted-foreground">
          {t("groups.empty")}
        </p>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {groups.map((g) => (
          <div key={g.id} className="glass overflow-hidden">
            {/* Полоса цвета группы — тот же цвет обводит её устройства в списке. */}
            <div className="h-1 w-full" style={{ backgroundColor: g.color }} />
            <div className="flex flex-col gap-3 px-5 pt-4 pb-[18px]">
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-[15px] font-semibold text-foreground flex items-center gap-2 min-w-0">
                  <Users className="h-4 w-4 flex-shrink-0" strokeWidth={2} style={{ color: g.color }} />
                  <span className="truncate">{g.name}</span>
                  {g.update_channel === "beta" && (
                    <Badge variant="secondary" className="flex-shrink-0 gap-1">
                      <FlaskConical className="h-3 w-3" strokeWidth={2} />
                      {t("groups.canary")}
                    </Badge>
                  )}
                </h2>
                <button
                  type="button"
                  onClick={() => handleDeleteGroup(g.id)}
                  className="text-muted-foreground hover:text-destructive transition-colors flex-shrink-0"
                  aria-label={t("groups.deleteTheGroup")}
                >
                  <Trash2 className="h-3.5 w-3.5" strokeWidth={2} />
                </button>
              </div>
              <p className="text-xs text-muted-foreground">
                {t("groups.counts", { devices: g.device_ids.length, policies: g.policy_ids.length, rules: g.software_rules.length })}
              </p>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs px-2"
                  onClick={() => setManageGroupId(g.id)}
                >
                  {t("groups.manage")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs px-2"
                  onClick={() => { setRunGroupId(g.id); setRunForm({ script_id: "", priority: "medium" }) }}
                  disabled={scripts.length === 0 || g.device_ids.length === 0}
                >
                  <Play className="h-3.5 w-3.5 mr-1" strokeWidth={2} />
                  {t("groups.runScript")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs px-2"
                  onClick={() => { setRebootGroupId(g.id); setRebootReason(""); setRebootDelay(REBOOT_DELAYS[0].value) }}
                  disabled={activeMembers(g).length === 0}
                >
                  <RotateCw className="h-3.5 w-3.5 mr-1" strokeWidth={2} />
                  {t("groups.reboot")}
                </Button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Create Group Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("groups.newDeviceGroup")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-1.5">
              <Label className="text-soft">{t("groups.groupName")}</Label>
              <Input
                placeholder={t("groups.accountingMacbooks")}
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-soft">{t("groups.color")}</Label>
              <ColorPalette value={groupColor} onChange={setGroupColor} />
              <p className="text-xs text-muted-foreground">
                {t("groups.colorHint")}
              </p>
            </div>
            <div className="space-y-1.5">
              <Label className="text-soft">{t("groups.updateChannel")}</Label>
              <Select
                value={groupChannel}
                onChange={(v) => setGroupChannel(v as UpdateChannel)}
                options={[
                  { value: "stable", label: i18n.t(UPDATE_CHANNEL_LABEL.stable) },
                  { value: "beta", label: i18n.t(UPDATE_CHANNEL_LABEL.beta) },
                ]}
              />
              <p className="text-xs text-muted-foreground">
                {t("groups.canaryHint")}
              </p>
            </div>
            <Button className="w-full" onClick={handleCreateGroup} disabled={submitting || !groupName.trim()}>
              {submitting ? t("groups.creating") : t("groups.create")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Manage Group Dialog */}
      <Dialog open={!!manageGroupId} onOpenChange={(o) => { if (!o) { setManageGroupId(null); setDeviceQuery("") } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t("groups.manageTitle", { name: managedGroup?.name ?? "" })}</DialogTitle>
          </DialogHeader>
          {managedGroup && (
            <div className="space-y-5 pt-2">
              {/* Цвет */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">{t("groups.color")}</p>
                <ColorPalette
                  value={managedGroup.color}
                  onChange={(c) => handleChangeColor(managedGroup.id, c)}
                />
              </div>

              {/* Канал обновлений */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground flex items-center gap-1.5">
                  <FlaskConical className="h-4 w-4 text-muted-foreground" strokeWidth={2} />
                  {t("groups.updateChannel")}
                </p>
                <Select
                  value={managedGroup.update_channel ?? "stable"}
                  onChange={(v) => handleChangeChannel(managedGroup.id, v as UpdateChannel)}
                  options={[
                    { value: "stable", label: i18n.t(UPDATE_CHANNEL_LABEL.stable) },
                    { value: "beta", label: i18n.t(UPDATE_CHANNEL_LABEL.beta) },
                  ]}
                />
                <p className="text-xs text-muted-foreground">
                  {managedGroup.update_channel === "beta"
                    ? t("groups.theGroupSDevices")
                    : t("groups.theGroupSDevices2")}
                </p>
              </div>

              {/* Устройства */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">{t("groups.devices")}</p>
                <Input
                  placeholder={t("groups.filterNameIpSerial")}
                  value={deviceQuery}
                  onChange={(e) => setDeviceQuery(e.target.value)}
                  className="h-8 text-sm"
                />
                <div className="space-y-1 max-h-40 overflow-auto">
                  {visibleDevices.map((d) => {
                    const inGroup = managedGroup.device_ids.includes(d.id)
                    return (
                      <div key={d.id} className="flex items-center justify-between text-sm py-1">
                        <span className={inGroup ? "font-medium text-foreground" : "text-muted-foreground"}>{d.hostname}</span>
                        <Button
                          size="sm"
                          variant={inGroup ? "destructive" : "outline"}
                          className="h-6 text-xs px-2"
                          onClick={() => inGroup
                            ? handleRemoveDevice(managedGroup.id, d.id)
                            : handleAddDevice(managedGroup.id, d.id)
                          }
                        >
                          {inGroup ? t("groups.remove") : t("groups.add")}
                        </Button>
                      </div>
                    )
                  })}
                  {visibleDevices.length === 0 && (
                    <p className="text-xs text-muted-foreground">
                      {devices.length === 0 ? t("groups.noDevices") : t("groups.nothingFound")}
                    </p>
                  )}
                </div>
              </div>

              {/* Скрипт-политики */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">{t("groups.scriptPolicies")}</p>
                <div className="space-y-1 max-h-40 overflow-auto">
                  {scriptPolicies.map((p) => {
                    const assigned = managedGroup.policy_ids.includes(p.id)
                    return (
                      <div key={p.id} className="flex items-center justify-between text-sm py-1">
                        <span className={assigned ? "font-medium text-foreground" : "text-muted-foreground"}>{p.name}</span>
                        <Button
                          size="sm"
                          variant={assigned ? "destructive" : "outline"}
                          className="h-6 text-xs px-2"
                          onClick={() => assigned
                            ? handleUnassignPolicy(managedGroup.id, p.id)
                            : handleAssignPolicy(managedGroup.id, p.id)
                          }
                        >
                          {assigned ? t("groups.unassign") : t("groups.assign")}
                        </Button>
                      </div>
                    )
                  })}
                  {scriptPolicies.length === 0 && <p className="text-xs text-muted-foreground">{t("groups.noScriptPolicies")}</p>}
                </div>
              </div>

              {/* {t("groups.softwareRules")} */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-muted-foreground" strokeWidth={2} />
                  {t("groups.softwareRules")}
                </p>
                <div className="space-y-1 max-h-40 overflow-auto">
                  {managedGroup.software_rules.map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between text-sm py-1">
                      <span className="flex items-center gap-2">
                        <span className="font-medium text-foreground">{rule.software_name}</span>
                        <Badge variant={rule.rule_type === "forbidden" ? "destructive" : "secondary"}>
                          {rule.rule_type === "forbidden" ? t("groups.denied") : t("groups.allowed")}
                        </Badge>
                      </span>
                      <Button
                        size="sm"
                        variant="destructive"
                        className="h-6 text-xs px-2"
                        onClick={() => handleRemoveSoftwareRule(managedGroup.id, rule.id)}
                      >
                        {t("groups.unassign")}
                      </Button>
                    </div>
                  ))}
                  {managedGroup.software_rules.length === 0 && (
                    <p className="text-xs text-muted-foreground">{t("groups.noSoftwareRules")}</p>
                  )}
                </div>
                <div className="flex items-end gap-2 pt-1">
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs text-soft">{t("groups.software")}</Label>
                    <Input
                      placeholder="chrome.exe"
                      value={softwareForm.software_name}
                      onChange={(e) => setSoftwareForm({ ...softwareForm, software_name: e.target.value })}
                    />
                  </div>
                  <div className="w-36 space-y-1">
                    <Label className="text-xs text-soft">{t("groups.type")}</Label>
                    <Select
                      value={softwareForm.rule_type}
                      onChange={(v) => setSoftwareForm({ ...softwareForm, rule_type: v as "allowed" | "forbidden" })}
                      options={[
                        { value: "forbidden", label: t("groups.denied") },
                        { value: "allowed", label: t("groups.allowed") },
                      ]}
                    />
                  </div>
                  <Button
                    size="sm"
                    onClick={() => handleAddSoftwareRule(managedGroup.id)}
                    disabled={submitting || !softwareForm.software_name.trim()}
                  >
                    {t("groups.add")}
                  </Button>
                </div>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Run Script Dialog */}
      <Dialog open={!!runGroupId} onOpenChange={(o) => !o && setRunGroupId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("groups.runAScriptOn")}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-1.5">
              <Label className="text-soft">{t("groups.script")}</Label>
              <Select
                value={runForm.script_id}
                onChange={(v) => setRunForm({ ...runForm, script_id: v })}
                placeholder={t("groups.chooseAScript")}
                options={scripts.map((s) => ({ value: s.id, label: `${s.name} (${s.platform})` }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-soft">{t("groups.priority")}</Label>
              <Select
                value={runForm.priority}
                onChange={(v) => setRunForm({ ...runForm, priority: v as typeof runForm.priority })}
                options={[
                  { value: "low", label: t("groups.low") },
                  { value: "medium", label: t("groups.medium") },
                  { value: "high", label: t("groups.high") },
                ]}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              {t("groups.platformSkipHint")}
            </p>
            <Button className="w-full" onClick={handleRunScript} disabled={submitting || !runForm.script_id}>
              {submitting ? t("groups.running") : t("groups.run")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Перезагрузка группы */}
      <Dialog open={!!rebootGroupId} onOpenChange={(o) => !o && setRebootGroupId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("groups.rebootTitle", { name: rebootGroup?.name ?? "" })}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <p className="text-sm text-foreground">
              <Trans i18nKey="groups.rebootCount"
                     values={{ targets: rebootTargets.length, total: rebootGroup?.device_ids.length ?? 0 }}
                     components={[<span className="font-semibold" />]} />
            </p>
            {rebootTargets.length > REBOOT_GROUP_MAX_DEVICES ? (
              <p className="text-sm text-destructive">
                {t("groups.rebootLimit", { max: REBOOT_GROUP_MAX_DEVICES })}
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                {t("groups.rebootDelayHint")}
              </p>
            )}
            <div className="space-y-1.5">
              <Label className="text-soft">{t("groups.when")}</Label>
              <Select
                value={String(rebootDelay)}
                onChange={(v) => setRebootDelay(Number(v))}
                options={REBOOT_DELAYS.map((d) => ({ value: String(d.value), label: i18n.t(d.label) }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-soft">{t("groups.reasonOptional")}</Label>
              <Input
                placeholder={t("groups.maintenanceWindowInstallingUpdat")}
                value={rebootReason}
                onChange={(e) => setRebootReason(e.target.value)}
              />
            </div>
            <Button
              className="w-full"
              onClick={handleRebootGroup}
              disabled={submitting || rebootTargets.length === 0 || rebootTargets.length > REBOOT_GROUP_MAX_DEVICES}
            >
              {submitting ? t("groups.sending") : t("groups.rebootConfirm", { count: rebootTargets.length })}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
