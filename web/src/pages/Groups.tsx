import { useEffect, useState } from "react"
import { Plus, Trash2, Users, Play, ShieldCheck } from "lucide-react"
import api, { Script, ScriptPolicy, DeviceGroup, Device, GROUP_PALETTE, DEFAULT_GROUP_COLOR } from "@/lib/api"
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
  return (
    <div className="flex flex-wrap gap-2">
      {GROUP_PALETTE.map((c) => (
        <button
          type="button"
          key={c}
          aria-label={`Цвет ${c}`}
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
  const [groups, setGroups] = useState<DeviceGroup[]>([])
  const [devices, setDevices] = useState<Device[]>([])
  const [scriptPolicies, setScriptPolicies] = useState<ScriptPolicy[]>([])
  const [scripts, setScripts] = useState<Script[]>([])
  const [loading, setLoading] = useState(true)

  const [createOpen, setCreateOpen] = useState(false)
  const [groupName, setGroupName] = useState("")
  const [groupColor, setGroupColor] = useState<string>(DEFAULT_GROUP_COLOR)

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
      toast({ title: "Не удалось загрузить данные", variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleCreateGroup() {
    setSubmitting(true)
    try {
      await api.post("/device-groups", { name: groupName, color: groupColor })
      setCreateOpen(false)
      setGroupName("")
      setGroupColor(DEFAULT_GROUP_COLOR)
      await load()
      toast({ title: "Группа создана", variant: "success" })
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
      toast({ title: `Задача создана на ${res.data.created} устройств`, variant: "success" })
    } catch {
      // авто-тост интерсептора
    } finally {
      setSubmitting(false)
    }
  }

  const managedGroup = groups.find((g) => g.id === manageGroupId) ?? null

  const dq = deviceQuery.trim().toLowerCase()
  const visibleDevices = dq
    ? devices.filter((d) =>
        [d.hostname, d.ip_address, d.serial_number, d.mac_address, d.os]
          .some((v) => (v ?? "").toLowerCase().includes(dq)),
      )
    : devices

  if (loading) {
    return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">Загрузка...</div>
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">Группы устройств</h1>
        <Button size="sm" onClick={() => setCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" strokeWidth={2} />
          Новая группа
        </Button>
      </div>

      {groups.length === 0 && (
        <p className="text-sm text-muted-foreground">
          Создайте группу, чтобы назначать политики и прогонять скрипты на устройства пачкой.
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
                </h2>
                <button
                  type="button"
                  onClick={() => handleDeleteGroup(g.id)}
                  className="text-muted-foreground hover:text-destructive transition-colors flex-shrink-0"
                  aria-label="Удалить группу"
                >
                  <Trash2 className="h-3.5 w-3.5" strokeWidth={2} />
                </button>
              </div>
              <p className="text-xs text-muted-foreground">
                {g.device_ids.length} устройств · {g.policy_ids.length} скрипт-политик · {g.software_rules.length} софт-правил
              </p>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs px-2"
                  onClick={() => setManageGroupId(g.id)}
                >
                  Управление
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs px-2"
                  onClick={() => { setRunGroupId(g.id); setRunForm({ script_id: "", priority: "medium" }) }}
                  disabled={scripts.length === 0 || g.device_ids.length === 0}
                >
                  <Play className="h-3.5 w-3.5 mr-1" strokeWidth={2} />
                  Прогнать скрипт
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
            <DialogTitle>Новая группа устройств</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-1.5">
              <Label className="text-soft">Название группы</Label>
              <Input
                placeholder="MacBook-и бухгалтерии"
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-soft">Цвет</Label>
              <ColorPalette value={groupColor} onChange={setGroupColor} />
              <p className="text-xs text-muted-foreground">
                Этим цветом будут обведены устройства группы в списке.
              </p>
            </div>
            <Button className="w-full" onClick={handleCreateGroup} disabled={submitting || !groupName.trim()}>
              {submitting ? "Создание..." : "Создать"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Manage Group Dialog */}
      <Dialog open={!!manageGroupId} onOpenChange={(o) => { if (!o) { setManageGroupId(null); setDeviceQuery("") } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Управление группой: {managedGroup?.name}</DialogTitle>
          </DialogHeader>
          {managedGroup && (
            <div className="space-y-5 pt-2">
              {/* Цвет */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">Цвет</p>
                <ColorPalette
                  value={managedGroup.color}
                  onChange={(c) => handleChangeColor(managedGroup.id, c)}
                />
              </div>

              {/* Устройства */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">Устройства</p>
                <Input
                  placeholder="Фильтр: имя, IP, серийник..."
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
                          {inGroup ? "Убрать" : "Добавить"}
                        </Button>
                      </div>
                    )
                  })}
                  {visibleDevices.length === 0 && (
                    <p className="text-xs text-muted-foreground">
                      {devices.length === 0 ? "Нет устройств" : "Ничего не найдено"}
                    </p>
                  )}
                </div>
              </div>

              {/* Скрипт-политики */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground">Политики скриптов</p>
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
                          {assigned ? "Снять" : "Назначить"}
                        </Button>
                      </div>
                    )
                  })}
                  {scriptPolicies.length === 0 && <p className="text-xs text-muted-foreground">Нет политик скриптов</p>}
                </div>
              </div>

              {/* Софт-правила */}
              <div className="space-y-2">
                <p className="text-sm font-medium text-foreground flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-muted-foreground" strokeWidth={2} />
                  Софт-правила
                </p>
                <div className="space-y-1 max-h-40 overflow-auto">
                  {managedGroup.software_rules.map((rule) => (
                    <div key={rule.id} className="flex items-center justify-between text-sm py-1">
                      <span className="flex items-center gap-2">
                        <span className="font-medium text-foreground">{rule.software_name}</span>
                        <Badge variant={rule.rule_type === "forbidden" ? "destructive" : "secondary"}>
                          {rule.rule_type === "forbidden" ? "Запрещено" : "Разрешено"}
                        </Badge>
                      </span>
                      <Button
                        size="sm"
                        variant="destructive"
                        className="h-6 text-xs px-2"
                        onClick={() => handleRemoveSoftwareRule(managedGroup.id, rule.id)}
                      >
                        Снять
                      </Button>
                    </div>
                  ))}
                  {managedGroup.software_rules.length === 0 && (
                    <p className="text-xs text-muted-foreground">Нет софт-правил</p>
                  )}
                </div>
                <div className="flex items-end gap-2 pt-1">
                  <div className="flex-1 space-y-1">
                    <Label className="text-xs text-soft">ПО</Label>
                    <Input
                      placeholder="chrome.exe"
                      value={softwareForm.software_name}
                      onChange={(e) => setSoftwareForm({ ...softwareForm, software_name: e.target.value })}
                    />
                  </div>
                  <div className="w-36 space-y-1">
                    <Label className="text-xs text-soft">Тип</Label>
                    <Select
                      value={softwareForm.rule_type}
                      onChange={(v) => setSoftwareForm({ ...softwareForm, rule_type: v as "allowed" | "forbidden" })}
                      options={[
                        { value: "forbidden", label: "Запрещено" },
                        { value: "allowed", label: "Разрешено" },
                      ]}
                    />
                  </div>
                  <Button
                    size="sm"
                    onClick={() => handleAddSoftwareRule(managedGroup.id)}
                    disabled={submitting || !softwareForm.software_name.trim()}
                  >
                    Добавить
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
            <DialogTitle>Прогнать скрипт на группу</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="space-y-1.5">
              <Label className="text-soft">Скрипт</Label>
              <Select
                value={runForm.script_id}
                onChange={(v) => setRunForm({ ...runForm, script_id: v })}
                placeholder="Выберите скрипт..."
                options={scripts.map((s) => ({ value: s.id, label: `${s.name} (${s.platform})` }))}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-soft">Приоритет</Label>
              <Select
                value={runForm.priority}
                onChange={(v) => setRunForm({ ...runForm, priority: v as typeof runForm.priority })}
                options={[
                  { value: "low", label: "Низкий" },
                  { value: "medium", label: "Средний" },
                  { value: "high", label: "Высокий" },
                ]}
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Несовместимые по платформе устройства сервер пропустит автоматически.
            </p>
            <Button className="w-full" onClick={handleRunScript} disabled={submitting || !runForm.script_id}>
              {submitting ? "Запуск..." : "Запустить"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}
