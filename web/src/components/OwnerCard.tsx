import { useEffect, useState } from "react"
import { UserCircle } from "lucide-react"
import api, { Device, errMessage } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Select } from "@/components/ui/select"
import { toast } from "@/lib/toast"

type UserRef = { id: string; email: string }

// OwnerCard — владелец устройства. Показ виден всем; ручное назначение (owner_id→users,
// Free) — только it_admin (PUT под it_admin, у viewer'а 403). Авто-владелец из каталога
// (owner_directory_name, Enterprise LDAP) — read-only, живёт отдельным слоем; ручной его
// переопределяет при показе.
export default function OwnerCard({ device, isAdmin, onChanged }: {
  device: Device
  isAdmin: boolean
  onChanged: () => void
}) {
  const [users, setUsers] = useState<UserRef[]>([])
  const [selected, setSelected] = useState(device.owner_user_id ?? "")
  const [saving, setSaving] = useState(false)

  useEffect(() => { setSelected(device.owner_user_id ?? "") }, [device.owner_user_id])
  useEffect(() => {
    if (!isAdmin) return
    // ponytail: плоский список юзеров в дропдауне — для пилота ок; поиск/комбобокс, когда
    // список станет длинным.
    api.get<UserRef[]>("/users").then((r) => setUsers(r.data ?? [])).catch(() => {})
  }, [isAdmin])

  const auto = device.owner_directory_name
  const manualEmail = device.owner_user_email

  async function save(ownerUserID: string) {
    setSaving(true)
    try {
      await api.put(`/devices/${device.id}/owner`, { owner_user_id: ownerUserID })
      toast({ title: ownerUserID ? "Владелец назначен" : "Владелец снят" })
      onChanged()
    } catch (e) {
      toast({ title: "Не удалось изменить владельца", description: errMessage(e), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="glass px-5 py-[18px]">
      <h2 className="text-[15px] font-semibold text-foreground flex items-center gap-2 mb-4">
        <UserCircle className="h-[17px] w-[17px] text-muted-foreground" strokeWidth={2} />
        Владелец
      </h2>
      <div className="flex items-center gap-2 mb-1">
        {manualEmail ? (
          <>
            <span className="text-sm text-foreground">{manualEmail}</span>
            <Badge variant="outline">вручную</Badge>
          </>
        ) : auto ? (
          <>
            <span className="text-sm text-foreground">{auto}</span>
            <Badge variant="default">из каталога</Badge>
          </>
        ) : (
          <span className="text-sm text-soft">не назначен</span>
        )}
      </div>
      {auto && manualEmail && (
        <p className="text-xs text-soft mb-3">Ручной владелец переопределяет авто-привязку из каталога ({auto}).</p>
      )}
      {isAdmin && (
        <div className="flex items-center gap-2 mt-3">
          <Select
            value={selected}
            onChange={setSelected}
            placeholder="— не назначен —"
            options={[{ value: "", label: "— не назначен —" }, ...users.map((u) => ({ value: u.id, label: u.email }))]}
            className="max-w-xs"
          />
          <Button
            size="sm"
            disabled={saving || selected === (device.owner_user_id ?? "")}
            onClick={() => save(selected)}
          >
            Сохранить
          </Button>
          {device.owner_user_id && (
            <Button size="sm" variant="ghost" disabled={saving} onClick={() => save("")}>
              Снять
            </Button>
          )}
        </div>
      )}
    </div>
  )
}
