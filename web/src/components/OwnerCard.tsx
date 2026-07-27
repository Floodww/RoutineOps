import { useEffect, useState } from "react"
import { UserCircle } from "lucide-react"
import api, { Device, Person, errMessage } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select } from "@/components/ui/select"
import { toast } from "@/lib/toast"

// OwnerCard — владелец устройства. Владелец это КАРТОЧКА ЧЕЛОВЕКА, а не аккаунт панели:
// аккаунты (приглашения) нужны тем, кто в панель ходит — админам и поддержке. Карточку
// либо приносит синк AD (Enterprise), либо заводит оператор прямо здесь (Free) — для
// устройства это одно и то же, поэтому список общий.
//
// Показ виден всем; назначение и заведение — только it_admin (ручки под it_admin).
export default function OwnerCard({ device, isAdmin, onChanged }: {
  device: Device
  isAdmin: boolean
  onChanged: () => void
}) {
  const [persons, setPersons] = useState<Person[]>([])
  const [selected, setSelected] = useState(device.owner_person_id ?? "")
  const [saving, setSaving] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState("")
  const [newEmail, setNewEmail] = useState("")

  useEffect(() => { setSelected(device.owner_person_id ?? "") }, [device.owner_person_id])

  function loadPersons() {
    // ponytail: плоский список в дропдауне — для пилота ок; поиск/комбобокс, когда
    // список станет длинным.
    api.get<Person[]>("/directory/persons").then((r) => setPersons(r.data ?? [])).catch(() => {})
  }
  useEffect(() => { if (isAdmin) loadPersons() }, [isAdmin])

  async function assign(personID: string) {
    setSaving(true)
    try {
      await api.put(`/devices/${device.id}/owner`, { person_id: personID })
      toast({ title: personID ? "Владелец назначен" : "Владелец снят" })
      onChanged()
    } catch (e) {
      toast({ title: "Не удалось изменить владельца", description: errMessage(e), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  // Заводим карточку и СРАЗУ назначаем: оператор пришёл сюда назначить владельца, а не
  // пополнить справочник — заставлять его выбирать только что созданного человека из
  // списка было бы лишним шагом на ровном месте.
  async function createAndAssign() {
    const name = newName.trim()
    if (!name) return
    setSaving(true)
    try {
      const r = await api.post<Person>("/persons", { display_name: name, email: newEmail.trim() })
      await api.put(`/devices/${device.id}/owner`, { person_id: r.data.id })
      toast({ title: "Владелец создан и назначен" })
      setNewName(""); setNewEmail(""); setCreating(false)
      loadPersons()
      onChanged()
    } catch (e) {
      toast({ title: "Не удалось создать владельца", description: errMessage(e), variant: "destructive" })
    } finally {
      setSaving(false)
    }
  }

  const fromDirectory = persons.find((p) => p.id === device.owner_person_id)?.source === "ldap"

  return (
    <div className="glass px-5 py-[18px]">
      <h2 className="text-[15px] font-semibold text-foreground flex items-center gap-2 mb-4">
        <UserCircle className="h-[17px] w-[17px] text-muted-foreground" strokeWidth={2} />
        Владелец
      </h2>
      <div className="flex items-center gap-2 mb-1">
        {device.owner_person_name ? (
          <>
            <span className="text-sm text-foreground">{device.owner_person_name}</span>
            {device.owner_person_email && (
              <span className="text-sm text-soft">{device.owner_person_email}</span>
            )}
            {fromDirectory && <Badge variant="default">из каталога</Badge>}
          </>
        ) : (
          <span className="text-sm text-soft">не назначен</span>
        )}
      </div>

      {isAdmin && !creating && (
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <Select
            value={selected}
            onChange={setSelected}
            placeholder="— не назначен —"
            options={[
              { value: "", label: "— не назначен —" },
              ...persons.map((p) => ({
                value: p.id,
                label: p.email ? `${p.display_name} (${p.email})` : p.display_name,
              })),
            ]}
            className="max-w-xs"
          />
          <Button size="sm" disabled={saving || selected === (device.owner_person_id ?? "")} onClick={() => assign(selected)}>
            Сохранить
          </Button>
          {device.owner_person_id && (
            <Button size="sm" variant="ghost" disabled={saving} onClick={() => assign("")}>
              Снять
            </Button>
          )}
          <Button size="sm" variant="ghost" disabled={saving} onClick={() => setCreating(true)}>
            Создать владельца
          </Button>
        </div>
      )}

      {isAdmin && creating && (
        <div className="mt-3 flex flex-col gap-2 max-w-md">
          <Input placeholder="ФИО" value={newName} onChange={(e) => setNewName(e.target.value)} autoFocus />
          <Input placeholder="E-mail (необязательно)" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
          <p className="text-xs text-soft">
            Владельцу не нужен вход в панель — приглашение не отправляется.
          </p>
          <div className="flex items-center gap-2">
            <Button size="sm" disabled={saving || !newName.trim()} onClick={createAndAssign}>
              Создать и назначить
            </Button>
            <Button size="sm" variant="ghost" disabled={saving} onClick={() => { setCreating(false); setNewName(""); setNewEmail("") }}>
              Отмена
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
