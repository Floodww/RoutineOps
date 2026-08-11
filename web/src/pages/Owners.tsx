import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { UserCircle, Trash2 } from "lucide-react"
import api, { Person, errMessage } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import ConfirmDialog from "@/components/ConfirmDialog"
import { toast } from "@/lib/toast"

// Страница владельцев — единственное место, где карточки человека видны РАЗОМ.
//
// Почему отдельная страница, а не кнопка в карточке устройства. Удаление владельца
// снимает его со ВСЕХ его машин, а карточка устройства показывает одну: там это действие
// выглядит как «убрать владельца у этого компьютера», хотя оно про весь парк. Цена
// ошибки — молчаливая потеря владельцев на чужих устройствах, и заметит её не тот, кто
// нажал.
//
// Почему не на странице «Каталог», где список персон уже есть: та страница —
// enterprise-фича, в open-core ручки /directory/* отвечают 501 и она показывает
// «недоступно в этой редакции». Карточки же заводятся руками и в свободной сборке
// (OwnerCard), значит и удаляться должны в обеих. Сам список (/directory/persons)
// редакцией не ограничен — он лежит вне enterprise-оверлея.
export default function Owners() {
  const { t } = useTranslation()
  const [persons, setPersons] = useState<Person[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<Person | null>(null)
  const [busy, setBusy] = useState("")

  async function load() {
    try {
      const r = await api.get<Person[]>("/directory/persons")
      setPersons(r.data ?? [])
      setLoadError(false)
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  async function remove(p: Person) {
    setBusy(p.id)
    try {
      await api.delete(`/persons/${p.id}`)
      toast({ title: t("owners.deleted", { name: personTitle(p) }) })
      await load()
    } catch (e) {
      toast({ title: t("owners.deleteFailed"), description: errMessage(e), variant: "destructive" })
    } finally {
      setBusy("")
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2.5">
        <UserCircle className="h-5 w-5 text-soft" strokeWidth={2} />
        <h1 className="text-lg font-semibold text-foreground">{t("owners.title")}</h1>
      </div>
      <p className="text-sm text-soft -mt-2">{t("owners.subtitle")}</p>

      <div className="glass px-5 py-[18px]">
        {loading ? (
          <p className="text-sm text-soft">{t("common.loading")}</p>
        ) : loadError ? (
          <p className="text-sm text-soft">{t("owners.loadFailed")}</p>
        ) : persons.length === 0 ? (
          <p className="text-sm text-soft">{t("owners.empty")}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("owners.name")}</TableHead>
                <TableHead>E-mail</TableHead>
                <TableHead>{t("owners.source")}</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {persons.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="text-foreground">{personTitle(p)}</TableCell>
                  <TableCell>{p.email || "—"}</TableCell>
                  <TableCell>
                    {canDelete(p) ? (
                      <Badge variant="outline">{t("owners.sourceManual")}</Badge>
                    ) : (
                      <Badge variant="default">{t("owners.sourceLdap")}</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {/* Синканную карточку сервер удалять отказывается (409 «remove it in AD»),
                        поэтому кнопки у неё нет вовсе: кнопка, которая гарантированно
                        приводит к отказу, — это обещание, которого интерфейс не выполняет. */}
                    {canDelete(p) && (
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={busy === p.id}
                        aria-label={t("owners.delete")}
                        title={t("owners.delete")}
                        onClick={() => setConfirmDelete(p)}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" strokeWidth={2} />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title={t("owners.deleteQ")}
        // Предупреждение говорит про ВЕСЬ парк, а не про одну машину: это единственное,
        // что отличает удаление карточки от снятия владельца с устройства.
        description={confirmDelete ? t("owners.deleteWarn", { name: personTitle(confirmDelete) }) : ""}
        confirmLabel={t("owners.delete")}
        destructive
        onConfirm={() => { if (confirmDelete) remove(confirmDelete) }}
      />
    </div>
  )
}

/**
 * canDelete — удалять можно только карточки, заведённые руками.
 *
 * Карточки из каталога принадлежат AD: сервер отвечает на них 409 «remove it in AD»,
 * и сделать с этим отказом пользователь ничего не может. Признак — поле source, оно
 * приходит в списке.
 */
export function canDelete(p: Pick<Person, "source">): boolean {
  return p.source !== "ldap"
}

/** personTitle — как показывать человека, если имя не заполнено. */
export function personTitle(p: Pick<Person, "display_name" | "sam_account" | "email">): string {
  return p.display_name || p.sam_account || p.email || "—"
}
