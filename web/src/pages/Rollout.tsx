import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { FlaskConical, PackageCheck, RefreshCw } from "lucide-react"
import api, { UpdateRollout, ChannelRollout } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { toast } from "@/lib/toast"

// Выкатка обновлений по каналам (Q-52).
//
// Страница отвечает на один вопрос, ради которого каналы и заводились: доехал ли
// релиз до канареечной группы и ОСТАЛСЯ ЛИ парк на прежней версии. Обе половины
// нужны вместе — «опубликовал в beta» без второй неотличимо от «опубликовал, и оно
// не поехало»: агент обновляется сам и молча.



// i18nLocale — локаль для дат: язык интерфейса, а не жёсткий ru-RU. Иначе
// англоязычный оператор видит английский текст с русскими датами.
function i18nLocale(): string {
  return document.documentElement.lang || navigator.language || "ru-RU"
}

// versionShare — доля устройств канала на этой версии. Считается здесь, а не на
// сервере: это способ показать число, а не факт о парке.
function versionShare(count: number, total: number): number {
  if (total <= 0) return 0
  return Math.round((count / total) * 100)
}

function ChannelCard({ channel }: { channel: ChannelRollout }) {
  const { t } = useTranslation()
  const isBeta = channel.channel === "beta"
  const total = channel.devices
  return (
    <section className="glass overflow-hidden">
      <div className={"h-1 w-full " + (isBeta ? "bg-amber-500" : "bg-emerald-500")} />
      <div className="flex flex-col gap-4 px-5 pt-4 pb-5">
        <header className="flex items-start justify-between gap-3">
          <h2 className="text-[15px] font-semibold text-foreground flex items-center gap-2">
            {isBeta
              ? <FlaskConical className="h-4 w-4 text-amber-500" strokeWidth={2} />
              : <PackageCheck className="h-4 w-4 text-emerald-500" strokeWidth={2} />}
            {isBeta ? t("rollout.channelBeta") : t("rollout.channelStable")}
          </h2>
          <p className="text-xs text-muted-foreground text-right">
            {channel.devices} {t("rollout.devices")} · {channel.groups} {t("rollout.groups")}
          </p>
        </header>

        <div className="space-y-1.5">
          <p className="text-xs font-medium text-soft">{t("rollout.offers")}</p>
          {channel.targets.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("rollout.noReleases")}</p>
          ) : (
            <ul className="space-y-1">
              {channel.targets.map((tgt) => (
                <li key={`${tgt.os}-${tgt.arch}`} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{tgt.os}/{tgt.arch}</span>
                  <span className="font-medium text-foreground tabular-nums">{tgt.version}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="space-y-1.5">
          <p className="text-xs font-medium text-soft">{t("rollout.parkOn")}</p>
          {channel.versions.length === 0 ? (
            <p className="text-xs text-muted-foreground">{t("rollout.noDevices")}</p>
          ) : (
            <ul className="space-y-2">
              {channel.versions.map((v) => {
                const share = versionShare(v.count, total)
                return (
                  <li key={v.version || "unreported"} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                      <span className={v.version ? "font-medium text-foreground" : "text-muted-foreground italic"}>
                        {v.version || t("rollout.noVersion")}
                      </span>
                      <span className="text-muted-foreground tabular-nums">{v.count} · {share}%</span>
                    </div>
                    {/* Полоса доли: на парке в тысячу машин «12 из 940» глазом не
                        соотносится, а именно соотношение и показывает ход выкатки. */}
                    <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className={"h-full rounded-full " + (isBeta ? "bg-amber-500" : "bg-emerald-500")}
                        style={{ width: `${share}%` }}
                      />
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      </div>
    </section>
  )
}

export default function Rollout() {
  const { t } = useTranslation()
  const [data, setData] = useState<UpdateRollout | null>(null)
  const [loading, setLoading] = useState(true)

  async function load() {
    try {
      const res = await api.get<UpdateRollout>("/update-rollout")
      setData(res.data)
    } catch {
      toast({ title: t("rollout.loadFailed"), variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) {
    return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">{t("common.loading")}</div>
  }

  const channels = data?.channels ?? []
  const releases = data?.releases ?? []

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">{t("rollout.title")}</h1>
        <Button size="sm" variant="outline" onClick={() => load()}>
          <RefreshCw className="h-4 w-4 mr-1.5" strokeWidth={2} />
          {t("common.refresh")}
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">{t("rollout.intro")}</p>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {channels.map((c) => <ChannelCard key={c.channel} channel={c} />)}
      </div>

      <section className="space-y-2">
        <h2 className="text-[15px] font-semibold text-foreground">{t("rollout.releases")}</h2>
        {releases.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("rollout.releasesEmpty")}</p>
        ) : (
          <div className="glass overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("rollout.colVersion")}</TableHead>
                  <TableHead>{t("rollout.colPlatform")}</TableHead>
                  <TableHead>{t("rollout.colChannel")}</TableHead>
                  <TableHead>{t("rollout.colPublished")}</TableHead>
                  <TableHead>SHA-256</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {releases.map((r) => (
                  <TableRow key={`${r.os}-${r.arch}-${r.version}`}>
                    <TableCell className="font-medium">{r.version}</TableCell>
                    <TableCell className="text-muted-foreground">{r.os}/{r.arch}</TableCell>
                    <TableCell>
                      <Badge variant={r.channel === "beta" ? "secondary" : "outline"}>
                        {r.channel === "beta" ? t("rollout.channelBeta") : t("rollout.channelStable")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(r.created_at).toLocaleString(i18nLocale())}
                    </TableCell>
                    {/* Полный хеш не влезает и не читается — но первых байт хватает,
                        чтобы сверить с тем, что вывела publish-release. */}
                    <TableCell className="font-mono text-xs text-muted-foreground" title={r.sha256}>
                      {r.sha256.slice(0, 16)}…
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>
    </div>
  )
}
