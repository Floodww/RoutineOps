import { useState, useEffect } from "react"
import { useTranslation } from "react-i18next"
import i18n from "@/i18n/config"
import { ShieldCheck, ShieldAlert, Download, Printer, RefreshCw } from "lucide-react"
import api, { ComplianceReport, DeviceCompliance } from "@/lib/api"
import SpotlightCard from "@/components/SpotlightCard"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { toast } from "@/lib/toast"

// uiLocale — локаль дат берётся из языка интерфейса, а не прибита к ru-RU: иначе
// англоязычный оператор видит английский текст с русским форматом дат.
function uiLocale(): string {
  return document.documentElement.lang || navigator.language || "ru-RU"
}

// Дашборд соответствия (Q-62, вторая половина).
//
// 🔴 Прежняя версия рисовала каждому активному устройству бейдж «Compliant» БЕЗ
// ЕДИНОЙ ПРОВЕРКИ — слово печаталось на каждой строке. Отчёт, который показывают
// аудитору, так выглядеть не может: он не просто беден, он утверждает неправду.
// Соответствие теперь считает сервер (BuildComplianceReport) из уязвимостей,
// давности контакта, версии агента относительно канала и состояния очереди.

function ReasonBadges({ device }: { device: DeviceCompliance }) {
  const { t } = useTranslation()
  if (device.compliant) {
    return (
      <Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 border-emerald-500/20">
        {t("compliance.ok")}
      </Badge>
    )
  }
  return (
    <div className="flex flex-wrap gap-1.5 justify-end">
      {device.reasons.map((r) => (
        <Badge
          key={r}
          variant="outline"
          className={
            r === "vulnerable"
              ? "bg-rose-500/10 text-rose-600 border-rose-500/20"
              : "bg-amber-500/10 text-amber-600 border-amber-500/20"
          }
        >
          {t(`complianceReason.${r}`, r)}
        </Badge>
      ))}
    </div>
  )
}

export default function Compliance() {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(true)
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [onlyProblems, setOnlyProblems] = useState(false)

  async function load() {
    try {
      const res = await api.get<ComplianceReport>("/compliance/report")
      setReport(res.data)
    } catch {
      toast({ title: t("compliance.loadFailed"), variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  // Выгрузка идёт СЕРВЕРНЫМ файлом, а не сборкой CSV на фронте: в отчёте, который
  // подшивают, строки обязаны совпадать с тем, что посчитал сервер, а не с тем, что
  // успела отфильтровать страница.
  // Язык уходит параметром: формулировки причин лежат на сервере, и без него
  // англоязычный оператор скачивал бы русский файл с английского экрана.
  async function handleDownloadCSV() {
    try {
      const res = await api.get(`/compliance/report.csv?lang=${encodeURIComponent(i18n.language)}`, {
        responseType: "blob",
      })
      const url = URL.createObjectURL(res.data as Blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `compliance-${new Date().toISOString().slice(0, 10)}.csv`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // авто-тост интерсептора
    }
  }

  if (loading) {
    return <div className="p-8 text-center text-muted-foreground animate-pulse">{t("compliance.loading")}</div>
  }

  const summary = report?.summary
  const devices = report?.devices ?? []
  const visible = onlyProblems ? devices.filter((d) => !d.compliant) : devices
  const share = summary && summary.devices > 0
    ? Math.round((summary.compliant / summary.devices) * 100)
    : 0

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-light tracking-tight text-foreground flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-emerald-500" />
            {t("compliance.title")}
          </h1>
          <p className="text-muted-foreground mt-2">
            {t("compliance.intro")}{" "}
            {t("compliance.generatedAt", {
              time: summary ? new Date(summary.generated_at).toLocaleString(uiLocale()) : "—",
            })}
          </p>
        </div>
        {/* print:hidden — кнопки не должны попасть в распечатанный PDF. */}
        <div className="flex gap-2 print:hidden">
          <Button size="sm" variant="outline" onClick={() => load()}>
            <RefreshCw className="w-4 h-4 mr-1.5" />
            {t("common.refresh")}
          </Button>
          <Button size="sm" variant="outline" onClick={handleDownloadCSV}>
            <Download className="w-4 h-4 mr-1.5" />
            CSV
          </Button>
          <Button size="sm" variant="outline" onClick={() => window.print()}>
            <Printer className="w-4 h-4 mr-1.5" />
            PDF
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <SpotlightCard className="p-6 flex flex-col justify-between">
          <h3 className="font-medium text-foreground mb-4">{t("compliance.compliant")}</h3>
          <div>
            <p className="text-3xl font-light tabular-nums text-emerald-500">
              {summary?.compliant ?? 0}
              <span className="text-lg text-muted-foreground"> / {summary?.devices ?? 0}</span>
            </p>
            <p className="text-sm text-muted-foreground mt-1">{t("compliance.share", { percent: share })}</p>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-6 flex flex-col justify-between">
          <h3 className="font-medium text-foreground mb-4">{t("compliance.attention")}</h3>
          <div>
            <p className="text-3xl font-light tabular-nums text-amber-500">{summary?.non_compliant ?? 0}</p>
            <p className="text-sm text-muted-foreground mt-1">{t("compliance.withIssues")}</p>
          </div>
        </SpotlightCard>

        <SpotlightCard className="p-6">
          <h3 className="font-medium text-foreground mb-4">{t("compliance.byReason")}</h3>
          {summary && Object.keys(summary.by_reason).length > 0 ? (
            <ul className="space-y-1.5">
              {Object.entries(summary.by_reason)
                .sort((a, b) => b[1] - a[1])
                .map(([reason, count]) => (
                  <li key={reason} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t(`complianceReason.${reason}`, reason)}</span>
                    <span className="tabular-nums font-medium">{count}</span>
                  </li>
                ))}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">{t("compliance.noIssues")}</p>
          )}
        </SpotlightCard>
      </div>

      <div className="bg-card border border-border/50 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-border/50 bg-muted/20 flex items-center justify-between gap-4">
          <h2 className="text-lg font-medium text-foreground flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-500" />
            {t("compliance.devices")}
          </h2>
          <label className="flex items-center gap-2 text-sm text-muted-foreground print:hidden">
            <input
              type="checkbox"
              checked={onlyProblems}
              onChange={(e) => setOnlyProblems(e.target.checked)}
              className="accent-amber-500"
            />
            {t("compliance.onlyProblems")}
          </label>
        </div>
        <div className="divide-y divide-border/50">
          {visible.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              {devices.length === 0 ? t("compliance.noDevices") : t("compliance.allCompliant")}
            </div>
          ) : (
            visible.map((d) => (
              <div key={d.device_id} className="p-4 flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium text-foreground truncate">{d.hostname || d.device_id}</p>
                  <p className="text-sm text-muted-foreground">
                    {t("compliance.deviceMeta", {
                      os: d.os,
                      version: d.os_version,
                      agent: d.agent_version || "—",
                      channel: d.update_channel,
                    })}
                    {d.vulnerable_count > 0 && ` · ${t("complianceReason.vulnerable")}: ${d.vulnerable_count}`}
                    {d.unverified_count > 0 && ` · ${t("complianceReason.unverified")}: ${d.unverified_count}`}
                  </p>
                </div>
                <ReasonBadges device={d} />
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
