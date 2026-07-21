import React, { useEffect, useRef, useState } from "react"
import { Plus, Trash2, ChevronDown, ChevronUp, Upload } from "lucide-react"
import api, { Script, ScriptPlatform, scriptPlatformFromFilename } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

import { Select } from "@/components/ui/select"
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import ConfirmDialog from "@/components/ConfirmDialog"
import { toast } from "@/lib/toast"
import { formatDistanceToNow } from "@/lib/time"

const PLATFORM_PLACEHOLDER: Record<string, string> = {
  macOS:   "#!/bin/bash\necho \"Hello from macOS\"",
  Windows: "Write-Host \"Hello from Windows\"",
  linux:   "#!/bin/bash\necho \"Hello from Linux\"",
}

const PLATFORM_OPTIONS = [
  { value: "macOS", label: "macOS" },
  { value: "Windows", label: "Windows" },
  { value: "linux", label: "Linux" },
]

const PLATFORM_COLOR: Record<string, string> = {
  macOS:   "text-blue-600 dark:text-blue-400 bg-blue-500/10 border-blue-500/20",
  Windows: "text-violet-600 dark:text-violet-400 bg-violet-500/10 border-violet-500/20",
  linux:   "text-amber-600 dark:text-amber-400 bg-amber-500/10 border-amber-500/20",
}

const FILTER_ITEMS: { value: "all" | ScriptPlatform; label: string; color: string }[] = [
  { value: "all",     label: "Все",     color: "brand-gradient text-white dark:text-[hsl(224_14%_10%)]" },
  { value: "macOS",   label: "macOS",   color: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border border-blue-500/30" },
  { value: "linux",   label: "Linux",   color: "bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30" },
  { value: "Windows", label: "Windows", color: "bg-violet-500/15 text-violet-600 dark:text-violet-400 border border-violet-500/30" },
]

export default function Scripts() {
  const [scripts, setScripts] = useState<Script[]>([])
  const [loading, setLoading] = useState(true)
  const [editScript, setEditScript] = useState<Script | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [form, setForm] = useState({ name: "", platform: "macOS" as ScriptPlatform, content: "" })
  const [submitting, setSubmitting] = useState(false)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [osFilter, setOsFilter] = useState<"all" | ScriptPlatform>("all")
  const [query, setQuery] = useState("")
  const [confirmDelete, setConfirmDelete] = useState<Script | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  async function load() {
    try {
      const r = await api.get<Script[]>("/scripts")
      setScripts(r.data ?? [])
    } catch {
      toast({ title: "Не удалось загрузить скрипты", variant: "destructive" })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function handleCreate() {
    setSubmitting(true)
    try {
      await api.post("/scripts", form)
      setCreateOpen(false)
      setForm({ name: "", platform: "macOS", content: "" })
      await load()
      toast({ title: "Скрипт сохранён", variant: "success" })
    } catch {
      toast({ title: "Не удалось создать скрипт", variant: "destructive" })
    } finally {
      setSubmitting(false)
    }
  }

  async function handleFileSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ""
    if (!file) return
    const content = await file.text()
    setForm({ name: file.name, platform: scriptPlatformFromFilename(file.name), content })
    setCreateOpen(true)
  }

  async function handleUpdate() {
    if (!editScript) return
    setSubmitting(true)
    try {
      await api.put(`/scripts/${editScript.id}`, {
        name: editScript.name,
        platform: editScript.platform,
        content: editScript.content,
      })
      setEditScript(null)
      await load()
    } catch {
      toast({ title: "Не удалось обновить скрипт", variant: "destructive" })
    } finally {
      setSubmitting(false)
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.delete(`/scripts/${id}`)
      setScripts((prev) => prev.filter((s) => s.id !== id))
      toast({ title: "Скрипт удалён", variant: "success" })
    } catch {
      toast({ title: "Не удалось удалить скрипт", variant: "destructive" })
    }
  }

  if (loading) return <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">Загрузка...</div>

  const q = query.trim().toLowerCase()
  const visible = scripts
    .filter((s) => osFilter === "all" || s.platform === osFilter)
    .filter((s) => !q || s.name.toLowerCase().includes(q))

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-foreground">Скрипты</h1>
        <div className="flex items-center gap-2">
          <input
            ref={fileInputRef}
            type="file"
            accept=".sh,.py,.ps1"
            aria-label="Загрузить файл скрипта"
            className="hidden"
            onChange={handleFileSelected}
          />
          <Button size="sm" variant="outline" onClick={() => fileInputRef.current?.click()}>
            <Upload className="h-4 w-4 mr-1.5" />
            Загрузить
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4 mr-1.5" />
            Новый скрипт
          </Button>
        </div>
      </div>

      {/* Фильтры — отдельная стеклянная панель, как на «Устройствах»: карте таблицы
          нужен overflow-hidden, и он обрезал бы всплывающие элементы фильтров. */}
      <div className="glass flex flex-wrap items-center gap-3 px-5 py-4">
        <div className="flex items-center gap-1.5">
          {FILTER_ITEMS.map(({ value, label, color }) => (
            <button
              type="button"
              key={value}
              onClick={() => setOsFilter(value)}
              className={`rounded-md px-2.5 py-1 text-xs transition-colors ${
                osFilter === value ? color : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        <Input
          placeholder="Поиск по названию..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="ml-auto max-w-xs"
        />
      </div>

      <div className="glass overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-t-0 hover:bg-transparent">
              <TableHead className="text-xs">Название</TableHead>
              <TableHead className="text-xs">Платформа</TableHead>
              <TableHead className="text-xs">Обновлён</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.length === 0 && (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={4} className="text-center text-sm text-muted-foreground py-8">
                  Нет скриптов
                </TableCell>
              </TableRow>
            )}
            {visible.map((s) => (
              <React.Fragment key={s.id}>
                <TableRow
                  className="cursor-pointer glass-hover"
                  onClick={() => setExpandedId(expandedId === s.id ? null : s.id)}
                >
                  <TableCell className="px-4 py-3 text-sm font-medium text-foreground">{s.name}</TableCell>
                  <TableCell className="px-4 py-3">
                    <Badge variant="outline" className={PLATFORM_COLOR[s.platform]}>
                      {s.platform}
                    </Badge>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-xs text-muted-foreground">
                    {formatDistanceToNow(s.updated_at)}
                  </TableCell>
                  <TableCell className="px-4 py-3">
                    <div className="flex items-center gap-2 justify-end">
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); setEditScript(s) }}
                        className="text-muted-foreground hover:text-foreground transition-colors text-xs"
                      >
                        Изменить
                      </button>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); setConfirmDelete(s) }}
                        className="text-muted-foreground hover:text-destructive transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                      {expandedId === s.id
                        ? <ChevronUp className="h-4 w-4 text-muted-foreground" />
                        : <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      }
                    </div>
                  </TableCell>
                </TableRow>
                {expandedId === s.id && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={4} className="px-4 py-3">
                      {/* Блок кода читается как «терминал» — остаётся на bg-muted,
                          но радиус и бордер берёт у системы (как pre в диалогах). */}
                      <pre className="rounded-md border border-border bg-muted px-3 py-3 text-xs font-mono whitespace-pre-wrap break-all text-soft max-h-60 overflow-auto">
                        {s.content}
                      </pre>
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Новый скрипт</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Название</Label>
                <Input
                  placeholder="Обновление Chrome"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Платформа</Label>
                <Select
                  value={form.platform}
                  onChange={(v) => setForm({ ...form, platform: v as ScriptPlatform })}
                  options={PLATFORM_OPTIONS}
                />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="script-content-new">Содержимое</Label>
              <textarea
                id="script-content-new"
                className="flex min-h-48 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-y"
                placeholder={PLATFORM_PLACEHOLDER[form.platform]}
                value={form.content}
                onChange={(e) => setForm({ ...form, content: e.target.value })}
              />
            </div>
            <Button
              className="w-full"
              onClick={handleCreate}
              disabled={submitting || !form.name || !form.content}
            >
              {submitting ? "Сохранение..." : "Создать"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editScript} onOpenChange={(o) => !o && setEditScript(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Редактировать скрипт</DialogTitle>
          </DialogHeader>
          {editScript && (
            <div className="space-y-4 pt-2">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Название</Label>
                  <Input
                    value={editScript.name}
                    onChange={(e) => setEditScript({ ...editScript, name: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Платформа</Label>
                  <Select
                    value={editScript.platform}
                    onChange={(v) => setEditScript({ ...editScript, platform: v as ScriptPlatform })}
                    options={PLATFORM_OPTIONS}
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="script-content-edit">Содержимое</Label>
                <textarea
                  id="script-content-edit"
                  className="flex min-h-48 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-y"
                  value={editScript.content}
                  onChange={(e) => setEditScript({ ...editScript, content: e.target.value })}
                />
              </div>
              <Button
                className="w-full"
                onClick={handleUpdate}
                disabled={submitting || !editScript.name || !editScript.content}
              >
                {submitting ? "Сохранение..." : "Сохранить"}
              </Button>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title="Удалить скрипт?"
        description={confirmDelete ? `«${confirmDelete.name}» будет удалён без возможности восстановления.` : ""}
        confirmLabel="Удалить"
        destructive
        onConfirm={() => { if (confirmDelete) handleDelete(confirmDelete.id) }}
      />
    </div>
  )
}
