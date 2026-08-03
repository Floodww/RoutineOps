import { useCallback, useEffect, useState } from "react"
import api from "@/lib/api"

// ADR-7 §11.4: тенанты, в которых состоит ТЕКУЩАЯ личность. Не путать с useTenants —
// тот отдаёт реестр всей инсталляции и доступен только надзору. Здесь — «мои», и
// сервер не присылает сюда тенант, в котором человека нет.
export interface MyTenant {
  tenant_id: string
  tenant_name: string
  role: string
  active: boolean
}

let cached: MyTenant[] | null = null

export function useMyTenants() {
  const [tenants, setTenants] = useState<MyTenant[]>(cached ?? [])
  const [loading, setLoading] = useState(!cached)

  useEffect(() => {
    if (cached) return
    api
      .get<MyTenant[]>("/auth/tenants")
      .then((r) => {
        cached = r.data
        setTenants(r.data)
      })
      // Сервисный токен получает 403 (личности у него нет) — это не ошибка UI,
      // селектор просто не показывается.
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  // switchTenant меняет активный тенант и перезагружает приложение.
  //
  // Перезагрузка целиком, а не точечная инвалидация: после смены тенанта НИ ОДИН
  // ранее загруженный список не относится к новому тенанту, а модульные кэши
  // (/me, /tenants) живут вне React. Пропустить хоть один — показать человеку
  // данные чужого тенанта, и это худший исход, чем лишняя секунда загрузки.
  const switchTenant = useCallback(async (tenantID: string) => {
    await api.post("/auth/tenant", { tenant_id: tenantID })
    cached = null
    window.location.reload()
  }, [])

  return { tenants, switchTenant, loading }
}

export function clearMyTenantsCache() {
  cached = null
}
