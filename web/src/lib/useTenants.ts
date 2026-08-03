import { useEffect, useState } from "react"
import api from "@/lib/api"

interface TenantsResp {
  show_tenant: boolean
  tenants: { id: string; name: string; created_at: string }[]
}

let cached: TenantsResp | null = null

export function useTenants() {
  const [data, setData] = useState<TenantsResp | null>(cached)
  const [loading, setLoading] = useState(!cached)

  useEffect(() => {
    if (cached) return
    api
      .get<TenantsResp>("/tenants")
      .then((r) => {
        cached = r.data
        setData(r.data)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return {
    showTenant: data?.show_tenant ?? false,
    tenants: data?.tenants ?? [],
    loading,
  }
}

export function clearTenantsCache() {
  cached = null
}
