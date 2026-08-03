import { useEffect, useState } from "react"
import api from "@/lib/api"

export interface Me {
  id: string
  email: string
  name: string
  role: string
  // ADR-7: надзор над инсталляцией — признак личности, а не роль в тенанте.
  // Он не меняется при переключении тенанта, поэтому и приходит отдельным полем.
  is_provider_admin?: boolean
  mfa_enabled?: boolean
}

// Модульный кэш: /me тянется один раз на сессию (роль редко меняется в рамках сессии),
// повторные маунты берут из кэша. clearMeCache() зовётся на logout.
let cached: Me | null = null

export function useMe() {
  const [me, setMe] = useState<Me | null>(cached)
  const [loading, setLoading] = useState(!cached)

  useEffect(() => {
    if (cached) return
    api
      .get<Me>("/me")
      .then((r) => {
        cached = r.data
        setMe(r.data)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return {
    me,
    isAdmin: me?.role === "it_admin",
    isProvider: me?.is_provider_admin === true,
    loading,
  }
}

export function clearMeCache() {
  cached = null
}
