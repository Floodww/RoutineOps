import axios from "axios"
import { clearMeCache } from "@/lib/useMe"
import { clearTenantsCache } from "@/lib/useTenants"

export async function login(email: string, password: string): Promise<{ mfaRequired?: boolean; mfaSetupRequired?: boolean }> {
  const res = await axios.post("/api/v1/auth/login", { email, password })
  if (res.data.status === "mfa_required") {
    return { mfaRequired: true }
  }
  if (res.data.status === "mfa_setup_required") {
    return { mfaSetupRequired: true }
  }
  sessionStorage.setItem("session", "1")
  clearMeCache()
  clearTenantsCache() // на случай смены пользователя без перезагрузки страницы
  return {}
}

export async function loginMFA(code: string): Promise<void> {
  await axios.post("/api/v1/auth/mfa/login", { code })
  sessionStorage.setItem("session", "1")
  clearMeCache()
  clearTenantsCache()
}

export async function logout() {
  await axios.post("/api/v1/auth/logout").catch(() => {})
  sessionStorage.removeItem("session")
  clearMeCache()
  clearTenantsCache()
}

export function isAuthenticated(): boolean {
  return sessionStorage.getItem("session") === "1"
}
