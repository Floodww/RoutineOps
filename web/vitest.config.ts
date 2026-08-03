import { defineConfig } from "vitest/config"
import path from "path"

// Отдельный конфиг для тестов — vite.config.ts (сборка) не трогаем.
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Язык интерфейса в тестах прибит явно — иначе LanguageDetector берёт его из
    // окружения раннера, и проверки текста начинают зависеть от машины. См. setup.ts.
    setupFiles: ["src/test/setup.ts"],
  },
})
