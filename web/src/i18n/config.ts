import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import ru from "../locales/ru.json";
import en from "../locales/en.json";

export const resources = {
  ru: {
    translation: ru,
  },
  en: {
    translation: en,
  },
} as const;

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: "ru",
    debug: import.meta.env.DEV,
    interpolation: {
      escapeValue: false, // React already escapes by default
    },
  });

// 🔴 Держим <html lang> в согласии с выбранным языком.
//
// В index.html он прибит как "en" и НИКЕМ не обновлялся, хотя интерфейс по умолчанию
// русский. Отсюда два следствия: скринридер читает русский текст правилами английского,
// а любое форматирование, опирающееся на язык страницы (даты, числа), берёт не ту
// локаль. Подписка ниже — единственное место, где это чинится для всего приложения.
function syncDocumentLang(lng: string) {
  if (typeof document !== "undefined") {
    document.documentElement.lang = lng;
  }
}

syncDocumentLang(i18n.language);
i18n.on("languageChanged", syncDocumentLang);

export default i18n;
