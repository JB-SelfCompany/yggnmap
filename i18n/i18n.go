package i18n

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Language represents a supported language
type Language string

const (
	English Language = "en"
	Russian Language = "ru"
)

// Translations contains all translation strings
type Translations map[string]map[Language]string

// translator manages translations
type Translator struct {
	translations Translations
	defaultLang  Language
}

// Global translator instance
var globalTranslator *Translator

// sanitizeLanguageCode validates and sanitizes language codes
func sanitizeLanguageCode(lang string) Language {
	// Only allow alphanumeric characters
	reg := regexp.MustCompile(`^[a-z]{2}$`)
	if !reg.MatchString(lang) {
		return English // Default to English if invalid
	}

	switch Language(lang) {
	case English:
		return English
	case Russian:
		return Russian
	default:
		return English
	}
}

// initTranslations initializes all translation strings
func initTranslations() Translations {
	return Translations{
		// Page title and header
		"page_title": {
			English: "YggNmap - Yggdrasil Port Scanner",
			Russian: "YggNmap - Сканер портов Yggdrasil",
		},
		"subtitle": {
			English: "Free Port Scanner for Yggdrasil Network",
			Russian: "Бесплатный сканер портов для сети Yggdrasil",
		},
		"your_address": {
			English: "We will scan this IPv6 address:",
			Russian: "Мы просканируем этот IPv6 адрес:",
		},
		"detecting_address": {
			English: "Detecting your address...",
			Russian: "Определяем ваш адрес...",
		},

		// About section
		"about_title": {
			English: "About This Service",
			Russian: "О сервисе",
		},
		"about_description": {
			English: "This is a free port scanning service for Yggdrasil Network users. We automatically detect your IPv6 address and scan it for open ports, helping you identify potential security vulnerabilities. No installation required - just click scan!",
			Russian: "Это бесплатный сервис сканирования портов для пользователей сети Yggdrasil. Мы автоматически определяем ваш IPv6 адрес и сканируем открытые порты, помогая выявить потенциальные уязвимости безопасности. Не требуется установка - просто нажмите сканировать!",
		},
		"quick_scan_info": {
			English: "Quick Scan: Scans 1000 most common ports (1-3 minutes)",
			Russian: "Быстрое сканирование: Проверяет 1000 наиболее распространённых портов (1-3 минуты)",
		},
		"full_scan_info": {
			English: "Full Scan: Scans all 65,535 ports (10-30 minutes)",
			Russian: "Полное сканирование: Проверяет все 65,535 портов (10-30 минут)",
		},
		"supports_info": {
			English: "Supports both 200::/8 (node addresses) and 300::/8 (subnet addresses)",
			Russian: "Поддерживает как 200::/8 (адреса узлов), так и 300::/8 (адреса подсетей)",
		},
		"rate_limit_info": {
			English: "Rate limits: Quick scan once per 30 seconds, Full scan once per 60 seconds, Custom scan once per 45 seconds",
			Russian: "Ограничения: Быстрое сканирование раз в 30 секунд, Полное сканирование раз в 60 секунд, Сканирование портов раз в 45 секунд",
		},

		// Buttons
		"quick_scan_btn": {
			English: "Quick Scan",
			Russian: "Быстрое сканирование",
		},
		"full_scan_btn": {
			English: "Full Scan",
			Russian: "Полное сканирование",
		},
		"custom_scan_btn": {
			English: "Custom Scan",
			Russian: "Сканирование портов",
		},
		"port_input_placeholder": {
			English: "e.g., 80,443 or 1-1000",
			Russian: "например, 80,443 или 1-1000",
		},
		"custom_scan_info": {
			English: "Custom Scan: Enter specific ports or ranges to scan",
			Russian: "Сканирование портов: Введите конкретные порты или диапазоны",
		},

		// Results
		"scan_results_quick": {
			English: "Quick Scan Results",
			Russian: "Результаты быстрого сканирования",
		},
		"scan_results_full": {
			English: "Full Scan Results",
			Russian: "Результаты полного сканирования",
		},
		"scan_results_custom": {
			English: "Custom Scan Results",
			Russian: "Результаты сканирования портов",
		},
		"port": {
			English: "Port",
			Russian: "Порт",
		},
		"protocol": {
			English: "Protocol",
			Russian: "Протокол",
		},
		"state": {
			English: "State",
			Russian: "Состояние",
		},
		"service": {
			English: "Service",
			Russian: "Сервис",
		},
		"no_ports_found": {
			English: "No open ports found. Your node is secure!",
			Russian: "Открытых портов не найдено. Ваш узел защищён!",
		},
		"scan_completed": {
			English: "Scan completed in %.2f seconds. Found %d open port(s).",
			Russian: "Сканирование завершено за %.2f секунд. Найдено портов: %d.",
		},

		// Loading and progress
		"scanning": {
			English: "Scanning ports...",
			Russian: "Сканируем порты...",
		},
		"initializing": {
			English: "Initializing scan...",
			Russian: "Инициализация сканирования...",
		},
		"progress": {
			English: "Progress: %d%%",
			Russian: "Прогресс: %d%%",
		},
		"port_found": {
			English: "Found open port: %d/%s",
			Russian: "Найден открытый порт: %d/%s",
		},

		// Export
		"export_csv": {
			English: "Export CSV",
			Russian: "Экспорт CSV",
		},
		"export_json": {
			English: "Export JSON",
			Russian: "Экспорт JSON",
		},
		"export_pdf": {
			English: "Export PDF",
			Russian: "Экспорт PDF",
		},

		// Errors
		"error_init": {
			English: "Failed to initialize. %s. Please refresh the page or check your connection.",
			Russian: "Ошибка инициализации. %s. Пожалуйста, обновите страницу или проверьте соединение.",
		},
		"error_csrf": {
			English: "Security token not available. Please refresh the page.",
			Russian: "Токен безопасности недоступен. Пожалуйста, обновите страницу.",
		},
		"error_csrf_expired": {
			English: "Security token expired. Please try again.",
			Russian: "Токен безопасности истёк. Пожалуйста, попробуйте снова.",
		},
		"error_scan": {
			English: "Scan error: %s",
			Russian: "Ошибка сканирования: %s",
		},
		"error_ports_required": {
			English: "Please enter ports to scan (e.g., 80,443 or 1-1000)",
			Russian: "Пожалуйста, введите порты для сканирования (например, 80,443 или 1-1000)",
		},
		"error_rate_limit_quick": {
			English: "Rate limit exceeded. Please wait 30 seconds before scanning again.",
			Russian: "Превышен лимит. Пожалуйста, подождите 30 секунд перед повторным сканированием.",
		},
		"error_rate_limit_full": {
			English: "Rate limit exceeded. Please wait 60 seconds before scanning again.",
			Russian: "Превышен лимит. Пожалуйста, подождите 60 секунд перед повторным сканированием.",
		},
		"error_rate_limit_custom": {
			English: "Rate limit exceeded. Please wait 45 seconds before scanning again.",
			Russian: "Превышен лимит. Пожалуйста, подождите 45 секунд перед повторным сканированием.",
		},
		"error_server_busy": {
			English: "Server is currently busy. Please try again later.",
			Russian: "Сервер в данный момент занят. Пожалуйста, попробуйте позже.",
		},
		"error_export": {
			English: "Export failed: %s",
			Russian: "Ошибка экспорта: %s",
		},
		"error_websocket": {
			English: "WebSocket connection failed: %s",
			Russian: "Ошибка WebSocket соединения: %s",
		},

		// Theme
		"dark_mode": {
			English: "Dark Mode",
			Russian: "Тёмная тема",
		},
		"light_mode": {
			English: "Light Mode",
			Russian: "Светлая тема",
		},
	}
}

// NewTranslator creates a new translator
func NewTranslator(defaultLang Language) *Translator {
	return &Translator{
		translations: initTranslations(),
		defaultLang:  defaultLang,
	}
}

// Get retrieves a translation for a given key and language
func (t *Translator) Get(key string, lang Language) string {
	if translations, ok := t.translations[key]; ok {
		if translation, ok := translations[lang]; ok {
			return translation
		}
		// Fallback to default language
		if translation, ok := translations[t.defaultLang]; ok {
			return translation
		}
	}
	// Return key if translation not found
	return key
}

// GetAllForLanguage returns all translations for a specific language as JSON
func (t *Translator) GetAllForLanguage(lang Language) (string, error) {
	result := make(map[string]string)

	for key, translations := range t.translations {
		if translation, ok := translations[lang]; ok {
			result[key] = translation
		} else if translation, ok := translations[t.defaultLang]; ok {
			// Fallback to default language
			result[key] = translation
		}
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal translations: %w", err)
	}

	return string(jsonData), nil
}

// ValidateLanguage validates and returns a sanitized language code
func ValidateLanguage(lang string) Language {
	return sanitizeLanguageCode(strings.ToLower(strings.TrimSpace(lang)))
}

// GetSupportedLanguages returns a list of supported languages
func GetSupportedLanguages() []Language {
	return []Language{English, Russian}
}

// Init initializes the global translator
func Init() {
	globalTranslator = NewTranslator(English)
}

// Get is a convenience function for getting translations from the global translator
func Get(key string, lang Language) string {
	if globalTranslator == nil {
		Init()
	}
	return globalTranslator.Get(key, lang)
}

// GetAllForLanguage returns all translations for a specific language from the global translator
func GetAllForLanguage(lang Language) (string, error) {
	if globalTranslator == nil {
		Init()
	}
	return globalTranslator.GetAllForLanguage(lang)
}
