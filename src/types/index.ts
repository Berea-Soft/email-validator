/**
 * Tipos principales de la librería de validación de emails.
 * Inspirados en el sistema de validación de Laravel (egulias/email-validator).
 */

// ---------------------------------------------------------------------------
// Reglas de validación disponibles
// ---------------------------------------------------------------------------

/**
 * Reglas de validación disponibles, equivalentes a las de Laravel:
 *
 * - `rfc`    → Valida según RFC 5321/5322 (RFCValidation)
 * - `strict` → RFC estricto, falla ante warnings (NoRFCWarningsValidation)
 * - `dns`    → Verifica registros MX/A/AAAA en DNS (DNSCheckValidation)
 * - `spoof`  → Detecta caracteres Unicode homógrafos (SpoofCheckValidation)
 * - `filter` → Validación básica equivalente a filter_var de PHP
 */
export type EmailValidationRule = "rfc" | "strict" | "dns" | "spoof" | "filter";

// ---------------------------------------------------------------------------
// Resultado de validación
// ---------------------------------------------------------------------------

/** Código de error de validación */
export type EmailValidationErrorCode =
  | "INVALID_FORMAT"
  | "INVALID_LOCAL_PART"
  | "INVALID_DOMAIN"
  | "CONSECUTIVE_DOTS"
  | "LEADING_DOT"
  | "TRAILING_DOT"
  | "MISSING_AT_SIGN"
  | "MULTIPLE_AT_SIGNS"
  | "EMPTY_EMAIL"
  | "EMAIL_TOO_LONG"
  | "LOCAL_PART_TOO_LONG"
  | "DOMAIN_TOO_LONG"
  | "LABEL_TOO_LONG"
  | "INVALID_CHARACTERS"
  | "NO_DNS_RECORD"
  | "NO_MX_RECORD"
  | "LOCAL_OR_RESERVED_DOMAIN"
  | "DOMAIN_ACCEPTS_NO_MAIL"
  | "SPOOF_DETECTED"
  | "DNS_LOOKUP_FAILED";

/** Código de advertencia de validación */
export type EmailValidationWarningCode =
  | "NO_MX_RECORD_FALLBACK"
  | "DEPRECATED_COMMENT"
  | "QUOTED_STRING"
  | "UNICODE_IN_LOCAL_PART";

/** Representa un error de validación */
export interface EmailValidationError {
  /** Código de error identificador */
  code: EmailValidationErrorCode;
  /** Mensaje descriptivo del error */
  message: string;
  /** Regla que produjo el error */
  rule: EmailValidationRule | "syntax";
}

/** Representa una advertencia de validación (no bloquea la validez) */
export interface EmailValidationWarning {
  /** Código de advertencia */
  code: EmailValidationWarningCode;
  /** Mensaje descriptivo */
  message: string;
}

/** Resultado completo de la validación de un email */
export interface EmailValidationResult {
  /** Indica si el email es válido según todas las reglas aplicadas */
  valid: boolean;
  /** Email evaluado */
  email: string;
  /** Errores encontrados (vacío si es válido) */
  errors: EmailValidationError[];
  /** Advertencias (el email puede ser válido pero con observaciones) */
  warnings: EmailValidationWarning[];
  /** Reglas que se aplicaron durante la validación */
  appliedRules: EmailValidationRule[];
  /** Partes del email (disponible si la sintaxis es válida) */
  parts?: EmailParts;
}

/** Partes descompuestas de un email */
export interface EmailParts {
  /** Parte local (antes del @) */
  local: string;
  /** Dominio (después del @) */
  domain: string;
  /** Indica si la parte local está entre comillas */
  isQuoted: boolean;
  /** Indica si el dominio es un literal IP */
  isIPLiteral: boolean;
}

// ---------------------------------------------------------------------------
// Opciones del validador
// ---------------------------------------------------------------------------

/** Opciones de configuración del validador de email */
export interface EmailValidatorOptions {
  /**
   * Reglas de validación a aplicar.
   * @default ["rfc"]
   */
  rules?: EmailValidationRule[];

  /**
   * Tiempo máximo en milisegundos para la consulta DNS.
   * @default 5000
   */
  dnsTimeout?: number;

  /**
   * Servidores DNS personalizados para la resolución (solo Node.js).
   * @default Sistema operativo
   */
  dnsServers?: string[];

  /**
   * Si es `true`, permite dominios reservados/locales en la validación DNS.
   * @default false
   */
  allowReservedDomains?: boolean;
}

// ---------------------------------------------------------------------------
// Interfaz del validador
// ---------------------------------------------------------------------------

/** Interfaz principal del validador de email */
export interface IEmailValidator {
  /**
   * Valida un email de forma síncrona (sin DNS).
   * @param email - Dirección de email a validar
   * @param rules - Reglas opcionales (sobreescriben las del constructor)
   */
  validate(email: string, rules?: EmailValidationRule[]): EmailValidationResult;

  /**
   * Valida un email de forma asíncrona (con soporte DNS).
   * @param email - Dirección de email a validar
   * @param rules - Reglas opcionales (sobreescriben las del constructor)
   */
  validateAsync(
    email: string,
    rules?: EmailValidationRule[]
  ): Promise<EmailValidationResult>;
}

// ---------------------------------------------------------------------------
// Interfaz de cada validador individual
// ---------------------------------------------------------------------------

/** Interfaz que deben implementar todos los validadores individuales */
export interface IEmailValidationStrategy {
  /** Nombre de la regla */
  readonly rule: EmailValidationRule;
  /**
   * Ejecuta la validación sobre el email o sus partes.
   * @returns `null` si es válido, o un `EmailValidationError` si falla.
   */
  validate(
    email: string,
    parts: EmailParts | null
  ): EmailValidationError | null;
}

/** Interfaz para validadores asíncronos (como DNS) */
export interface IAsyncEmailValidationStrategy {
  readonly rule: EmailValidationRule;
  validateAsync(
    email: string,
    parts: EmailParts | null
  ): Promise<EmailValidationError | null>;
  getWarnings(): EmailValidationWarning[];
}
