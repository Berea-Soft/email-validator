/**
 * @bereasoft/email-validator
 *
 * Librería TypeScript para validación de emails inspirada en el sistema de
 * validación de Laravel (egulias/email-validator).
 *
 * Reglas disponibles (equivalentes a las de Laravel):
 *   - `rfc`    → RFCValidation (RFC 5321/5322)
 *   - `strict` → NoRFCWarningsValidation
 *   - `dns`    → DNSCheckValidation (registros MX/A/AAAA)
 *   - `spoof`  → SpoofCheckValidation (homógrafos Unicode)
 *   - `filter` → FilterEmailValidation (equivalente a filter_var de PHP)
 *
 * @example
 * ```typescript
 * // API orientada a objetos
 * import { EmailValidator } from '@bereasoft/email-validator';
 *
 * const validator = new EmailValidator({ rules: ['rfc', 'filter'] });
 * const result = validator.validate('user@example.com');
 * console.log(result.valid); // true
 *
 * // Con DNS (asíncrono)
 * const result = await validator.validateAsync('user@example.com', ['rfc', 'dns']);
 *
 * // API fluida (estilo Laravel Rule::email())
 * import { email } from '@bereasoft/email-validator';
 *
 * const result = await email()
 *   .rfcCompliant()
 *   .validateMxRecord()
 *   .preventSpoofing()
 *   .validateAsync('user@example.com');
 *
 * // Funciones de conveniencia
 * import { isValidEmail, isValidEmailAsync } from '@bereasoft/email-validator';
 *
 * isValidEmail('user@example.com');                          // true (síncrono)
 * await isValidEmailAsync('user@gmail.com', ['rfc', 'dns']); // true (con DNS)
 * ```
 *
 * @module @bereasoft/email-validator
 */

// ---------------------------------------------------------------------------
// Clase principal
// ---------------------------------------------------------------------------
export { EmailValidator } from "./EmailValidator.js";
export type { EmailValidatorDependencies } from "./EmailValidator.js";

// ---------------------------------------------------------------------------
// API Fluida
// ---------------------------------------------------------------------------
export { email, isValidEmail, isValidEmailAsync, EmailValidationBuilder } from "./fluent.js";

// ---------------------------------------------------------------------------
// Validadores individuales (para uso avanzado)
// ---------------------------------------------------------------------------
export { RFCValidator } from "./validators/RFCValidator.js";
export { StrictRFCValidator } from "./validators/StrictRFCValidator.js";
export { DNSValidator } from "./validators/DNSValidator.js";
export { SpoofValidator } from "./validators/SpoofValidator.js";
export { FilterValidator, FilterUnicodeValidator } from "./validators/FilterValidator.js";

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------
export { parseEmail } from "./utils/parser.js";
export { lookupDNS, RESERVED_DOMAINS } from "./utils/dns.js";
export { analyzeSpoofing } from "./utils/spoof.js";

// ---------------------------------------------------------------------------
// Tipos
// ---------------------------------------------------------------------------
export type {
  EmailValidationRule,
  EmailValidationResult,
  EmailValidationError,
  EmailValidationWarning,
  EmailValidationErrorCode,
  EmailValidationWarningCode,
  EmailValidatorOptions,
  EmailParts,
  IEmailValidator,
  IEmailValidationStrategy,
  IAsyncEmailValidationStrategy,
} from "./types/index.js";
