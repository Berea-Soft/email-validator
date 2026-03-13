/**
 * API Fluida para validación de emails.
 *
 * Proporciona una interfaz encadenada similar al nuevo `Rule::email()` de Laravel 12:
 *
 * ```typescript
 * import { email } from '@bereasoft/email-validator';
 *
 * // Equivalente a 'email:rfc,dns' en Laravel
 * const result = await email()
 *   .rfcCompliant()
 *   .validateMxRecord()
 *   .validateAsync('user@example.com');
 *
 * // Equivalente a 'email:rfc,strict,dns,spoof' en Laravel
 * const result = await email()
 *   .rfcCompliant({ strict: true })
 *   .validateMxRecord()
 *   .preventSpoofing()
 *   .validateAsync('user@example.com');
 * ```
 */

import type {
  EmailValidationRule,
  EmailValidationResult,
  EmailValidatorOptions,
} from "./types/index.js";
import { EmailValidator } from "./EmailValidator.js";

// ---------------------------------------------------------------------------
// Builder de validación fluida
// ---------------------------------------------------------------------------

export class EmailValidationBuilder {
  private rules: EmailValidationRule[] = [];
  private options: EmailValidatorOptions = {};

  /**
   * Agrega validación RFC 5321/5322.
   * Equivalente a `email:rfc` en Laravel.
   *
   * @param options.strict - Si es `true`, equivale a `email:strict` (NoRFCWarningsValidation)
   */
  rfcCompliant(options: { strict?: boolean } = {}): this {
    this.rules.push(options.strict ? "strict" : "rfc");
    return this;
  }

  /**
   * Agrega validación de registro MX en DNS.
   * Equivalente a `email:dns` en Laravel.
   *
   * @param timeoutMs - Tiempo máximo de espera para la consulta DNS
   */
  validateMxRecord(timeoutMs?: number): this {
    this.rules.push("dns");
    if (timeoutMs !== undefined) {
      this.options.dnsTimeout = timeoutMs;
    }
    return this;
  }

  /**
   * Agrega validación anti-spoofing Unicode.
   * Equivalente a `email:spoof` en Laravel.
   */
  preventSpoofing(): this {
    this.rules.push("spoof");
    return this;
  }

  /**
   * Agrega validación tipo filter_var de PHP.
   * Equivalente a `email:filter` en Laravel.
   */
  filterValidation(): this {
    this.rules.push("filter");
    return this;
  }

  /**
   * Configura opciones adicionales del validador.
   */
  withOptions(options: Omit<EmailValidatorOptions, "rules">): this {
    this.options = { ...this.options, ...options };
    return this;
  }

  /**
   * Ejecuta la validación de forma síncrona (sin DNS).
   * Las reglas `dns` son ignoradas.
   */
  validate(emailAddress: string): EmailValidationResult {
    const validator = new EmailValidator({
      ...this.options,
      rules: this.rules,
    });
    return validator.validate(emailAddress);
  }

  /**
   * Ejecuta la validación de forma asíncrona (con soporte DNS).
   */
  async validateAsync(emailAddress: string): Promise<EmailValidationResult> {
    const validator = new EmailValidator({
      ...this.options,
      rules: this.rules,
    });
    return validator.validateAsync(emailAddress);
  }

  /**
   * Retorna las reglas configuradas actualmente.
   */
  getRules(): EmailValidationRule[] {
    return [...this.rules];
  }
}

// ---------------------------------------------------------------------------
// Funciones de conveniencia
// ---------------------------------------------------------------------------

/**
 * Crea un builder de validación fluida.
 * Punto de entrada principal de la API fluida.
 *
 * @example
 * ```typescript
 * const result = await email()
 *   .rfcCompliant()
 *   .validateMxRecord()
 *   .preventSpoofing()
 *   .validateAsync('user@example.com');
 * ```
 */
export function email(): EmailValidationBuilder {
  return new EmailValidationBuilder();
}

/**
 * Valida un email de forma rápida con reglas predefinidas.
 *
 * @param emailAddress - Dirección de email a validar
 * @param rules - Reglas a aplicar (por defecto: ['rfc'])
 * @returns `true` si el email es válido, `false` en caso contrario
 *
 * @example
 * ```typescript
 * isValidEmail('user@example.com'); // true
 * isValidEmail('invalid-email');    // false
 * ```
 */
export function isValidEmail(
  emailAddress: string,
  rules: EmailValidationRule[] = ["rfc"]
): boolean {
  const validator = new EmailValidator({ rules });
  return validator.validate(emailAddress).valid;
}

/**
 * Valida un email de forma asíncrona con soporte DNS.
 *
 * @param emailAddress - Dirección de email a validar
 * @param rules - Reglas a aplicar (por defecto: ['rfc', 'dns'])
 * @returns `true` si el email es válido, `false` en caso contrario
 *
 * @example
 * ```typescript
 * await isValidEmailAsync('user@gmail.com', ['rfc', 'dns']); // true
 * await isValidEmailAsync('user@notexistingdomain123456.com', ['rfc', 'dns']); // false
 * ```
 */
export async function isValidEmailAsync(
  emailAddress: string,
  rules: EmailValidationRule[] = ["rfc", "dns"]
): Promise<boolean> {
  const validator = new EmailValidator({ rules });
  const result = await validator.validateAsync(emailAddress);
  return result.valid;
}
