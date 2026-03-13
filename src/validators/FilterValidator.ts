/**
 * Validador Filter — equivalente a `FilterEmailValidation` de egulias/email-validator.
 *
 * Implementa una validación de email similar a la función `filter_var` de PHP
 * con `FILTER_VALIDATE_EMAIL`. Es más permisiva que la validación RFC completa
 * pero más estricta que una simple expresión regular.
 *
 * Características:
 *   - Usa una expresión regular robusta basada en el comportamiento de filter_var
 *   - No permite partes locales entre comillas
 *   - No permite literales de IP como dominio
 *   - Requiere TLD de al menos 2 caracteres
 *   - Permite caracteres Unicode en el dominio (IDN)
 */

import type {
  IEmailValidationStrategy,
  EmailParts,
  EmailValidationError,
} from "../types/index.js";

/**
 * Expresión regular que emula el comportamiento de `filter_var($email, FILTER_VALIDATE_EMAIL)` de PHP.
 *
 * Basada en el RFC 5321 con las mismas restricciones que aplica PHP:
 *   - Parte local: letras, números y caracteres especiales permitidos
 *   - Dominio: etiquetas separadas por puntos, TLD de al menos 2 caracteres
 */
const FILTER_VAR_REGEX =
  /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

/**
 * Expresión regular extendida que permite algunos caracteres Unicode en el dominio.
 * Equivalente a `FilterEmailValidation::unicode()` de egulias.
 */
const FILTER_VAR_UNICODE_REGEX =
  /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+)*@(?:[\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,}$/u;

export class FilterValidator implements IEmailValidationStrategy {
  readonly rule = "filter" as const;

  private allowUnicode: boolean;

  constructor(allowUnicode = false) {
    this.allowUnicode = allowUnicode;
  }

  validate(email: string, _parts: EmailParts | null): EmailValidationError | null {
    if (!email || typeof email !== "string") {
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "filter",
      };
    }

    const trimmed = email.trim();

    if (trimmed.length === 0) {
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "filter",
      };
    }

    const regex = this.allowUnicode ? FILTER_VAR_UNICODE_REGEX : FILTER_VAR_REGEX;

    if (!regex.test(trimmed)) {
      return {
        code: "INVALID_FORMAT",
        message: this.allowUnicode
          ? "El email no tiene un formato válido (filter_unicode)"
          : "El email no tiene un formato válido (filter)",
        rule: "filter",
      };
    }

    return null;
  }
}

/**
 * Variante del FilterValidator que permite caracteres Unicode.
 * Equivalente a `FilterEmailValidation::unicode()`.
 */
export class FilterUnicodeValidator extends FilterValidator {
  constructor() {
    super(true);
  }
}
