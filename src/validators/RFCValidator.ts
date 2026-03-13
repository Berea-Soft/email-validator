/**
 * Validador RFC — equivalente a `RFCValidation` de egulias/email-validator.
 *
 * Valida la sintaxis de una dirección de email según:
 *   - RFC 5321 (Simple Mail Transfer Protocol)
 *   - RFC 5322 (Internet Message Format)
 *
 * Este es el validador base que verifica la estructura sintáctica del email.
 */

import type {
  IEmailValidationStrategy,
  EmailParts,
  EmailValidationError,
} from "../types/index.js";
import { parseEmail, MAX_EMAIL_LENGTH } from "../utils/parser.js";

export class RFCValidator implements IEmailValidationStrategy {
  readonly rule = "rfc" as const;

  validate(email: string, _parts: EmailParts | null): EmailValidationError | null {
    if (!email || typeof email !== "string") {
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "rfc",
      };
    }

    const trimmed = email.trim();

    if (trimmed.length === 0) {
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "rfc",
      };
    }

    if (trimmed.length > MAX_EMAIL_LENGTH) {
      return {
        code: "EMAIL_TOO_LONG",
        message: `El email excede la longitud máxima de ${MAX_EMAIL_LENGTH} caracteres`,
        rule: "rfc",
      };
    }

    // Verificar que no hay múltiples '@' sin comillas
    const atCount = (trimmed.match(/@/g) ?? []).length;
    if (atCount === 0) {
      return {
        code: "MISSING_AT_SIGN",
        message: "El email debe contener el símbolo '@'",
        rule: "rfc",
      };
    }

    // Múltiples @ solo son válidos si la parte local está entre comillas
    if (atCount > 1) {
      const lastAt = trimmed.lastIndexOf("@");
      const localPart = trimmed.slice(0, lastAt);
      if (!localPart.startsWith('"') || !localPart.endsWith('"')) {
        return {
          code: "MULTIPLE_AT_SIGNS",
          message: "El email contiene múltiples '@' fuera de una parte local entre comillas",
          rule: "rfc",
        };
      }
    }

    // Parsear el email completo
    const parseResult = parseEmail(trimmed);

    if (!parseResult.success) {
      return this.mapParseError(parseResult.error ?? "Formato inválido");
    }

    return null;
  }

  private mapParseError(error: string): EmailValidationError {
    // Mapear mensajes de error del parser a códigos de error tipados
    if (error.includes("vacío")) {
      return { code: "EMPTY_EMAIL", message: error, rule: "rfc" };
    }
    if (error.includes("longitud máxima") && error.includes("email")) {
      return { code: "EMAIL_TOO_LONG", message: error, rule: "rfc" };
    }
    if (error.includes("parte local") && error.includes("longitud")) {
      return { code: "LOCAL_PART_TOO_LONG", message: error, rule: "rfc" };
    }
    if (error.includes("dominio") && error.includes("longitud")) {
      return { code: "DOMAIN_TOO_LONG", message: error, rule: "rfc" };
    }
    if (error.includes("etiqueta") && error.includes("longitud")) {
      return { code: "LABEL_TOO_LONG", message: error, rule: "rfc" };
    }
    if (error.includes("'@'")) {
      return { code: "MISSING_AT_SIGN", message: error, rule: "rfc" };
    }
    if (error.includes("punto") && error.includes("comenzar")) {
      return { code: "LEADING_DOT", message: error, rule: "rfc" };
    }
    if (error.includes("punto") && error.includes("terminar")) {
      return { code: "TRAILING_DOT", message: error, rule: "rfc" };
    }
    if (error.includes("puntos consecutivos")) {
      return { code: "CONSECUTIVE_DOTS", message: error, rule: "rfc" };
    }
    if (error.includes("caracteres inválidos") || error.includes("carácter inválido")) {
      return { code: "INVALID_CHARACTERS", message: error, rule: "rfc" };
    }
    if (error.includes("dominio")) {
      return { code: "INVALID_DOMAIN", message: error, rule: "rfc" };
    }
    if (error.includes("parte local")) {
      return { code: "INVALID_LOCAL_PART", message: error, rule: "rfc" };
    }

    return { code: "INVALID_FORMAT", message: error, rule: "rfc" };
  }
}
