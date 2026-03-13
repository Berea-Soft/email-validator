/**
 * Validador RFC Estricto — equivalente a `NoRFCWarningsValidation` de egulias/email-validator.
 *
 * Extiende la validación RFC básica rechazando emails que, aunque técnicamente
 * válidos según el RFC, generan advertencias o son considerados malas prácticas:
 *
 *   - Partes locales entre comillas (quoted strings)
 *   - Comentarios en el email (p.ej. user(comment)@domain.com)
 *   - Caracteres obsoletos
 *   - Espacios en la parte local
 *   - Literales de IP como dominio
 */

import type {
  IEmailValidationStrategy,
  EmailParts,
  EmailValidationError,
} from "../types/index.js";
import { RFCValidator } from "./RFCValidator.js";

export class StrictRFCValidator implements IEmailValidationStrategy {
  readonly rule = "strict" as const;

  private rfcValidator = new RFCValidator();

  validate(email: string, parts: EmailParts | null): EmailValidationError | null {
    // Primero aplicar la validación RFC básica
    const rfcError = this.rfcValidator.validate(email, parts);
    if (rfcError) {
      // Convertir el error a la regla "strict"
      return { ...rfcError, rule: "strict" };
    }

    if (!parts) return null;

    // Rechazar partes locales entre comillas
    if (parts.isQuoted) {
      return {
        code: "INVALID_LOCAL_PART",
        message:
          "La validación estricta no permite partes locales entre comillas (quoted strings)",
        rule: "strict",
      };
    }

    // Rechazar literales de IP como dominio
    if (parts.isIPLiteral) {
      return {
        code: "INVALID_DOMAIN",
        message:
          "La validación estricta no permite literales de IP como dominio",
        rule: "strict",
      };
    }

    // Rechazar comentarios: (comment)user@domain o user@(comment)domain
    if (this.hasComments(email)) {
      return {
        code: "INVALID_FORMAT",
        message:
          "La validación estricta no permite comentarios en la dirección de email",
        rule: "strict",
      };
    }

    // Rechazar puntos al inicio o final de la parte local (ya cubierto en RFC,
    // pero aquí lo hacemos explícito para el modo estricto)
    if (parts.local.startsWith(".") || parts.local.endsWith(".")) {
      return {
        code: "LEADING_DOT",
        message:
          "La validación estricta no permite puntos al inicio o final de la parte local",
        rule: "strict",
      };
    }

    // Rechazar puntos consecutivos en la parte local
    if (parts.local.includes("..")) {
      return {
        code: "CONSECUTIVE_DOTS",
        message:
          "La validación estricta no permite puntos consecutivos en la parte local",
        rule: "strict",
      };
    }

    // Rechazar caracteres de espacio en la parte local
    if (/\s/.test(parts.local)) {
      return {
        code: "INVALID_CHARACTERS",
        message:
          "La validación estricta no permite espacios en la parte local",
        rule: "strict",
      };
    }

    return null;
  }

  /**
   * Detecta la presencia de comentarios en el email.
   * Los comentarios tienen la forma (texto) y pueden aparecer al inicio
   * o al final de la parte local o del dominio.
   */
  private hasComments(email: string): boolean {
    // Patrón: paréntesis al inicio de la parte local, al final, o en el dominio
    const commentPattern = /^\(.*?\)|(?<=@)\(.*?\)|\(.*?\)@|\(.*?\)$/;
    return commentPattern.test(email);
  }
}
