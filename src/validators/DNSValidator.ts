/**
 * Validador DNS — equivalente a `DNSCheckValidation` de egulias/email-validator.
 *
 * Verifica que el dominio del email tenga registros DNS válidos:
 *   1. Registros MX (preferido) — indica que el dominio acepta correo
 *   2. Registros A o AAAA (fallback) — el dominio existe aunque sin MX explícito
 *
 * Comportamiento equivalente al de Laravel:
 *   - Falla si el dominio es local o reservado (test, example, localhost, etc.)
 *   - Falla si no hay registros DNS (MX, A ni AAAA)
 *   - Falla si el dominio tiene un Null MX (RFC 7505) — indica que no acepta correo
 *   - Genera advertencia si solo hay registros A/AAAA (sin MX)
 */

import type {
  IAsyncEmailValidationStrategy,
  EmailParts,
  EmailValidationError,
  EmailValidationWarning,
} from "../types/index.js";
import { lookupDNS } from "../utils/dns.js";

export class DNSValidator implements IAsyncEmailValidationStrategy {
  readonly rule = "dns" as const;

  private _warnings: EmailValidationWarning[] = [];
  private timeoutMs: number;

  constructor(timeoutMs = 5000) {
    this.timeoutMs = timeoutMs;
  }

  getWarnings(): EmailValidationWarning[] {
    return this._warnings;
  }

  async validateAsync(
    email: string,
    parts: EmailParts | null
  ): Promise<EmailValidationError | null> {
    this._warnings = [];

    // Si no se pudo parsear el email, no podemos validar DNS
    if (!parts) {
      return {
        code: "INVALID_FORMAT",
        message: "No se puede validar DNS: el email no tiene un formato válido",
        rule: "dns",
      };
    }

    const domain = parts.domain;

    // Los literales de IP no se consultan en DNS
    if (parts.isIPLiteral) {
      return null;
    }

    const result = await lookupDNS(domain, this.timeoutMs);

    // Dominio local o reservado
    if (
      result.error?.includes("local o reservado") ||
      result.error?.includes("reservado")
    ) {
      return {
        code: "LOCAL_OR_RESERVED_DOMAIN",
        message: result.error,
        rule: "dns",
      };
    }

    // Sin registros DNS
    if (!result.hasRecords) {
      return {
        code: "NO_DNS_RECORD",
        message:
          result.error ??
          `No se encontraron registros DNS para el dominio '${domain}'`,
        rule: "dns",
      };
    }

    // Null MX (dominio que no acepta correo)
    if (!result.acceptsMail) {
      return {
        code: "DOMAIN_ACCEPTS_NO_MAIL",
        message:
          result.error ??
          `El dominio '${domain}' tiene un registro Null MX y no acepta correo`,
        rule: "dns",
      };
    }

    // Sin MX pero con A/AAAA (advertencia, no error)
    if (result.hasARecord && result.mxRecords.length === 0) {
      this._warnings.push({
        code: "NO_MX_RECORD_FALLBACK",
        message: `El dominio '${domain}' no tiene registros MX; se usaron registros A/AAAA como fallback`,
      });
    }

    // Propagar advertencias del lookup
    for (const warning of result.warnings) {
      this._warnings.push({
        code: "NO_MX_RECORD_FALLBACK",
        message: warning,
      });
    }

    return null;
  }
}
