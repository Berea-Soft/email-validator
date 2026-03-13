/**
 * Validador de Spoofing — equivalente a `SpoofCheckValidation` de egulias/email-validator.
 *
 * Detecta el uso de caracteres Unicode homógrafos o engañosos que podrían
 * usarse para suplantar identidades en direcciones de email.
 *
 * Ejemplos de spoofing:
 *   - "аdmin@example.com" — la 'а' es Cirílica (U+0430), no Latina
 *   - "pаypal@example.com" — mezcla de scripts
 *   - "user@ехаmple.com" — dominio con caracteres Cirílicos
 */

import type {
  IEmailValidationStrategy,
  EmailParts,
  EmailValidationError,
} from "../types/index.js";
import { analyzeSpoofing } from "../utils/spoof.js";

export class SpoofValidator implements IEmailValidationStrategy {
  readonly rule = "spoof" as const;

  validate(email: string, _parts: EmailParts | null): EmailValidationError | null {
    const result = analyzeSpoofing(email);

    if (result.isSpoofed) {
      return {
        code: "SPOOF_DETECTED",
        message:
          result.reason ??
          "Se detectaron caracteres Unicode potencialmente engañosos (homógrafos)",
        rule: "spoof",
      };
    }

    return null;
  }
}
