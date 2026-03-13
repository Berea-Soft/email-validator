/**
 * Validador principal de emails.
 *
 * Orquesta todos los validadores individuales (RFC, Strict, DNS, Spoof, Filter)
 * de forma similar a como Laravel combina sus reglas de validación de email.
 *
 * Uso básico:
 * ```typescript
 * import { EmailValidator } from '@bereasoft/email-validator';
 *
 * // Validación síncrona (sin DNS)
 * const validator = new EmailValidator({ rules: ['rfc', 'filter'] });
 * const result = validator.validate('user@example.com');
 *
 * // Validación asíncrona (con DNS)
 * const result = await validator.validateAsync('user@example.com', ['rfc', 'dns']);
 * ```
 */

import type {
  IEmailValidator,
  IEmailValidationStrategy,
  IAsyncEmailValidationStrategy,
  EmailValidationRule,
  EmailValidationResult,
  EmailValidationError,
  EmailValidationWarning,
  EmailValidatorOptions,
  EmailParts,
} from "./types/index.js";
import { parseEmail } from "./utils/parser.js";
import { RFCValidator } from "./validators/RFCValidator.js";
import { StrictRFCValidator } from "./validators/StrictRFCValidator.js";
import { DNSValidator } from "./validators/DNSValidator.js";
import { SpoofValidator } from "./validators/SpoofValidator.js";
import { FilterValidator } from "./validators/FilterValidator.js";

type SyncRule = Exclude<EmailValidationRule, "dns">;
type AsyncRule = Extract<EmailValidationRule, "dns">;

type SyncStrategyFactory = () => IEmailValidationStrategy;
type AsyncStrategyFactory = () => IAsyncEmailValidationStrategy;

export interface EmailValidatorDependencies {
  /**
   * Registro opcional de fábricas para estrategias síncronas.
   * Permite extender/reemplazar estrategias sin modificar esta clase.
   */
  syncFactories?: Partial<Record<SyncRule, SyncStrategyFactory>>;

  /**
   * Registro opcional de fábricas para estrategias asíncronas.
   * Útil para pruebas y para desacoplar infraestructura (DNS).
   */
  asyncFactories?: Partial<Record<AsyncRule, AsyncStrategyFactory>>;
}

export class EmailValidator implements IEmailValidator {
  private readonly options: Required<EmailValidatorOptions>;
  private readonly syncFactories = new Map<SyncRule, SyncStrategyFactory>();
  private readonly asyncFactories = new Map<AsyncRule, AsyncStrategyFactory>();

  constructor(
    options: EmailValidatorOptions = {},
    dependencies: EmailValidatorDependencies = {}
  ) {
    this.options = {
      rules: options.rules ?? ["rfc"],
      dnsTimeout: options.dnsTimeout ?? 5000,
      dnsServers: options.dnsServers ?? [],
      allowReservedDomains: options.allowReservedDomains ?? false,
    };

    this.registerDefaultStrategies();
    this.registerCustomStrategies(dependencies);
  }

  // ---------------------------------------------------------------------------
  // Validación síncrona (sin DNS)
  // ---------------------------------------------------------------------------

  /**
   * Valida un email de forma síncrona.
   * Las reglas `dns` son ignoradas en la validación síncrona.
   *
   * @param email - Dirección de email a validar
   * @param rules - Reglas a aplicar (sobreescriben las del constructor)
   */
  validate(email: string, rules?: EmailValidationRule[]): EmailValidationResult {
    const appliedRules = rules ?? this.options.rules;
    const errors: EmailValidationError[] = [];
    const warnings: EmailValidationWarning[] = [];

    // Parsear el email para obtener sus partes
    const parseResult = parseEmail(email?.trim() ?? "");
    const parts: EmailParts | null = parseResult.success ? parseResult.parts : null;

    // Aplicar cada regla síncrona
    for (const rule of appliedRules) {
      if (rule === "dns") {
        // DNS requiere validación asíncrona; ignorar en modo síncrono
        continue;
      }

      const validator = this.createSyncValidator(rule);
      if (!validator) continue;

      const error = validator.validate(email, parts);
      if (error) {
        errors.push(error);
        // Detener en el primer error (comportamiento de Laravel)
        break;
      }
    }

    return {
      valid: errors.length === 0,
      email,
      errors,
      warnings,
      appliedRules: appliedRules.filter((r) => r !== "dns"),
      parts: parts ?? undefined,
    };
  }

  // ---------------------------------------------------------------------------
  // Validación asíncrona (con DNS)
  // ---------------------------------------------------------------------------

  /**
   * Valida un email de forma asíncrona, incluyendo consultas DNS.
   *
   * @param email - Dirección de email a validar
   * @param rules - Reglas a aplicar (sobreescriben las del constructor)
   */
  async validateAsync(
    email: string,
    rules?: EmailValidationRule[]
  ): Promise<EmailValidationResult> {
    const appliedRules = rules ?? this.options.rules;
    const errors: EmailValidationError[] = [];
    const warnings: EmailValidationWarning[] = [];

    // Parsear el email para obtener sus partes
    const parseResult = parseEmail(email?.trim() ?? "");
    const parts: EmailParts | null = parseResult.success ? parseResult.parts : null;

    // Aplicar cada regla en orden
    for (const rule of appliedRules) {
      if (rule === "dns") {
        const dnsValidator = this.createAsyncValidator("dns");
        if (!dnsValidator) continue;

        const error = await dnsValidator.validateAsync(email, parts);

        if (error) {
          errors.push(error);
          break;
        }

        // Agregar advertencias DNS
        for (const warning of dnsValidator.getWarnings()) {
          warnings.push(warning);
        }
        continue;
      }

      const validator = this.createSyncValidator(rule);
      if (!validator) continue;

      const error = validator.validate(email, parts);
      if (error) {
        errors.push(error);
        break;
      }
    }

    return {
      valid: errors.length === 0,
      email,
      errors,
      warnings,
      appliedRules,
      parts: parts ?? undefined,
    };
  }

  // ---------------------------------------------------------------------------
  // Factory de validadores síncronos
  // ---------------------------------------------------------------------------

  private createSyncValidator(rule: SyncRule): IEmailValidationStrategy | null {
    const factory = this.syncFactories.get(rule);
    return factory ? factory() : null;
  }

  private createAsyncValidator(rule: AsyncRule): IAsyncEmailValidationStrategy | null {
    const factory = this.asyncFactories.get(rule);
    return factory ? factory() : null;
  }

  private registerDefaultStrategies(): void {
    this.syncFactories.set("rfc", () => new RFCValidator());
    this.syncFactories.set("strict", () => new StrictRFCValidator());
    this.syncFactories.set("spoof", () => new SpoofValidator());
    this.syncFactories.set("filter", () => new FilterValidator());
    this.asyncFactories.set("dns", () => new DNSValidator(this.options.dnsTimeout));
  }

  private registerCustomStrategies(dependencies: EmailValidatorDependencies): void {
    if (dependencies.syncFactories) {
      for (const [rule, factory] of Object.entries(dependencies.syncFactories)) {
        if (factory) {
          this.syncFactories.set(rule as SyncRule, factory);
        }
      }
    }

    if (dependencies.asyncFactories) {
      for (const [rule, factory] of Object.entries(dependencies.asyncFactories)) {
        if (factory) {
          this.asyncFactories.set(rule as AsyncRule, factory);
        }
      }
    }
  }

}
