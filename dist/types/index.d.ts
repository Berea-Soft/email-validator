/**
 * Analiza un email en busca de caracteres de spoofing.
 *
 * @param email - Dirección de email a analizar
 * @returns Resultado del análisis
 */
export declare function analyzeSpoofing(email: string): SpoofAnalysisResult;

declare type AsyncRule = Extract<EmailValidationRule, "dns">;

declare type AsyncStrategyFactory = () => IAsyncEmailValidationStrategy;

declare interface DNSLookupResult {
    /** Indica si el dominio tiene registros válidos */
    hasRecords: boolean;
    /** Registros MX encontrados */
    mxRecords: MXRecord[];
    /** Indica si hay registros A o AAAA (fallback cuando no hay MX) */
    hasARecord: boolean;
    /** Indica si el dominio acepta correo (no es Null MX) */
    acceptsMail: boolean;
    /** Advertencias (p.ej. sin MX pero con A record) */
    warnings: string[];
    /** Error si la consulta falló */
    error?: string;
}

export declare class DNSValidator implements IAsyncEmailValidationStrategy {
    readonly rule: "dns";
    private _warnings;
    private timeoutMs;
    constructor(timeoutMs?: number);
    getWarnings(): EmailValidationWarning[];
    validateAsync(email: string, parts: EmailParts | null): Promise<EmailValidationError | null>;
}

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
export declare function email(): EmailValidationBuilder;

/** Partes descompuestas de un email */
export declare interface EmailParts {
    /** Parte local (antes del @) */
    local: string;
    /** Dominio (después del @) */
    domain: string;
    /** Indica si la parte local está entre comillas */
    isQuoted: boolean;
    /** Indica si el dominio es un literal IP */
    isIPLiteral: boolean;
}

export declare class EmailValidationBuilder {
    private rules;
    private options;
    /**
     * Agrega validación RFC 5321/5322.
     * Equivalente a `email:rfc` en Laravel.
     *
     * @param options.strict - Si es `true`, equivale a `email:strict` (NoRFCWarningsValidation)
     */
    rfcCompliant(options?: {
        strict?: boolean;
    }): this;
    /**
     * Agrega validación de registro MX en DNS.
     * Equivalente a `email:dns` en Laravel.
     *
     * @param timeoutMs - Tiempo máximo de espera para la consulta DNS
     */
    validateMxRecord(timeoutMs?: number): this;
    /**
     * Agrega validación anti-spoofing Unicode.
     * Equivalente a `email:spoof` en Laravel.
     */
    preventSpoofing(): this;
    /**
     * Agrega validación tipo filter_var de PHP.
     * Equivalente a `email:filter` en Laravel.
     */
    filterValidation(): this;
    /**
     * Configura opciones adicionales del validador.
     */
    withOptions(options: Omit<EmailValidatorOptions, "rules">): this;
    /**
     * Ejecuta la validación de forma síncrona (sin DNS).
     * Las reglas `dns` son ignoradas.
     */
    validate(emailAddress: string): EmailValidationResult;
    /**
     * Ejecuta la validación de forma asíncrona (con soporte DNS).
     */
    validateAsync(emailAddress: string): Promise<EmailValidationResult>;
    /**
     * Retorna las reglas configuradas actualmente.
     */
    getRules(): EmailValidationRule[];
}

/** Representa un error de validación */
export declare interface EmailValidationError {
    /** Código de error identificador */
    code: EmailValidationErrorCode;
    /** Mensaje descriptivo del error */
    message: string;
    /** Regla que produjo el error */
    rule: EmailValidationRule | "syntax";
}

/** Código de error de validación */
export declare type EmailValidationErrorCode = "INVALID_FORMAT" | "INVALID_LOCAL_PART" | "INVALID_DOMAIN" | "CONSECUTIVE_DOTS" | "LEADING_DOT" | "TRAILING_DOT" | "MISSING_AT_SIGN" | "MULTIPLE_AT_SIGNS" | "EMPTY_EMAIL" | "EMAIL_TOO_LONG" | "LOCAL_PART_TOO_LONG" | "DOMAIN_TOO_LONG" | "LABEL_TOO_LONG" | "INVALID_CHARACTERS" | "NO_DNS_RECORD" | "NO_MX_RECORD" | "LOCAL_OR_RESERVED_DOMAIN" | "DOMAIN_ACCEPTS_NO_MAIL" | "SPOOF_DETECTED" | "DNS_LOOKUP_FAILED";

/** Resultado completo de la validación de un email */
export declare interface EmailValidationResult {
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

/**
 * Tipos principales de la librería de validación de emails.
 * Inspirados en el sistema de validación de Laravel (egulias/email-validator).
 */
/**
 * Reglas de validación disponibles, equivalentes a las de Laravel:
 *
 * - `rfc`    → Valida según RFC 5321/5322 (RFCValidation)
 * - `strict` → RFC estricto, falla ante warnings (NoRFCWarningsValidation)
 * - `dns`    → Verifica registros MX/A/AAAA en DNS (DNSCheckValidation)
 * - `spoof`  → Detecta caracteres Unicode homógrafos (SpoofCheckValidation)
 * - `filter` → Validación básica equivalente a filter_var de PHP
 */
export declare type EmailValidationRule = "rfc" | "strict" | "dns" | "spoof" | "filter";

/** Representa una advertencia de validación (no bloquea la validez) */
export declare interface EmailValidationWarning {
    /** Código de advertencia */
    code: EmailValidationWarningCode;
    /** Mensaje descriptivo */
    message: string;
}

/** Código de advertencia de validación */
export declare type EmailValidationWarningCode = "NO_MX_RECORD_FALLBACK" | "DEPRECATED_COMMENT" | "QUOTED_STRING" | "UNICODE_IN_LOCAL_PART";

export declare class EmailValidator implements IEmailValidator {
    private readonly options;
    private readonly syncFactories;
    private readonly asyncFactories;
    constructor(options?: EmailValidatorOptions, dependencies?: EmailValidatorDependencies);
    /**
     * Valida un email de forma síncrona.
     * Las reglas `dns` son ignoradas en la validación síncrona.
     *
     * @param email - Dirección de email a validar
     * @param rules - Reglas a aplicar (sobreescriben las del constructor)
     */
    validate(email: string, rules?: EmailValidationRule[]): EmailValidationResult;
    /**
     * Valida un email de forma asíncrona, incluyendo consultas DNS.
     *
     * @param email - Dirección de email a validar
     * @param rules - Reglas a aplicar (sobreescriben las del constructor)
     */
    validateAsync(email: string, rules?: EmailValidationRule[]): Promise<EmailValidationResult>;
    private createSyncValidator;
    private createAsyncValidator;
    private registerDefaultStrategies;
    private registerCustomStrategies;
}

export declare interface EmailValidatorDependencies {
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

/** Opciones de configuración del validador de email */
export declare interface EmailValidatorOptions {
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

/**
 * Variante del FilterValidator que permite caracteres Unicode.
 * Equivalente a `FilterEmailValidation::unicode()`.
 */
export declare class FilterUnicodeValidator extends FilterValidator {
    constructor();
}

export declare class FilterValidator implements IEmailValidationStrategy {
    readonly rule: "filter";
    private allowUnicode;
    constructor(allowUnicode?: boolean);
    validate(email: string, _parts: EmailParts | null): EmailValidationError | null;
}

/** Interfaz para validadores asíncronos (como DNS) */
export declare interface IAsyncEmailValidationStrategy {
    readonly rule: EmailValidationRule;
    validateAsync(email: string, parts: EmailParts | null): Promise<EmailValidationError | null>;
    getWarnings(): EmailValidationWarning[];
}

/** Interfaz que deben implementar todos los validadores individuales */
export declare interface IEmailValidationStrategy {
    /** Nombre de la regla */
    readonly rule: EmailValidationRule;
    /**
     * Ejecuta la validación sobre el email o sus partes.
     * @returns `null` si es válido, o un `EmailValidationError` si falla.
     */
    validate(email: string, parts: EmailParts | null): EmailValidationError | null;
}

/** Interfaz principal del validador de email */
export declare interface IEmailValidator {
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
    validateAsync(email: string, rules?: EmailValidationRule[]): Promise<EmailValidationResult>;
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
export declare function isValidEmail(emailAddress: string, rules?: EmailValidationRule[]): boolean;

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
export declare function isValidEmailAsync(emailAddress: string, rules?: EmailValidationRule[]): Promise<boolean>;

/**
 * Realiza una consulta DNS para verificar si el dominio acepta correo.
 *
 * Detecta automáticamente el entorno (Node.js vs Browser) y usa el método
 * apropiado de resolución DNS.
 *
 * @param domain - Dominio a consultar (sin el '@')
 * @param timeoutMs - Tiempo máximo de espera en milisegundos
 * @returns Resultado de la consulta DNS
 */
export declare function lookupDNS(domain: string, timeoutMs?: number): Promise<DNSLookupResult>;

/**
 * Utilidades de resolución DNS para validación de emails.
 *
 * Equivalente a `DNSCheckValidation` de egulias/email-validator.
 * Verifica la existencia de registros MX, A y AAAA para el dominio del email.
 *
 * Funciona tanto en Node.js (usando el módulo `dns/promises`) como en
 * entornos browser/edge (usando la API DNS-over-HTTPS de Cloudflare/Google).
 */
declare interface MXRecord {
    exchange: string;
    priority: number;
}

/**
 * Descompone una dirección de email en sus partes constituyentes.
 *
 * @param email - Dirección de email a parsear
 * @returns Resultado con las partes o un error descriptivo
 */
export declare function parseEmail(email: string): ParseResult;

declare interface ParseResult {
    success: boolean;
    parts: EmailParts | null;
    error?: string;
}

/**
 * TLDs y dominios reservados que no deben consultarse en DNS.
 * Equivalente a la lista en DNSCheckValidation.php de egulias.
 */
export declare const RESERVED_DOMAINS: Set<string>;

export declare class RFCValidator implements IEmailValidationStrategy {
    readonly rule: "rfc";
    validate(email: string, _parts: EmailParts | null): EmailValidationError | null;
    private mapParseError;
}

/**
 * Utilidades para detección de spoofing mediante caracteres Unicode homógrafos.
 *
 * Equivalente a la clase `SpoofCheckValidation` de egulias/email-validator,
 * que utiliza la extensión PHP `intl` con `Spoofchecker`.
 *
 * En JavaScript se implementa mediante:
 *   1. Detección de mezcla de scripts (Latin + Cyrillic, etc.)
 *   2. Detección de caracteres homógrafos conocidos
 *   3. Normalización Unicode (NFC/NFKC) para detectar equivalencias engañosas
 */
/**
 * Resultado del análisis de spoofing
 */
declare interface SpoofAnalysisResult {
    /** Indica si se detectó spoofing */
    isSpoofed: boolean;
    /** Descripción del tipo de spoofing detectado */
    reason?: string;
}

export declare class SpoofValidator implements IEmailValidationStrategy {
    readonly rule: "spoof";
    validate(email: string, _parts: EmailParts | null): EmailValidationError | null;
}

export declare class StrictRFCValidator implements IEmailValidationStrategy {
    readonly rule: "strict";
    private rfcValidator;
    validate(email: string, parts: EmailParts | null): EmailValidationError | null;
    /**
     * Detecta la presencia de comentarios en el email.
     * Los comentarios tienen la forma (texto) y pueden aparecer al inicio
     * o al final de la parte local o del dominio.
     */
    private hasComments;
}

declare type SyncRule = Exclude<EmailValidationRule, "dns">;

declare type SyncStrategyFactory = () => IEmailValidationStrategy;

export { }
