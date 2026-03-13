/**
 * Pruebas unitarias para @bereasoft/email-validator
 *
 * Cubre todos los validadores y la API principal:
 *   - RFCValidator
 *   - StrictRFCValidator
 *   - SpoofValidator
 *   - FilterValidator
 *   - DNSValidator (con mock)
 *   - EmailValidator (clase principal)
 *   - API fluida (email(), isValidEmail(), isValidEmailAsync())
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Importar desde los archivos compilados (dist) o directamente con tsx
import { EmailValidator } from "../src/EmailValidator.js";
import { RFCValidator } from "../src/validators/RFCValidator.js";
import { StrictRFCValidator } from "../src/validators/StrictRFCValidator.js";
import { SpoofValidator } from "../src/validators/SpoofValidator.js";
import { FilterValidator } from "../src/validators/FilterValidator.js";
import { DNSValidator } from "../src/validators/DNSValidator.js";
import { email, isValidEmail, isValidEmailAsync } from "../src/fluent.js";
import { parseEmail } from "../src/utils/parser.js";
import { analyzeSpoofing } from "../src/utils/spoof.js";
import type {
  IAsyncEmailValidationStrategy,
  IEmailValidationStrategy,
} from "../src/types/index.js";

// ---------------------------------------------------------------------------
// Mock del módulo DNS para pruebas sin red
// ---------------------------------------------------------------------------

vi.mock("../src/utils/dns.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/utils/dns.js")>();
  return {
    ...original,
    lookupDNS: vi.fn(async (domain: string) => {
      // Dominios que simulamos como válidos con MX
      const validDomains = [
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "example.com",
        "test-domain.com",
      ];

      // Dominios que simulamos como reservados
      const reservedDomains = ["localhost", "local", "test", "invalid", "example.invalid"];

      // Dominios sin registros DNS
      const noDNSDomains = [
        "notexistingdomain123456.com",
        "thisdoesnotexist99999.org",
      ];

      // Dominios con Null MX
      const nullMXDomains = ["nullmx-domain.com"];

      if (reservedDomains.includes(domain)) {
        return {
          hasRecords: false,
          mxRecords: [],
          hasARecord: false,
          acceptsMail: false,
          warnings: [],
          error: `El dominio '${domain}' es local o reservado`,
        };
      }

      if (noDNSDomains.includes(domain)) {
        return {
          hasRecords: false,
          mxRecords: [],
          hasARecord: false,
          acceptsMail: false,
          warnings: [],
          error: "No se encontraron registros DNS para el dominio",
        };
      }

      if (nullMXDomains.includes(domain)) {
        return {
          hasRecords: true,
          mxRecords: [],
          hasARecord: false,
          acceptsMail: false,
          warnings: [],
          error: "El dominio tiene un registro Null MX (no acepta correo)",
        };
      }

      if (validDomains.includes(domain)) {
        return {
          hasRecords: true,
          mxRecords: [{ exchange: `mail.${domain}`, priority: 10 }],
          hasARecord: false,
          acceptsMail: true,
          warnings: [],
        };
      }

      // Por defecto, simular que el dominio no existe
      return {
        hasRecords: false,
        mxRecords: [],
        hasARecord: false,
        acceptsMail: false,
        warnings: [],
        error: "No se encontraron registros DNS para el dominio",
      };
    }),
  };
});

// ===========================================================================
// Tests del Parser
// ===========================================================================

describe("parseEmail", () => {
  describe("emails válidos", () => {
    it("parsea un email simple correctamente", () => {
      const result = parseEmail("user@example.com");
      expect(result.success).toBe(true);
      expect(result.parts?.local).toBe("user");
      expect(result.parts?.domain).toBe("example.com");
      expect(result.parts?.isQuoted).toBe(false);
      expect(result.parts?.isIPLiteral).toBe(false);
    });

    it("parsea un email con subdominios", () => {
      const result = parseEmail("user@mail.example.co.uk");
      expect(result.success).toBe(true);
      expect(result.parts?.domain).toBe("mail.example.co.uk");
    });

    it("parsea una parte local con puntos", () => {
      const result = parseEmail("first.last@example.com");
      expect(result.success).toBe(true);
      expect(result.parts?.local).toBe("first.last");
    });

    it("parsea una parte local con caracteres especiales permitidos", () => {
      const result = parseEmail("user+tag@example.com");
      expect(result.success).toBe(true);
    });

    it("parsea una parte local entre comillas", () => {
      const result = parseEmail('"user name"@example.com');
      expect(result.success).toBe(true);
      expect(result.parts?.isQuoted).toBe(true);
    });

    it("parsea un email con literal de IP", () => {
      const result = parseEmail("user@[192.168.1.1]");
      expect(result.success).toBe(true);
      expect(result.parts?.isIPLiteral).toBe(true);
    });

    it("parsea un email con literal IPv6", () => {
      const result = parseEmail("user@[IPv6:::1]");
      expect(result.success).toBe(true);
      expect(result.parts?.isIPLiteral).toBe(true);
    });
  });

  describe("emails inválidos", () => {
    it("falla con email vacío", () => {
      expect(parseEmail("").success).toBe(false);
      expect(parseEmail("  ").success).toBe(false);
    });

    it("falla sin símbolo @", () => {
      const result = parseEmail("userexample.com");
      expect(result.success).toBe(false);
    });

    it("falla con parte local vacía", () => {
      const result = parseEmail("@example.com");
      expect(result.success).toBe(false);
    });

    it("falla con dominio vacío", () => {
      const result = parseEmail("user@");
      expect(result.success).toBe(false);
    });

    it("falla con puntos consecutivos en parte local", () => {
      const result = parseEmail("user..name@example.com");
      expect(result.success).toBe(false);
    });

    it("falla con punto al inicio de la parte local", () => {
      const result = parseEmail(".user@example.com");
      expect(result.success).toBe(false);
    });

    it("falla con punto al final de la parte local", () => {
      const result = parseEmail("user.@example.com");
      expect(result.success).toBe(false);
    });

    it("falla con TLD numérico", () => {
      const result = parseEmail("user@example.123");
      expect(result.success).toBe(false);
    });

    it("falla con etiqueta de dominio que empieza con guion", () => {
      const result = parseEmail("user@-example.com");
      expect(result.success).toBe(false);
    });

    it("falla con email demasiado largo", () => {
      const longEmail = "a".repeat(65) + "@example.com";
      const result = parseEmail(longEmail);
      expect(result.success).toBe(false);
    });
  });
});

// ===========================================================================
// Tests del RFCValidator
// ===========================================================================

describe("RFCValidator", () => {
  let validator: RFCValidator;

  beforeEach(() => {
    validator = new RFCValidator();
  });

  it("valida emails RFC válidos", () => {
    const validEmails = [
      "user@example.com",
      "user.name@example.com",
      "user+tag@example.com",
      "user_name@example.co.uk",
      "123@example.com",
      "user@subdomain.example.com",
      '"quoted user"@example.com',
      "user@[192.168.1.1]",
    ];

    for (const emailAddr of validEmails) {
      const parseResult = parseEmail(emailAddr);
      const error = validator.validate(emailAddr, parseResult.parts);
      expect(error).toBeNull();
    }
  });

  it("rechaza emails inválidos", () => {
    const invalidEmails = [
      "",
      "notanemail",
      "@example.com",
      "user@",
      "user..name@example.com",
      ".user@example.com",
      "user.@example.com",
    ];

    for (const emailAddr of invalidEmails) {
      const parseResult = parseEmail(emailAddr);
      const error = validator.validate(emailAddr, parseResult.parts);
      expect(error).not.toBeNull();
    }
  });

  it("retorna el código de error correcto para email vacío", () => {
    const error = validator.validate("", null);
    expect(error?.code).toBe("EMPTY_EMAIL");
  });

  it("retorna el código de error correcto para email sin @", () => {
    const error = validator.validate("notanemail", null);
    expect(error?.code).toBe("MISSING_AT_SIGN");
  });

  it("tiene la regla correcta", () => {
    expect(validator.rule).toBe("rfc");
  });
});

// ===========================================================================
// Tests del StrictRFCValidator
// ===========================================================================

describe("StrictRFCValidator", () => {
  let validator: StrictRFCValidator;

  beforeEach(() => {
    validator = new StrictRFCValidator();
  });

  it("valida emails RFC estrictos válidos", () => {
    const validEmails = [
      "user@example.com",
      "user.name@example.com",
      "user+tag@example.com",
    ];

    for (const emailAddr of validEmails) {
      const parseResult = parseEmail(emailAddr);
      const error = validator.validate(emailAddr, parseResult.parts);
      expect(error).toBeNull();
    }
  });

  it("rechaza partes locales entre comillas", () => {
    const emailAddr = '"quoted user"@example.com';
    const parseResult = parseEmail(emailAddr);
    const error = validator.validate(emailAddr, parseResult.parts);
    expect(error).not.toBeNull();
    expect(error?.code).toBe("INVALID_LOCAL_PART");
    expect(error?.rule).toBe("strict");
  });

  it("rechaza literales de IP como dominio", () => {
    const emailAddr = "user@[192.168.1.1]";
    const parseResult = parseEmail(emailAddr);
    const error = validator.validate(emailAddr, parseResult.parts);
    expect(error).not.toBeNull();
    expect(error?.code).toBe("INVALID_DOMAIN");
  });

  it("tiene la regla correcta", () => {
    expect(validator.rule).toBe("strict");
  });
});

// ===========================================================================
// Tests del SpoofValidator
// ===========================================================================

describe("SpoofValidator", () => {
  let validator: SpoofValidator;

  beforeEach(() => {
    validator = new SpoofValidator();
  });

  it("valida emails sin caracteres de spoofing", () => {
    const validEmails = [
      "user@example.com",
      "admin@gmail.com",
      "test.user@domain.org",
    ];

    for (const emailAddr of validEmails) {
      const error = validator.validate(emailAddr, null);
      expect(error).toBeNull();
    }
  });

  it("detecta caracteres Cirílicos homógrafos", () => {
    // 'а' es U+0430 CYRILLIC SMALL LETTER A, visualmente idéntica a 'a' latina
    const spoofedEmail = "\u0430dmin@example.com"; // аdmin (con 'а' cirílica)
    const error = validator.validate(spoofedEmail, null);
    expect(error).not.toBeNull();
    expect(error?.code).toBe("SPOOF_DETECTED");
  });

  it("detecta caracteres de control Unicode invisibles", () => {
    const emailWithZeroWidth = "user\u200b@example.com"; // Zero-width space
    const error = validator.validate(emailWithZeroWidth, null);
    expect(error).not.toBeNull();
    expect(error?.code).toBe("SPOOF_DETECTED");
  });

  it("tiene la regla correcta", () => {
    expect(validator.rule).toBe("spoof");
  });
});

// ===========================================================================
// Tests del FilterValidator
// ===========================================================================

describe("FilterValidator", () => {
  let validator: FilterValidator;

  beforeEach(() => {
    validator = new FilterValidator();
  });

  it("valida emails con formato filter_var válido", () => {
    const validEmails = [
      "user@example.com",
      "user.name@example.co.uk",
      "user+tag@example.org",
      "user123@subdomain.example.com",
    ];

    for (const emailAddr of validEmails) {
      const error = validator.validate(emailAddr, null);
      expect(error).toBeNull();
    }
  });

  it("rechaza emails inválidos", () => {
    const invalidEmails = [
      "",
      "notanemail",
      "@example.com",
      "user@",
      "user @example.com",
    ];

    for (const emailAddr of invalidEmails) {
      const error = validator.validate(emailAddr, null);
      expect(error).not.toBeNull();
    }
  });

  it("rechaza TLD de un solo carácter", () => {
    const error = validator.validate("user@example.c", null);
    expect(error).not.toBeNull();
  });

  it("tiene la regla correcta", () => {
    expect(validator.rule).toBe("filter");
  });
});

// ===========================================================================
// Tests del DNSValidator (con mock)
// ===========================================================================

describe("DNSValidator", () => {
  let validator: DNSValidator;

  beforeEach(() => {
    validator = new DNSValidator(5000);
  });

  it("valida un dominio con registros MX válidos", async () => {
    const parseResult = parseEmail("user@gmail.com");
    const error = await validator.validateAsync("user@gmail.com", parseResult.parts);
    expect(error).toBeNull();
  });

  it("falla con un dominio sin registros DNS", async () => {
    const parseResult = parseEmail("user@notexistingdomain123456.com");
    const error = await validator.validateAsync(
      "user@notexistingdomain123456.com",
      parseResult.parts
    );
    expect(error).not.toBeNull();
    expect(error?.code).toBe("NO_DNS_RECORD");
  });

  it("falla con un dominio reservado", async () => {
    // user@localhost falla en el parser (sin TLD), por lo que usamos
    // un dominio con TLD reservado que pase el parser pero sea rechazado por DNS
    const parseResult = parseEmail("user@example.invalid");
    // El parser acepta 'example.invalid' (tiene TLD), pero el mock DNS lo rechaza
    // Verificamos que el parser falla con localhost (sin TLD)
    const localhostParse = parseEmail("user@localhost");
    expect(localhostParse.success).toBe(false); // Parser rechaza sin TLD

    // Verificar que el DNSValidator rechaza dominios reservados cuando llega a él
    const error = await validator.validateAsync("user@example.invalid", parseResult.parts);
    expect(error).not.toBeNull();
    // El mock retorna LOCAL_OR_RESERVED_DOMAIN para dominios reservados
    expect(error?.code).toBe("LOCAL_OR_RESERVED_DOMAIN");
  });

  it("falla con un dominio con Null MX", async () => {
    const parseResult = parseEmail("user@nullmx-domain.com");
    const error = await validator.validateAsync(
      "user@nullmx-domain.com",
      parseResult.parts
    );
    expect(error).not.toBeNull();
    expect(error?.code).toBe("DOMAIN_ACCEPTS_NO_MAIL");
  });

  it("falla si el email no tiene partes válidas", async () => {
    const error = await validator.validateAsync("invalid", null);
    expect(error).not.toBeNull();
    expect(error?.code).toBe("INVALID_FORMAT");
  });

  it("no valida literales de IP (los omite)", async () => {
    const parseResult = parseEmail("user@[192.168.1.1]");
    const error = await validator.validateAsync("user@[192.168.1.1]", parseResult.parts);
    expect(error).toBeNull();
  });

  it("tiene la regla correcta", () => {
    expect(validator.rule).toBe("dns");
  });
});

// ===========================================================================
// Tests del EmailValidator (clase principal)
// ===========================================================================

describe("EmailValidator", () => {
  describe("validate() - síncrono", () => {
    it("valida con regla rfc por defecto", () => {
      const validator = new EmailValidator();
      const result = validator.validate("user@example.com");
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.appliedRules).toContain("rfc");
    });

    it("retorna las partes del email si es válido", () => {
      const validator = new EmailValidator({ rules: ["rfc"] });
      const result = validator.validate("user@example.com");
      expect(result.parts?.local).toBe("user");
      expect(result.parts?.domain).toBe("example.com");
    });

    it("retorna errores para emails inválidos", () => {
      const validator = new EmailValidator({ rules: ["rfc"] });
      const result = validator.validate("invalid");
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it("aplica múltiples reglas síncronas", () => {
      const validator = new EmailValidator({ rules: ["rfc", "filter"] });
      const result = validator.validate("user@example.com");
      expect(result.valid).toBe(true);
      expect(result.appliedRules).toContain("rfc");
      expect(result.appliedRules).toContain("filter");
    });

    it("ignora la regla dns en modo síncrono", () => {
      const validator = new EmailValidator({ rules: ["rfc", "dns"] });
      const result = validator.validate("user@example.com");
      // DNS se ignora en modo síncrono
      expect(result.appliedRules).not.toContain("dns");
    });

    it("rechaza email con comillas en modo strict", () => {
      const validator = new EmailValidator({ rules: ["strict"] });
      const result = validator.validate('"user"@example.com');
      expect(result.valid).toBe(false);
    });

    it("rechaza spoofing con regla spoof", () => {
      const validator = new EmailValidator({ rules: ["spoof"] });
      const result = validator.validate("\u0430dmin@example.com");
      expect(result.valid).toBe(false);
      expect(result.errors[0]?.code).toBe("SPOOF_DETECTED");
    });

    it("incluye el email en el resultado", () => {
      const validator = new EmailValidator();
      const result = validator.validate("user@example.com");
      expect(result.email).toBe("user@example.com");
    });
  });

  describe("validateAsync() - asíncrono", () => {
    it("valida con reglas rfc y dns", async () => {
      const validator = new EmailValidator({ rules: ["rfc", "dns"] });
      const result = await validator.validateAsync("user@gmail.com");
      expect(result.valid).toBe(true);
      expect(result.appliedRules).toContain("dns");
    });

    it("falla DNS para dominio inexistente", async () => {
      const validator = new EmailValidator({ rules: ["rfc", "dns"] });
      const result = await validator.validateAsync(
        "user@notexistingdomain123456.com"
      );
      expect(result.valid).toBe(false);
      expect(result.errors[0]?.code).toBe("NO_DNS_RECORD");
    });

    it("falla RFC antes de llegar a DNS", async () => {
      const validator = new EmailValidator({ rules: ["rfc", "dns"] });
      const result = await validator.validateAsync("invalid-email");
      expect(result.valid).toBe(false);
      // El error debe ser de RFC, no de DNS
      expect(result.errors[0]?.rule).toBe("rfc");
    });

    it("valida con todas las reglas combinadas", async () => {
      const validator = new EmailValidator({
        rules: ["rfc", "strict", "dns", "spoof", "filter"],
      });
      const result = await validator.validateAsync("user@gmail.com");
      expect(result.valid).toBe(true);
    });
  });
});

// ===========================================================================
// Tests SOLID (OCP/DIP) del EmailValidator
// ===========================================================================

describe("EmailValidator - SOLID", () => {
  it("permite reemplazar una estrategia por inyección de dependencias (DIP)", () => {
    const customRfc: IEmailValidationStrategy = {
      rule: "rfc",
      validate: () => ({
        code: "INVALID_FORMAT",
        message: "Falla controlada por estrategia inyectada",
        rule: "rfc",
      }),
    };

    const validator = new EmailValidator(
      { rules: ["rfc"] },
      {
        syncFactories: {
          rfc: () => customRfc,
        },
      }
    );

    const result = validator.validate("user@example.com");
    expect(result.valid).toBe(false);
    expect(result.errors[0]?.message).toContain("estrategia inyectada");
  });

  it("detiene la cadena en el primer error y no ejecuta reglas siguientes", () => {
    const firstValidate = vi.fn(() => ({
      code: "INVALID_FORMAT" as const,
      message: "Primer error",
      rule: "rfc" as const,
    }));
    const secondValidate = vi.fn(() => null);

    const validator = new EmailValidator(
      { rules: ["rfc", "filter"] },
      {
        syncFactories: {
          rfc: () => ({ rule: "rfc", validate: firstValidate }),
          filter: () => ({ rule: "filter", validate: secondValidate }),
        },
      }
    );

    const result = validator.validate("user@example.com");

    expect(result.valid).toBe(false);
    expect(firstValidate).toHaveBeenCalledTimes(1);
    expect(secondValidate).not.toHaveBeenCalled();
  });

  it("en modo async no ejecuta DNS si una regla previa falla", async () => {
    const rfcValidate = vi.fn(() => ({
      code: "INVALID_FORMAT" as const,
      message: "RFC inválido",
      rule: "rfc" as const,
    }));
    const dnsValidate = vi.fn(async () => null);

    const dnsStrategy: IAsyncEmailValidationStrategy = {
      rule: "dns",
      validateAsync: dnsValidate,
      getWarnings: () => [],
    };

    const validator = new EmailValidator(
      { rules: ["rfc", "dns"] },
      {
        syncFactories: {
          rfc: () => ({ rule: "rfc", validate: rfcValidate }),
        },
        asyncFactories: {
          dns: () => dnsStrategy,
        },
      }
    );

    const result = await validator.validateAsync("bad-email");

    expect(result.valid).toBe(false);
    expect(rfcValidate).toHaveBeenCalledTimes(1);
    expect(dnsValidate).not.toHaveBeenCalled();
  });
});

// ===========================================================================
// Escenarios BDD (Given/When/Then)
// ===========================================================================

describe("BDD Scenarios", () => {
  it("Given un email bien formado, When aplico rfc+filter, Then el resultado es válido", () => {
    const validator = new EmailValidator({ rules: ["rfc", "filter"] });
    const result = validator.validate("user@example.com");

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.appliedRules).toEqual(["rfc", "filter"]);
  });

  it("Given un email mal formado, When aplico rfc+dns en async, Then falla por RFC antes de DNS", async () => {
    const dnsValidate = vi.fn(async () => null);

    const validator = new EmailValidator(
      { rules: ["rfc", "dns"] },
      {
        asyncFactories: {
          dns: () => ({
            rule: "dns",
            validateAsync: dnsValidate,
            getWarnings: () => [],
          }),
        },
      }
    );

    const result = await validator.validateAsync("invalid-email");

    expect(result.valid).toBe(false);
    expect(result.errors[0]?.rule).toBe("rfc");
    expect(dnsValidate).not.toHaveBeenCalled();
  });

  it("Given un dominio inexistente, When aplico rfc+dns, Then retorna NO_DNS_RECORD", async () => {
    const validator = new EmailValidator({ rules: ["rfc", "dns"] });

    const result = await validator.validateAsync("user@notexistingdomain123456.com");

    expect(result.valid).toBe(false);
    expect(result.errors[0]?.code).toBe("NO_DNS_RECORD");
  });
});

// ===========================================================================
// Tests de la API Fluida
// ===========================================================================

describe("API Fluida - email()", () => {
  it("crea un builder con rfcCompliant()", () => {
    const builder = email().rfcCompliant();
    expect(builder.getRules()).toContain("rfc");
  });

  it("crea un builder con rfcCompliant({ strict: true })", () => {
    const builder = email().rfcCompliant({ strict: true });
    expect(builder.getRules()).toContain("strict");
  });

  it("crea un builder con validateMxRecord()", () => {
    const builder = email().validateMxRecord();
    expect(builder.getRules()).toContain("dns");
  });

  it("crea un builder con preventSpoofing()", () => {
    const builder = email().preventSpoofing();
    expect(builder.getRules()).toContain("spoof");
  });

  it("encadena múltiples reglas", () => {
    const builder = email()
      .rfcCompliant()
      .validateMxRecord()
      .preventSpoofing()
      .filterValidation();

    expect(builder.getRules()).toEqual(["rfc", "dns", "spoof", "filter"]);
  });

  it("validate() síncrono funciona correctamente", () => {
    const result = email().rfcCompliant().validate("user@example.com");
    expect(result.valid).toBe(true);
  });

  it("validateAsync() con DNS funciona correctamente", async () => {
    const result = await email()
      .rfcCompliant()
      .validateMxRecord()
      .validateAsync("user@gmail.com");

    expect(result.valid).toBe(true);
  });

  it("validateAsync() falla para dominio inválido", async () => {
    const result = await email()
      .rfcCompliant()
      .validateMxRecord()
      .validateAsync("user@notexistingdomain123456.com");

    expect(result.valid).toBe(false);
  });
});

// ===========================================================================
// Tests de isValidEmail() y isValidEmailAsync()
// ===========================================================================

describe("isValidEmail()", () => {
  it("retorna true para emails válidos", () => {
    expect(isValidEmail("user@example.com")).toBe(true);
    expect(isValidEmail("user.name@example.co.uk")).toBe(true);
    expect(isValidEmail("user+tag@example.org")).toBe(true);
  });

  it("retorna false para emails inválidos", () => {
    expect(isValidEmail("")).toBe(false);
    expect(isValidEmail("notanemail")).toBe(false);
    expect(isValidEmail("@example.com")).toBe(false);
    expect(isValidEmail("user@")).toBe(false);
  });

  it("acepta reglas personalizadas", () => {
    // Con regla strict, rechaza comillas
    expect(isValidEmail('"user"@example.com', ["strict"])).toBe(false);
    // Con regla rfc, acepta comillas
    expect(isValidEmail('"user"@example.com', ["rfc"])).toBe(true);
  });
});

describe("isValidEmailAsync()", () => {
  it("retorna true para emails con DNS válido", async () => {
    const result = await isValidEmailAsync("user@gmail.com", ["rfc", "dns"]);
    expect(result).toBe(true);
  });

  it("retorna false para emails con DNS inválido", async () => {
    const result = await isValidEmailAsync(
      "user@notexistingdomain123456.com",
      ["rfc", "dns"]
    );
    expect(result).toBe(false);
  });
});

// ===========================================================================
// Tests de analyzeSpoofing()
// ===========================================================================

describe("analyzeSpoofing()", () => {
  it("no detecta spoofing en emails normales", () => {
    const result = analyzeSpoofing("user@example.com");
    expect(result.isSpoofed).toBe(false);
  });

  it("detecta caracteres Cirílicos homógrafos", () => {
    const result = analyzeSpoofing("\u0430dmin@example.com"); // а = Cirílica
    expect(result.isSpoofed).toBe(true);
    expect(result.reason).toContain("homógrafo");
  });

  it("detecta zero-width spaces", () => {
    const result = analyzeSpoofing("user\u200b@example.com");
    expect(result.isSpoofed).toBe(true);
  });

  it("detecta diferencias NFC vs NFKC", () => {
    // Caracteres de compatibilidad Unicode
    const result = analyzeSpoofing("user\ufb01@example.com"); // ﬁ (fi ligature)
    expect(result.isSpoofed).toBe(true);
  });
});

// ===========================================================================
// Tests de casos de borde y escenarios reales
// ===========================================================================

describe("Casos de borde y escenarios reales", () => {
  it("acepta emails con TLDs largos (.museum, .photography)", () => {
    const validator = new EmailValidator({ rules: ["rfc"] });
    expect(validator.validate("user@example.museum").valid).toBe(true);
    expect(validator.validate("user@example.photography").valid).toBe(true);
  });

  it("acepta emails con números en el dominio", () => {
    const validator = new EmailValidator({ rules: ["rfc"] });
    expect(validator.validate("user@123domain.com").valid).toBe(true);
  });

  it("rechaza emails con espacios sin comillas", () => {
    const validator = new EmailValidator({ rules: ["rfc"] });
    expect(validator.validate("user name@example.com").valid).toBe(false);
  });

  it("acepta el email más largo posible válido", () => {
    // 64 caracteres en parte local + @ + dominio corto
    const longLocal = "a".repeat(64);
    const validator = new EmailValidator({ rules: ["rfc"] });
    expect(validator.validate(`${longLocal}@example.com`).valid).toBe(true);
  });

  it("rechaza parte local de 65 caracteres", () => {
    const tooLongLocal = "a".repeat(65);
    const validator = new EmailValidator({ rules: ["rfc"] });
    expect(validator.validate(`${tooLongLocal}@example.com`).valid).toBe(false);
  });

  it("maneja correctamente el email con múltiples puntos en dominio", () => {
    const validator = new EmailValidator({ rules: ["rfc"] });
    expect(validator.validate("user@a.b.c.d.example.com").valid).toBe(true);
  });

  it("el resultado siempre incluye el email original", () => {
    const validator = new EmailValidator();
    const testEmail = "test@example.com";
    const result = validator.validate(testEmail);
    expect(result.email).toBe(testEmail);
  });

  it("combina rfc + filter correctamente", () => {
    const validator = new EmailValidator({ rules: ["rfc", "filter"] });
    // Válido para ambas reglas
    expect(validator.validate("user@example.com").valid).toBe(true);
    // Inválido para ambas
    expect(validator.validate("invalid").valid).toBe(false);
  });
});
