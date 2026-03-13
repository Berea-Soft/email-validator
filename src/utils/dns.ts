/**
 * Utilidades de resolución DNS para validación de emails.
 *
 * Equivalente a `DNSCheckValidation` de egulias/email-validator.
 * Verifica la existencia de registros MX, A y AAAA para el dominio del email.
 *
 * Funciona tanto en Node.js (usando el módulo `dns/promises`) como en
 * entornos browser/edge (usando la API DNS-over-HTTPS de Cloudflare/Google).
 */

// ---------------------------------------------------------------------------
// Tipos de registros DNS
// ---------------------------------------------------------------------------

export interface MXRecord {
  exchange: string;
  priority: number;
}

export interface DNSLookupResult {
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

// ---------------------------------------------------------------------------
// Dominios reservados (RFC 2606, RFC 6762 Appendix G)
// ---------------------------------------------------------------------------

/**
 * TLDs y dominios reservados que no deben consultarse en DNS.
 * Equivalente a la lista en DNSCheckValidation.php de egulias.
 */
export const RESERVED_DOMAINS = new Set([
  // RFC 2606 - Reserved Top Level DNS Names
  "test",
  "example",
  "invalid",
  "localhost",
  // mDNS (RFC 6762)
  "local",
  // Private DNS Namespaces (RFC 6762 Appendix G)
  "intranet",
  "internal",
  "private",
  "corp",
  "home",
  "lan",
]);

// ---------------------------------------------------------------------------
// Detección del entorno de ejecución
// ---------------------------------------------------------------------------

function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    process.versions != null &&
    process.versions.node != null
  );
}

// ---------------------------------------------------------------------------
// Resolución DNS en Node.js
// ---------------------------------------------------------------------------

async function lookupDNSNode(
  domain: string,
  timeoutMs: number
): Promise<DNSLookupResult> {
  const { promises: dnsPromises } = await import("dns");

  const warnings: string[] = [];
  const mxRecords: MXRecord[] = [];
  let hasARecord = false;

  // Función auxiliar con timeout
  async function withTimeout<T>(
    promise: Promise<T>,
    ms: number
  ): Promise<T | null> {
    return Promise.race([
      promise,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), ms)),
    ]);
  }

  // 1. Intentar resolver registros MX
  try {
    const mxResult = await withTimeout(
      dnsPromises.resolveMx(domain),
      timeoutMs
    );

    if (mxResult && mxResult.length > 0) {
      for (const record of mxResult) {
        // Null MX: dominio que explícitamente no acepta correo (RFC 7505)
        if (record.exchange === "" || record.exchange === ".") {
          return {
            hasRecords: true,
            mxRecords: [],
            hasARecord: false,
            acceptsMail: false,
            warnings,
            error: "El dominio tiene un registro Null MX (no acepta correo)",
          };
        }

        mxRecords.push({
          exchange: record.exchange,
          priority: record.priority,
        });
      }

      return {
        hasRecords: true,
        mxRecords,
        hasARecord: false,
        acceptsMail: true,
        warnings,
      };
    }
  } catch {
    // No hay registros MX, intentar con A/AAAA
  }

  // 2. Fallback: intentar registros A
  try {
    const aResult = await withTimeout(
      dnsPromises.resolve4(domain),
      timeoutMs
    );
    if (aResult && aResult.length > 0) {
      hasARecord = true;
      warnings.push(
        "El dominio no tiene registros MX; se encontraron registros A (fallback)"
      );
    }
  } catch {
    // No hay registros A
  }

  // 3. Fallback: intentar registros AAAA
  if (!hasARecord) {
    try {
      const aaaaResult = await withTimeout(
        dnsPromises.resolve6(domain),
        timeoutMs
      );
      if (aaaaResult && aaaaResult.length > 0) {
        hasARecord = true;
        warnings.push(
          "El dominio no tiene registros MX; se encontraron registros AAAA (fallback)"
        );
      }
    } catch {
      // No hay registros AAAA
    }
  }

  if (hasARecord) {
    return {
      hasRecords: true,
      mxRecords: [],
      hasARecord: true,
      acceptsMail: true,
      warnings,
    };
  }

  return {
    hasRecords: false,
    mxRecords: [],
    hasARecord: false,
    acceptsMail: false,
    warnings,
    error: "No se encontraron registros DNS (MX, A ni AAAA) para el dominio",
  };
}

// ---------------------------------------------------------------------------
// Resolución DNS en Browser/Edge (DNS-over-HTTPS)
// ---------------------------------------------------------------------------

async function lookupDNSDoH(
  domain: string,
  timeoutMs: number
): Promise<DNSLookupResult> {
  const warnings: string[] = [];
  const mxRecords: MXRecord[] = [];

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // Usar Cloudflare DNS-over-HTTPS (1.1.1.1)
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`;

    const response = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      return {
        hasRecords: false,
        mxRecords: [],
        hasARecord: false,
        acceptsMail: false,
        warnings,
        error: `Error en consulta DNS-over-HTTPS: HTTP ${response.status}`,
      };
    }

    const data = (await response.json()) as {
      Status: number;
      Answer?: Array<{ type: number; data: string; TTL: number }>;
    };

    // NXDOMAIN (3) = dominio no existe
    if (data.Status === 3) {
      return {
        hasRecords: false,
        mxRecords: [],
        hasARecord: false,
        acceptsMail: false,
        warnings,
        error: "El dominio no existe (NXDOMAIN)",
      };
    }

    if (data.Answer && data.Answer.length > 0) {
      for (const record of data.Answer) {
        // Tipo 15 = MX
        if (record.type === 15) {
          const parts = record.data.split(" ");
          const priority = parseInt(parts[0] ?? "10", 10);
          const exchange = parts[1] ?? "";

          // Null MX
          if (exchange === "" || exchange === ".") {
            return {
              hasRecords: true,
              mxRecords: [],
              hasARecord: false,
              acceptsMail: false,
              warnings,
              error: "El dominio tiene un registro Null MX (no acepta correo)",
            };
          }

          mxRecords.push({ exchange, priority });
        }
      }

      if (mxRecords.length > 0) {
        return {
          hasRecords: true,
          mxRecords,
          hasARecord: false,
          acceptsMail: true,
          warnings,
        };
      }
    }

    // Fallback a registros A
    const aUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
    const aResponse = await fetch(aUrl, {
      headers: { Accept: "application/dns-json" },
    });

    if (aResponse.ok) {
      const aData = (await aResponse.json()) as {
        Status: number;
        Answer?: Array<{ type: number; data: string }>;
      };

      if (aData.Answer && aData.Answer.some((r) => r.type === 1)) {
        warnings.push(
          "El dominio no tiene registros MX; se encontraron registros A (fallback)"
        );
        return {
          hasRecords: true,
          mxRecords: [],
          hasARecord: true,
          acceptsMail: true,
          warnings,
        };
      }
    }

    return {
      hasRecords: false,
      mxRecords: [],
      hasARecord: false,
      acceptsMail: false,
      warnings,
      error: "No se encontraron registros DNS para el dominio",
    };
  } catch (err) {
    clearTimeout(timer);

    if (err instanceof Error && err.name === "AbortError") {
      return {
        hasRecords: false,
        mxRecords: [],
        hasARecord: false,
        acceptsMail: false,
        warnings,
        error: `Timeout: la consulta DNS tardó más de ${timeoutMs}ms`,
      };
    }

    return {
      hasRecords: false,
      mxRecords: [],
      hasARecord: false,
      acceptsMail: false,
      warnings,
      error: `Error en la consulta DNS: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Función principal de lookup DNS
// ---------------------------------------------------------------------------

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
export async function lookupDNS(
  domain: string,
  timeoutMs = 5000
): Promise<DNSLookupResult> {
  // Normalizar el dominio (eliminar trailing dot si existe)
  const normalizedDomain = domain.replace(/\.$/, "").toLowerCase();

  // Verificar si es un dominio reservado
  const labels = normalizedDomain.split(".");
  const tld = labels[labels.length - 1] ?? "";

  if (labels.length <= 1 || RESERVED_DOMAINS.has(tld)) {
    return {
      hasRecords: false,
      mxRecords: [],
      hasARecord: false,
      acceptsMail: false,
      warnings: [],
      error: `El dominio '${normalizedDomain}' es local o reservado`,
    };
  }

  if (isNodeEnvironment()) {
    return lookupDNSNode(normalizedDomain, timeoutMs);
  }

  return lookupDNSDoH(normalizedDomain, timeoutMs);
}
