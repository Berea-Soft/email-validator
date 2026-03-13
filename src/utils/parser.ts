/**
 * Parser de direcciones de email conforme a RFC 5321 / RFC 5322.
 *
 * Implementa la descomposición de una dirección en sus partes (local y dominio)
 * con soporte para:
 *   - Partes locales entre comillas ("quoted strings")
 *   - Literales de IP como dominio ([192.168.1.1], [IPv6:::1])
 *   - Detección de caracteres especiales y restricciones RFC
 */

import type { EmailParts } from "../types/index.js";

// ---------------------------------------------------------------------------
// Constantes RFC
// ---------------------------------------------------------------------------

/** Longitud máxima total de una dirección de email (RFC 5321 §4.5.3.1.3) */
export const MAX_EMAIL_LENGTH = 254;

/** Longitud máxima de la parte local (RFC 5321 §4.5.3.1.1) */
export const MAX_LOCAL_PART_LENGTH = 64;

/** Longitud máxima del dominio (RFC 5321 §4.5.3.1.2) */
export const MAX_DOMAIN_LENGTH = 255;

/** Longitud máxima de una etiqueta de dominio */
export const MAX_LABEL_LENGTH = 63;

/**
 * Caracteres especiales que requieren comillas en la parte local
 * según RFC 5321 §4.1.2
 */
export const SPECIAL_CHARS = new Set([
  "(",
  ")",
  "<",
  ">",
  "[",
  "]",
  ":",
  ";",
  "@",
  "\\",
  ",",
  '"',
]);

/**
 * Caracteres permitidos en una parte local sin comillas (atext)
 * según RFC 5321 §4.1.2 y RFC 5322 §3.2.3
 */
const ATEXT_REGEX = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+$/;

/**
 * Caracteres permitidos dentro de una cadena entre comillas
 * (qtext) según RFC 5322 §3.2.4
 */
const QTEXT_REGEX = /^[\x20-\x7E]*$/;

// ---------------------------------------------------------------------------
// Resultado del parser
// ---------------------------------------------------------------------------

export interface ParseResult {
  success: boolean;
  parts: EmailParts | null;
  error?: string;
}

// ---------------------------------------------------------------------------
// Funciones de parsing
// ---------------------------------------------------------------------------

/**
 * Descompone una dirección de email en sus partes constituyentes.
 *
 * @param email - Dirección de email a parsear
 * @returns Resultado con las partes o un error descriptivo
 */
export function parseEmail(email: string): ParseResult {
  if (!email || typeof email !== "string") {
    return { success: false, parts: null, error: "El email no puede estar vacío" };
  }

  const trimmed = email.trim();

  if (trimmed.length === 0) {
    return { success: false, parts: null, error: "El email no puede estar vacío" };
  }

  if (trimmed.length > MAX_EMAIL_LENGTH) {
    return {
      success: false,
      parts: null,
      error: `El email excede la longitud máxima de ${MAX_EMAIL_LENGTH} caracteres`,
    };
  }

  // Buscar el último '@' para separar local y dominio
  const lastAtIndex = trimmed.lastIndexOf("@");

  if (lastAtIndex === -1) {
    return { success: false, parts: null, error: "Falta el símbolo '@'" };
  }

  if (lastAtIndex === 0) {
    return { success: false, parts: null, error: "La parte local no puede estar vacía" };
  }

  const local = trimmed.slice(0, lastAtIndex);
  const domain = trimmed.slice(lastAtIndex + 1);

  if (domain.length === 0) {
    return { success: false, parts: null, error: "El dominio no puede estar vacío" };
  }

  // Validar parte local
  const localResult = parseLocalPart(local);
  if (!localResult.success) {
    return { success: false, parts: null, error: localResult.error };
  }

  // Validar dominio
  const domainResult = parseDomain(domain);
  if (!domainResult.success) {
    return { success: false, parts: null, error: domainResult.error };
  }

  return {
    success: true,
    parts: {
      local,
      domain,
      isQuoted: localResult.isQuoted ?? false,
      isIPLiteral: domainResult.isIPLiteral ?? false,
    },
  };
}

// ---------------------------------------------------------------------------
// Parsing de la parte local
// ---------------------------------------------------------------------------

interface LocalPartResult {
  success: boolean;
  isQuoted?: boolean;
  error?: string;
}

function parseLocalPart(local: string): LocalPartResult {
  if (local.length === 0) {
    return { success: false, error: "La parte local no puede estar vacía" };
  }

  if (local.length > MAX_LOCAL_PART_LENGTH) {
    return {
      success: false,
      error: `La parte local excede ${MAX_LOCAL_PART_LENGTH} caracteres`,
    };
  }

  // Parte local entre comillas: "contenido"
  if (local.startsWith('"') && local.endsWith('"')) {
    return parseQuotedLocalPart(local);
  }

  // Parte local sin comillas: dot-atom
  return parseDotAtomLocalPart(local);
}

function parseQuotedLocalPart(local: string): LocalPartResult {
  // Extraer el contenido sin las comillas externas
  const inner = local.slice(1, -1);

  // Verificar que el contenido sea válido (qtext o pares de escape)
  let i = 0;
  while (i < inner.length) {
    const char = inner[i];

    if (char === "\\") {
      // Par de escape: \\ o \"
      if (i + 1 >= inner.length) {
        return { success: false, error: "Secuencia de escape incompleta en parte local entre comillas" };
      }
      const next = inner.charCodeAt(i + 1);
      if (next < 0x20 || next > 0x7e) {
        return { success: false, error: "Carácter de escape inválido en parte local entre comillas" };
      }
      i += 2;
      continue;
    }

    const code = char.charCodeAt(0);
    // qtext: cualquier carácter imprimible ASCII excepto \ y "
    if (code < 0x20 || code > 0x7e || char === '"') {
      return {
        success: false,
        error: `Carácter inválido '${char}' en parte local entre comillas`,
      };
    }

    i++;
  }

  return { success: true, isQuoted: true };
}

function parseDotAtomLocalPart(local: string): LocalPartResult {
  // No puede comenzar ni terminar con punto
  if (local.startsWith(".")) {
    return { success: false, error: "La parte local no puede comenzar con un punto" };
  }

  if (local.endsWith(".")) {
    return { success: false, error: "La parte local no puede terminar con un punto" };
  }

  // No puede tener puntos consecutivos
  if (local.includes("..")) {
    return { success: false, error: "La parte local no puede contener puntos consecutivos" };
  }

  // Verificar cada átomo entre puntos
  const atoms = local.split(".");
  for (const atom of atoms) {
    if (atom.length === 0) {
      return { success: false, error: "La parte local contiene un átomo vacío" };
    }

    if (!ATEXT_REGEX.test(atom)) {
      return {
        success: false,
        error: `La parte local contiene caracteres inválidos: '${atom}'`,
      };
    }
  }

  return { success: true, isQuoted: false };
}

// ---------------------------------------------------------------------------
// Parsing del dominio
// ---------------------------------------------------------------------------

interface DomainResult {
  success: boolean;
  isIPLiteral?: boolean;
  error?: string;
}

function parseDomain(domain: string): DomainResult {
  if (domain.length === 0) {
    return { success: false, error: "El dominio no puede estar vacío" };
  }

  if (domain.length > MAX_DOMAIN_LENGTH) {
    return {
      success: false,
      error: `El dominio excede ${MAX_DOMAIN_LENGTH} caracteres`,
    };
  }

  // Literal de IP: [192.168.1.1] o [IPv6:::1]
  if (domain.startsWith("[") && domain.endsWith("]")) {
    return parseIPLiteralDomain(domain);
  }

  // Dominio estándar: dot-atom
  return parseDotAtomDomain(domain);
}

function parseIPLiteralDomain(domain: string): DomainResult {
  const inner = domain.slice(1, -1);

  if (inner.startsWith("IPv6:")) {
    const ipv6 = inner.slice(5);
    if (!isValidIPv6(ipv6)) {
      return { success: false, error: `Dirección IPv6 inválida: '${ipv6}'` };
    }
    return { success: true, isIPLiteral: true };
  }

  // IPv4
  if (!isValidIPv4(inner)) {
    return { success: false, error: `Dirección IP inválida: '${inner}'` };
  }

  return { success: true, isIPLiteral: true };
}

function parseDotAtomDomain(domain: string): DomainResult {
  // No puede comenzar ni terminar con punto o guion
  if (domain.startsWith(".") || domain.endsWith(".")) {
    return { success: false, error: "El dominio no puede comenzar ni terminar con un punto" };
  }

  if (domain.includes("..")) {
    return { success: false, error: "El dominio no puede contener puntos consecutivos" };
  }

  const labels = domain.split(".");

  if (labels.length < 2) {
    return { success: false, error: "El dominio debe tener al menos una etiqueta y un TLD" };
  }

  for (const label of labels) {
    if (label.length === 0) {
      return { success: false, error: "El dominio contiene una etiqueta vacía" };
    }

    if (label.length > MAX_LABEL_LENGTH) {
      return {
        success: false,
        error: `La etiqueta '${label}' excede ${MAX_LABEL_LENGTH} caracteres`,
      };
    }

    // Las etiquetas pueden contener letras, dígitos y guiones
    // pero no pueden comenzar ni terminar con guion (RFC 1123)
    if (label.startsWith("-") || label.endsWith("-")) {
      return {
        success: false,
        error: `La etiqueta '${label}' no puede comenzar ni terminar con guion`,
      };
    }

    // Soporte para IDN (internationalized domain names) y ASCII estándar
    if (!/^[a-zA-Z0-9\-]+$/.test(label) && !isValidIDNLabel(label)) {
      return {
        success: false,
        error: `La etiqueta '${label}' contiene caracteres inválidos`,
      };
    }
  }

  // El TLD no puede ser solo números
  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) {
    return { success: false, error: `El TLD '${tld}' no puede ser solo números` };
  }

  return { success: true, isIPLiteral: false };
}

// ---------------------------------------------------------------------------
// Helpers de validación de IP
// ---------------------------------------------------------------------------

function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;

  return parts.every((part) => {
    const num = parseInt(part, 10);
    return (
      /^\d+$/.test(part) &&
      !isNaN(num) &&
      num >= 0 &&
      num <= 255 &&
      String(num) === part
    );
  });
}

function isValidIPv6(ip: string): boolean {
  // Validación básica de IPv6
  const ipv6Regex =
    /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:)*::$|^::$/;
  return ipv6Regex.test(ip);
}

function isValidIDNLabel(label: string): boolean {
  // Etiquetas IDN (xn--...) o con caracteres Unicode
  if (label.startsWith("xn--")) {
    return /^xn--[a-zA-Z0-9\-]+$/.test(label);
  }
  // Permitir caracteres Unicode básicos para dominios internacionalizados
  return /^[\p{L}\p{N}\-]+$/u.test(label);
}
