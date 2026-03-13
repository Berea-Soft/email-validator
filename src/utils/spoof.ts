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

// ---------------------------------------------------------------------------
// Rangos de scripts Unicode relevantes
// ---------------------------------------------------------------------------

/**
 * Rangos de scripts Unicode que pueden ser usados para spoofing.
 * Basado en la especificación Unicode TR39 (Security Considerations).
 */
const SCRIPT_RANGES: Record<string, [number, number][]> = {
  latin: [
    [0x0041, 0x005a], // A-Z
    [0x0061, 0x007a], // a-z
    [0x00c0, 0x00d6], // Latin Extended-A
    [0x00d8, 0x00f6],
    [0x00f8, 0x024f], // Latin Extended-B
  ],
  cyrillic: [
    [0x0400, 0x04ff], // Cyrillic
    [0x0500, 0x052f], // Cyrillic Supplement
  ],
  greek: [
    [0x0370, 0x03ff], // Greek and Coptic
    [0x1f00, 0x1fff], // Greek Extended
  ],
  armenian: [[0x0530, 0x058f]],
  georgian: [[0x10a0, 0x10ff]],
  cherokee: [[0x13a0, 0x13ff]],
  arabic: [[0x0600, 0x06ff]],
  hebrew: [[0x0590, 0x05ff]],
};

/**
 * Caracteres homógrafos conocidos que se parecen visualmente a caracteres ASCII.
 * Mapeados como: carácter_confuso → carácter_ascii_equivalente
 */
const HOMOGRAPH_MAP: Map<string, string> = new Map([
  // Cirílico → Latino
  ["а", "a"], // U+0430 CYRILLIC SMALL LETTER A
  ["е", "e"], // U+0435 CYRILLIC SMALL LETTER IE
  ["о", "o"], // U+043E CYRILLIC SMALL LETTER O
  ["р", "p"], // U+0440 CYRILLIC SMALL LETTER ER
  ["с", "c"], // U+0441 CYRILLIC SMALL LETTER ES
  ["у", "y"], // U+0443 CYRILLIC SMALL LETTER U
  ["х", "x"], // U+0445 CYRILLIC SMALL LETTER HA
  ["А", "A"], // U+0410 CYRILLIC CAPITAL LETTER A
  ["В", "B"], // U+0412 CYRILLIC CAPITAL LETTER VE
  ["Е", "E"], // U+0415 CYRILLIC CAPITAL LETTER IE
  ["К", "K"], // U+041A CYRILLIC CAPITAL LETTER KA
  ["М", "M"], // U+041C CYRILLIC CAPITAL LETTER EM
  ["Н", "H"], // U+041D CYRILLIC CAPITAL LETTER EN
  ["О", "O"], // U+041E CYRILLIC CAPITAL LETTER O
  ["Р", "P"], // U+0420 CYRILLIC CAPITAL LETTER ER
  ["С", "C"], // U+0421 CYRILLIC CAPITAL LETTER ES
  ["Т", "T"], // U+0422 CYRILLIC CAPITAL LETTER TE
  ["Х", "X"], // U+0425 CYRILLIC CAPITAL LETTER HA
  // Griego → Latino
  ["ο", "o"], // U+03BF GREEK SMALL LETTER OMICRON
  ["Ο", "O"], // U+039F GREEK CAPITAL LETTER OMICRON
  ["α", "a"], // U+03B1 GREEK SMALL LETTER ALPHA
  ["ν", "v"], // U+03BD GREEK SMALL LETTER NU
  // Caracteres especiales similares a ASCII
  ["ℓ", "l"], // U+2113 SCRIPT SMALL L
  ["℮", "e"], // U+212E ESTIMATED SIGN
  ["ℯ", "e"], // U+212F SCRIPT SMALL E
  ["ℰ", "E"], // U+2130 SCRIPT CAPITAL E
  ["ℱ", "F"], // U+2131 SCRIPT CAPITAL F
  ["ℳ", "M"], // U+2133 SCRIPT CAPITAL M
  ["ℴ", "o"], // U+2134 SCRIPT SMALL O
  // Dígitos de ancho completo (Fullwidth)
  ["０", "0"],
  ["１", "1"],
  ["２", "2"],
  ["３", "3"],
  ["４", "4"],
  ["５", "5"],
  ["６", "6"],
  ["７", "7"],
  ["８", "8"],
  ["９", "9"],
  // Letras de ancho completo
  ["ａ", "a"],
  ["ｂ", "b"],
  ["ｃ", "c"],
  ["ｄ", "d"],
  ["ｅ", "e"],
  ["ｆ", "f"],
  ["ｇ", "g"],
  ["ｈ", "h"],
  ["ｉ", "i"],
  ["ｊ", "j"],
  ["ｋ", "k"],
  ["ｌ", "l"],
  ["ｍ", "m"],
  ["ｎ", "n"],
  ["ｏ", "o"],
  ["ｐ", "p"],
  ["ｑ", "q"],
  ["ｒ", "r"],
  ["ｓ", "s"],
  ["ｔ", "t"],
  ["ｕ", "u"],
  ["ｖ", "v"],
  ["ｗ", "w"],
  ["ｘ", "x"],
  ["ｙ", "y"],
  ["ｚ", "z"],
]);

// ---------------------------------------------------------------------------
// Funciones de detección
// ---------------------------------------------------------------------------

/**
 * Resultado del análisis de spoofing
 */
export interface SpoofAnalysisResult {
  /** Indica si se detectó spoofing */
  isSpoofed: boolean;
  /** Descripción del tipo de spoofing detectado */
  reason?: string;
}

/**
 * Analiza un email en busca de caracteres de spoofing.
 *
 * @param email - Dirección de email a analizar
 * @returns Resultado del análisis
 */
export function analyzeSpoofing(email: string): SpoofAnalysisResult {
  // 1. Verificar caracteres homógrafos directos
  const homographResult = detectHomographs(email);
  if (homographResult.isSpoofed) {
    return homographResult;
  }

  // 2. Verificar mezcla de scripts en el dominio
  const atIndex = email.lastIndexOf("@");
  if (atIndex !== -1) {
    const domain = email.slice(atIndex + 1);
    const mixedScriptResult = detectMixedScripts(domain);
    if (mixedScriptResult.isSpoofed) {
      return mixedScriptResult;
    }
  }

  // 3. Verificar normalización Unicode (detecta caracteres compuestos engañosos)
  const normResult = detectUnicodeNormalizationIssues(email);
  if (normResult.isSpoofed) {
    return normResult;
  }

  return { isSpoofed: false };
}

/**
 * Detecta caracteres homógrafos en el email.
 */
function detectHomographs(text: string): SpoofAnalysisResult {
  for (const char of text) {
    if (HOMOGRAPH_MAP.has(char)) {
      return {
        isSpoofed: true,
        reason: `Carácter homógrafo detectado: '${char}' (U+${char
          .codePointAt(0)
          ?.toString(16)
          .toUpperCase()
          .padStart(4, "0")}) que se parece a '${HOMOGRAPH_MAP.get(char)}'`,
      };
    }
  }
  return { isSpoofed: false };
}

/**
 * Detecta mezcla de scripts Unicode en un texto (p.ej. Latin + Cyrillic).
 */
function detectMixedScripts(text: string): SpoofAnalysisResult {
  const detectedScripts = new Set<string>();

  for (const char of text) {
    // Ignorar caracteres ASCII básicos y puntuación
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x0080) continue;
    if (char === "." || char === "-" || char === "_") continue;

    const script = getCharScript(code);
    if (script) {
      detectedScripts.add(script);
    }
  }

  // Si hay más de un script no-ASCII, es sospechoso
  if (detectedScripts.size > 1) {
    return {
      isSpoofed: true,
      reason: `Mezcla de scripts Unicode detectada: ${Array.from(detectedScripts).join(", ")}`,
    };
  }

  return { isSpoofed: false };
}

/**
 * Detecta problemas de normalización Unicode que podrían usarse para spoofing.
 */
function detectUnicodeNormalizationIssues(text: string): SpoofAnalysisResult {
  // Comparar NFC vs NFKC: si difieren, hay caracteres de compatibilidad
  const nfc = text.normalize("NFC");
  const nfkc = text.normalize("NFKC");

  if (nfc !== nfkc) {
    return {
      isSpoofed: true,
      reason:
        "El email contiene caracteres Unicode de compatibilidad que pueden usarse para spoofing",
    };
  }

  // Detectar caracteres de control o formato invisibles
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    // Caracteres de control Unicode (excepto ASCII básico)
    if (
      (code >= 0x200b && code <= 0x200f) || // Zero-width spaces
      (code >= 0x202a && code <= 0x202e) || // Directional formatting
      code === 0xfeff || // BOM
      (code >= 0x2060 && code <= 0x2064) // Word joiner, etc.
    ) {
      return {
        isSpoofed: true,
        reason: `Carácter de control Unicode invisible detectado: U+${code
          .toString(16)
          .toUpperCase()
          .padStart(4, "0")}`,
      };
    }
  }

  return { isSpoofed: false };
}

/**
 * Determina el script Unicode de un punto de código.
 */
function getCharScript(codePoint: number): string | null {
  for (const [script, ranges] of Object.entries(SCRIPT_RANGES)) {
    for (const [start, end] of ranges) {
      if (codePoint >= start && codePoint <= end) {
        return script;
      }
    }
  }
  return null;
}
