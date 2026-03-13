const _ = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+$/;
function A(r) {
  if (!r || typeof r != "string")
    return { success: !1, parts: null, error: "El email no puede estar vacío" };
  const e = r.trim();
  if (e.length === 0)
    return { success: !1, parts: null, error: "El email no puede estar vacío" };
  if (e.length > 254)
    return {
      success: !1,
      parts: null,
      error: "El email excede la longitud máxima de 254 caracteres"
    };
  const s = e.lastIndexOf("@");
  if (s === -1)
    return { success: !1, parts: null, error: "Falta el símbolo '@'" };
  if (s === 0)
    return { success: !1, parts: null, error: "La parte local no puede estar vacía" };
  const t = e.slice(0, s), n = e.slice(s + 1);
  if (n.length === 0)
    return { success: !1, parts: null, error: "El dominio no puede estar vacío" };
  const o = R(t);
  if (!o.success)
    return { success: !1, parts: null, error: o.error };
  const i = I(n);
  return i.success ? {
    success: !0,
    parts: {
      local: t,
      domain: n,
      isQuoted: o.isQuoted ?? !1,
      isIPLiteral: i.isIPLiteral ?? !1
    }
  } : { success: !1, parts: null, error: i.error };
}
function R(r) {
  return r.length === 0 ? { success: !1, error: "La parte local no puede estar vacía" } : r.length > 64 ? {
    success: !1,
    error: "La parte local excede 64 caracteres"
  } : r.startsWith('"') && r.endsWith('"') ? v(r) : N(r);
}
function v(r) {
  const e = r.slice(1, -1);
  let s = 0;
  for (; s < e.length; ) {
    const t = e[s];
    if (t === "\\") {
      if (s + 1 >= e.length)
        return { success: !1, error: "Secuencia de escape incompleta en parte local entre comillas" };
      const o = e.charCodeAt(s + 1);
      if (o < 32 || o > 126)
        return { success: !1, error: "Carácter de escape inválido en parte local entre comillas" };
      s += 2;
      continue;
    }
    const n = t.charCodeAt(0);
    if (n < 32 || n > 126 || t === '"')
      return {
        success: !1,
        error: `Carácter inválido '${t}' en parte local entre comillas`
      };
    s++;
  }
  return { success: !0, isQuoted: !0 };
}
function N(r) {
  if (r.startsWith("."))
    return { success: !1, error: "La parte local no puede comenzar con un punto" };
  if (r.endsWith("."))
    return { success: !1, error: "La parte local no puede terminar con un punto" };
  if (r.includes(".."))
    return { success: !1, error: "La parte local no puede contener puntos consecutivos" };
  const e = r.split(".");
  for (const s of e) {
    if (s.length === 0)
      return { success: !1, error: "La parte local contiene un átomo vacío" };
    if (!_.test(s))
      return {
        success: !1,
        error: `La parte local contiene caracteres inválidos: '${s}'`
      };
  }
  return { success: !0, isQuoted: !1 };
}
function I(r) {
  return r.length === 0 ? { success: !1, error: "El dominio no puede estar vacío" } : r.length > 255 ? {
    success: !1,
    error: "El dominio excede 255 caracteres"
  } : r.startsWith("[") && r.endsWith("]") ? M(r) : S(r);
}
function M(r) {
  const e = r.slice(1, -1);
  if (e.startsWith("IPv6:")) {
    const s = e.slice(5);
    return O(s) ? { success: !0, isIPLiteral: !0 } : { success: !1, error: `Dirección IPv6 inválida: '${s}'` };
  }
  return T(e) ? { success: !0, isIPLiteral: !0 } : { success: !1, error: `Dirección IP inválida: '${e}'` };
}
function S(r) {
  if (r.startsWith(".") || r.endsWith("."))
    return { success: !1, error: "El dominio no puede comenzar ni terminar con un punto" };
  if (r.includes(".."))
    return { success: !1, error: "El dominio no puede contener puntos consecutivos" };
  const e = r.split(".");
  if (e.length < 2)
    return { success: !1, error: "El dominio debe tener al menos una etiqueta y un TLD" };
  for (const t of e) {
    if (t.length === 0)
      return { success: !1, error: "El dominio contiene una etiqueta vacía" };
    if (t.length > 63)
      return {
        success: !1,
        error: `La etiqueta '${t}' excede 63 caracteres`
      };
    if (t.startsWith("-") || t.endsWith("-"))
      return {
        success: !1,
        error: `La etiqueta '${t}' no puede comenzar ni terminar con guion`
      };
    if (!/^[a-zA-Z0-9\-]+$/.test(t) && !y(t))
      return {
        success: !1,
        error: `La etiqueta '${t}' contiene caracteres inválidos`
      };
  }
  const s = e[e.length - 1];
  return /^\d+$/.test(s) ? { success: !1, error: `El TLD '${s}' no puede ser solo números` } : { success: !0, isIPLiteral: !1 };
}
function T(r) {
  const e = r.split(".");
  return e.length !== 4 ? !1 : e.every((s) => {
    const t = parseInt(s, 10);
    return /^\d+$/.test(s) && !isNaN(t) && t >= 0 && t <= 255 && String(t) === s;
  });
}
function O(r) {
  return /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:)*::$|^::$/.test(r);
}
function y(r) {
  return r.startsWith("xn--") ? /^xn--[a-zA-Z0-9\-]+$/.test(r) : /^[\p{L}\p{N}\-]+$/u.test(r);
}
class E {
  constructor() {
    this.rule = "rfc";
  }
  validate(e, s) {
    if (!e || typeof e != "string")
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "rfc"
      };
    const t = e.trim();
    if (t.length === 0)
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "rfc"
      };
    if (t.length > 254)
      return {
        code: "EMAIL_TOO_LONG",
        message: "El email excede la longitud máxima de 254 caracteres",
        rule: "rfc"
      };
    const n = (t.match(/@/g) ?? []).length;
    if (n === 0)
      return {
        code: "MISSING_AT_SIGN",
        message: "El email debe contener el símbolo '@'",
        rule: "rfc"
      };
    if (n > 1) {
      const i = t.lastIndexOf("@"), a = t.slice(0, i);
      if (!a.startsWith('"') || !a.endsWith('"'))
        return {
          code: "MULTIPLE_AT_SIGNS",
          message: "El email contiene múltiples '@' fuera de una parte local entre comillas",
          rule: "rfc"
        };
    }
    const o = A(t);
    return o.success ? null : this.mapParseError(o.error ?? "Formato inválido");
  }
  mapParseError(e) {
    return e.includes("vacío") ? { code: "EMPTY_EMAIL", message: e, rule: "rfc" } : e.includes("longitud máxima") && e.includes("email") ? { code: "EMAIL_TOO_LONG", message: e, rule: "rfc" } : e.includes("parte local") && e.includes("longitud") ? { code: "LOCAL_PART_TOO_LONG", message: e, rule: "rfc" } : e.includes("dominio") && e.includes("longitud") ? { code: "DOMAIN_TOO_LONG", message: e, rule: "rfc" } : e.includes("etiqueta") && e.includes("longitud") ? { code: "LABEL_TOO_LONG", message: e, rule: "rfc" } : e.includes("'@'") ? { code: "MISSING_AT_SIGN", message: e, rule: "rfc" } : e.includes("punto") && e.includes("comenzar") ? { code: "LEADING_DOT", message: e, rule: "rfc" } : e.includes("punto") && e.includes("terminar") ? { code: "TRAILING_DOT", message: e, rule: "rfc" } : e.includes("puntos consecutivos") ? { code: "CONSECUTIVE_DOTS", message: e, rule: "rfc" } : e.includes("caracteres inválidos") || e.includes("carácter inválido") ? { code: "INVALID_CHARACTERS", message: e, rule: "rfc" } : e.includes("dominio") ? { code: "INVALID_DOMAIN", message: e, rule: "rfc" } : e.includes("parte local") ? { code: "INVALID_LOCAL_PART", message: e, rule: "rfc" } : { code: "INVALID_FORMAT", message: e, rule: "rfc" };
  }
}
class D {
  constructor() {
    this.rule = "strict", this.rfcValidator = new E();
  }
  validate(e, s) {
    const t = this.rfcValidator.validate(e, s);
    return t ? { ...t, rule: "strict" } : s ? s.isQuoted ? {
      code: "INVALID_LOCAL_PART",
      message: "La validación estricta no permite partes locales entre comillas (quoted strings)",
      rule: "strict"
    } : s.isIPLiteral ? {
      code: "INVALID_DOMAIN",
      message: "La validación estricta no permite literales de IP como dominio",
      rule: "strict"
    } : this.hasComments(e) ? {
      code: "INVALID_FORMAT",
      message: "La validación estricta no permite comentarios en la dirección de email",
      rule: "strict"
    } : s.local.startsWith(".") || s.local.endsWith(".") ? {
      code: "LEADING_DOT",
      message: "La validación estricta no permite puntos al inicio o final de la parte local",
      rule: "strict"
    } : s.local.includes("..") ? {
      code: "CONSECUTIVE_DOTS",
      message: "La validación estricta no permite puntos consecutivos en la parte local",
      rule: "strict"
    } : /\s/.test(s.local) ? {
      code: "INVALID_CHARACTERS",
      message: "La validación estricta no permite espacios en la parte local",
      rule: "strict"
    } : null : null;
  }
  /**
   * Detecta la presencia de comentarios en el email.
   * Los comentarios tienen la forma (texto) y pueden aparecer al inicio
   * o al final de la parte local o del dominio.
   */
  hasComments(e) {
    return new RegExp("^\\(.*?\\)|(?<=@)\\(.*?\\)|\\(.*?\\)@|\\(.*?\\)$").test(e);
  }
}
const w = /* @__PURE__ */ new Set([
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
  "lan"
]);
function C() {
  return typeof process < "u" && process.versions != null && process.versions.node != null;
}
async function x(r, e) {
  const { promises: s } = await import("dns"), t = [], n = [];
  let o = !1;
  async function i(a, c) {
    return Promise.race([
      a,
      new Promise((l) => setTimeout(() => l(null), c))
    ]);
  }
  try {
    const a = await i(
      s.resolveMx(r),
      e
    );
    if (a && a.length > 0) {
      for (const c of a) {
        if (c.exchange === "" || c.exchange === ".")
          return {
            hasRecords: !0,
            mxRecords: [],
            hasARecord: !1,
            acceptsMail: !1,
            warnings: t,
            error: "El dominio tiene un registro Null MX (no acepta correo)"
          };
        n.push({
          exchange: c.exchange,
          priority: c.priority
        });
      }
      return {
        hasRecords: !0,
        mxRecords: n,
        hasARecord: !1,
        acceptsMail: !0,
        warnings: t
      };
    }
  } catch {
  }
  try {
    const a = await i(
      s.resolve4(r),
      e
    );
    a && a.length > 0 && (o = !0, t.push(
      "El dominio no tiene registros MX; se encontraron registros A (fallback)"
    ));
  } catch {
  }
  if (!o)
    try {
      const a = await i(
        s.resolve6(r),
        e
      );
      a && a.length > 0 && (o = !0, t.push(
        "El dominio no tiene registros MX; se encontraron registros AAAA (fallback)"
      ));
    } catch {
    }
  return o ? {
    hasRecords: !0,
    mxRecords: [],
    hasARecord: !0,
    acceptsMail: !0,
    warnings: t
  } : {
    hasRecords: !1,
    mxRecords: [],
    hasARecord: !1,
    acceptsMail: !1,
    warnings: t,
    error: "No se encontraron registros DNS (MX, A ni AAAA) para el dominio"
  };
}
async function P(r, e) {
  const s = [], t = [], n = new AbortController(), o = setTimeout(() => n.abort(), e);
  try {
    const i = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(r)}&type=MX`, a = await fetch(i, {
      headers: { Accept: "application/dns-json" },
      signal: n.signal
    });
    if (clearTimeout(o), !a.ok)
      return {
        hasRecords: !1,
        mxRecords: [],
        hasARecord: !1,
        acceptsMail: !1,
        warnings: s,
        error: `Error en consulta DNS-over-HTTPS: HTTP ${a.status}`
      };
    const c = await a.json();
    if (c.Status === 3)
      return {
        hasRecords: !1,
        mxRecords: [],
        hasARecord: !1,
        acceptsMail: !1,
        warnings: s,
        error: "El dominio no existe (NXDOMAIN)"
      };
    if (c.Answer && c.Answer.length > 0) {
      for (const u of c.Answer)
        if (u.type === 15) {
          const f = u.data.split(" "), m = parseInt(f[0] ?? "10", 10), h = f[1] ?? "";
          if (h === "" || h === ".")
            return {
              hasRecords: !0,
              mxRecords: [],
              hasARecord: !1,
              acceptsMail: !1,
              warnings: s,
              error: "El dominio tiene un registro Null MX (no acepta correo)"
            };
          t.push({ exchange: h, priority: m });
        }
      if (t.length > 0)
        return {
          hasRecords: !0,
          mxRecords: t,
          hasARecord: !1,
          acceptsMail: !0,
          warnings: s
        };
    }
    const l = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(r)}&type=A`, d = await fetch(l, {
      headers: { Accept: "application/dns-json" }
    });
    if (d.ok) {
      const u = await d.json();
      if (u.Answer && u.Answer.some((f) => f.type === 1))
        return s.push(
          "El dominio no tiene registros MX; se encontraron registros A (fallback)"
        ), {
          hasRecords: !0,
          mxRecords: [],
          hasARecord: !0,
          acceptsMail: !0,
          warnings: s
        };
    }
    return {
      hasRecords: !1,
      mxRecords: [],
      hasARecord: !1,
      acceptsMail: !1,
      warnings: s,
      error: "No se encontraron registros DNS para el dominio"
    };
  } catch (i) {
    return clearTimeout(o), i instanceof Error && i.name === "AbortError" ? {
      hasRecords: !1,
      mxRecords: [],
      hasARecord: !1,
      acceptsMail: !1,
      warnings: s,
      error: `Timeout: la consulta DNS tardó más de ${e}ms`
    } : {
      hasRecords: !1,
      mxRecords: [],
      hasARecord: !1,
      acceptsMail: !1,
      warnings: s,
      error: `Error en la consulta DNS: ${i instanceof Error ? i.message : String(i)}`
    };
  }
}
async function $(r, e = 5e3) {
  const s = r.replace(/\.$/, "").toLowerCase(), t = s.split("."), n = t[t.length - 1] ?? "";
  return t.length <= 1 || w.has(n) ? {
    hasRecords: !1,
    mxRecords: [],
    hasARecord: !1,
    acceptsMail: !1,
    warnings: [],
    error: `El dominio '${s}' es local o reservado`
  } : C() ? x(s, e) : P(s, e);
}
class F {
  constructor(e = 5e3) {
    this.rule = "dns", this._warnings = [], this.timeoutMs = e;
  }
  getWarnings() {
    return this._warnings;
  }
  async validateAsync(e, s) {
    if (this._warnings = [], !s)
      return {
        code: "INVALID_FORMAT",
        message: "No se puede validar DNS: el email no tiene un formato válido",
        rule: "dns"
      };
    const t = s.domain;
    if (s.isIPLiteral)
      return null;
    const n = await $(t, this.timeoutMs);
    if (n.error?.includes("local o reservado") || n.error?.includes("reservado"))
      return {
        code: "LOCAL_OR_RESERVED_DOMAIN",
        message: n.error,
        rule: "dns"
      };
    if (!n.hasRecords)
      return {
        code: "NO_DNS_RECORD",
        message: n.error ?? `No se encontraron registros DNS para el dominio '${t}'`,
        rule: "dns"
      };
    if (!n.acceptsMail)
      return {
        code: "DOMAIN_ACCEPTS_NO_MAIL",
        message: n.error ?? `El dominio '${t}' tiene un registro Null MX y no acepta correo`,
        rule: "dns"
      };
    n.hasARecord && n.mxRecords.length === 0 && this._warnings.push({
      code: "NO_MX_RECORD_FALLBACK",
      message: `El dominio '${t}' no tiene registros MX; se usaron registros A/AAAA como fallback`
    });
    for (const o of n.warnings)
      this._warnings.push({
        code: "NO_MX_RECORD_FALLBACK",
        message: o
      });
    return null;
  }
}
const V = {
  latin: [
    [65, 90],
    // A-Z
    [97, 122],
    // a-z
    [192, 214],
    // Latin Extended-A
    [216, 246],
    [248, 591]
    // Latin Extended-B
  ],
  cyrillic: [
    [1024, 1279],
    // Cyrillic
    [1280, 1327]
    // Cyrillic Supplement
  ],
  greek: [
    [880, 1023],
    // Greek and Coptic
    [7936, 8191]
    // Greek Extended
  ],
  armenian: [[1328, 1423]],
  georgian: [[4256, 4351]],
  cherokee: [[5024, 5119]],
  arabic: [[1536, 1791]],
  hebrew: [[1424, 1535]]
}, g = /* @__PURE__ */ new Map([
  // Cirílico → Latino
  ["а", "a"],
  // U+0430 CYRILLIC SMALL LETTER A
  ["е", "e"],
  // U+0435 CYRILLIC SMALL LETTER IE
  ["о", "o"],
  // U+043E CYRILLIC SMALL LETTER O
  ["р", "p"],
  // U+0440 CYRILLIC SMALL LETTER ER
  ["с", "c"],
  // U+0441 CYRILLIC SMALL LETTER ES
  ["у", "y"],
  // U+0443 CYRILLIC SMALL LETTER U
  ["х", "x"],
  // U+0445 CYRILLIC SMALL LETTER HA
  ["А", "A"],
  // U+0410 CYRILLIC CAPITAL LETTER A
  ["В", "B"],
  // U+0412 CYRILLIC CAPITAL LETTER VE
  ["Е", "E"],
  // U+0415 CYRILLIC CAPITAL LETTER IE
  ["К", "K"],
  // U+041A CYRILLIC CAPITAL LETTER KA
  ["М", "M"],
  // U+041C CYRILLIC CAPITAL LETTER EM
  ["Н", "H"],
  // U+041D CYRILLIC CAPITAL LETTER EN
  ["О", "O"],
  // U+041E CYRILLIC CAPITAL LETTER O
  ["Р", "P"],
  // U+0420 CYRILLIC CAPITAL LETTER ER
  ["С", "C"],
  // U+0421 CYRILLIC CAPITAL LETTER ES
  ["Т", "T"],
  // U+0422 CYRILLIC CAPITAL LETTER TE
  ["Х", "X"],
  // U+0425 CYRILLIC CAPITAL LETTER HA
  // Griego → Latino
  ["ο", "o"],
  // U+03BF GREEK SMALL LETTER OMICRON
  ["Ο", "O"],
  // U+039F GREEK CAPITAL LETTER OMICRON
  ["α", "a"],
  // U+03B1 GREEK SMALL LETTER ALPHA
  ["ν", "v"],
  // U+03BD GREEK SMALL LETTER NU
  // Caracteres especiales similares a ASCII
  ["ℓ", "l"],
  // U+2113 SCRIPT SMALL L
  ["℮", "e"],
  // U+212E ESTIMATED SIGN
  ["ℯ", "e"],
  // U+212F SCRIPT SMALL E
  ["ℰ", "E"],
  // U+2130 SCRIPT CAPITAL E
  ["ℱ", "F"],
  // U+2131 SCRIPT CAPITAL F
  ["ℳ", "M"],
  // U+2133 SCRIPT CAPITAL M
  ["ℴ", "o"],
  // U+2134 SCRIPT SMALL O
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
  ["ｚ", "z"]
]);
function G(r) {
  const e = X(r);
  if (e.isSpoofed)
    return e;
  const s = r.lastIndexOf("@");
  if (s !== -1) {
    const n = r.slice(s + 1), o = b(n);
    if (o.isSpoofed)
      return o;
  }
  const t = z(r);
  return t.isSpoofed ? t : { isSpoofed: !1 };
}
function X(r) {
  for (const e of r)
    if (g.has(e))
      return {
        isSpoofed: !0,
        reason: `Carácter homógrafo detectado: '${e}' (U+${e.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}) que se parece a '${g.get(e)}'`
      };
  return { isSpoofed: !1 };
}
function b(r) {
  const e = /* @__PURE__ */ new Set();
  for (const s of r) {
    const t = s.codePointAt(0) ?? 0;
    if (t < 128 || s === "." || s === "-" || s === "_") continue;
    const n = H(t);
    n && e.add(n);
  }
  return e.size > 1 ? {
    isSpoofed: !0,
    reason: `Mezcla de scripts Unicode detectada: ${Array.from(e).join(", ")}`
  } : { isSpoofed: !1 };
}
function z(r) {
  const e = r.normalize("NFC"), s = r.normalize("NFKC");
  if (e !== s)
    return {
      isSpoofed: !0,
      reason: "El email contiene caracteres Unicode de compatibilidad que pueden usarse para spoofing"
    };
  for (const t of r) {
    const n = t.codePointAt(0) ?? 0;
    if (n >= 8203 && n <= 8207 || // Zero-width spaces
    n >= 8234 && n <= 8238 || // Directional formatting
    n === 65279 || // BOM
    n >= 8288 && n <= 8292)
      return {
        isSpoofed: !0,
        reason: `Carácter de control Unicode invisible detectado: U+${n.toString(16).toUpperCase().padStart(4, "0")}`
      };
  }
  return { isSpoofed: !1 };
}
function H(r) {
  for (const [e, s] of Object.entries(V))
    for (const [t, n] of s)
      if (r >= t && r <= n)
        return e;
  return null;
}
class U {
  constructor() {
    this.rule = "spoof";
  }
  validate(e, s) {
    const t = G(e);
    return t.isSpoofed ? {
      code: "SPOOF_DETECTED",
      message: t.reason ?? "Se detectaron caracteres Unicode potencialmente engañosos (homógrafos)",
      rule: "spoof"
    } : null;
  }
}
const W = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/, k = /^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]+)*@(?:[\p{L}\p{N}](?:[\p{L}\p{N}\-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,}$/u;
class L {
  constructor(e = !1) {
    this.rule = "filter", this.allowUnicode = e;
  }
  validate(e, s) {
    if (!e || typeof e != "string")
      return {
        code: "EMPTY_EMAIL",
        message: "El email no puede estar vacío",
        rule: "filter"
      };
    const t = e.trim();
    return t.length === 0 ? {
      code: "EMPTY_EMAIL",
      message: "El email no puede estar vacío",
      rule: "filter"
    } : (this.allowUnicode ? k : W).test(t) ? null : {
      code: "INVALID_FORMAT",
      message: this.allowUnicode ? "El email no tiene un formato válido (filter_unicode)" : "El email no tiene un formato válido (filter)",
      rule: "filter"
    };
  }
}
class Z extends L {
  constructor() {
    super(!0);
  }
}
class p {
  constructor(e = {}, s = {}) {
    this.syncFactories = /* @__PURE__ */ new Map(), this.asyncFactories = /* @__PURE__ */ new Map(), this.options = {
      rules: e.rules ?? ["rfc"],
      dnsTimeout: e.dnsTimeout ?? 5e3,
      dnsServers: e.dnsServers ?? [],
      allowReservedDomains: e.allowReservedDomains ?? !1
    }, this.registerDefaultStrategies(), this.registerCustomStrategies(s);
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
  validate(e, s) {
    const t = s ?? this.options.rules, n = [], o = [], i = A(e?.trim() ?? ""), a = i.success ? i.parts : null;
    for (const c of t) {
      if (c === "dns")
        continue;
      const l = this.createSyncValidator(c);
      if (!l) continue;
      const d = l.validate(e, a);
      if (d) {
        n.push(d);
        break;
      }
    }
    return {
      valid: n.length === 0,
      email: e,
      errors: n,
      warnings: o,
      appliedRules: t.filter((c) => c !== "dns"),
      parts: a ?? void 0
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
  async validateAsync(e, s) {
    const t = s ?? this.options.rules, n = [], o = [], i = A(e?.trim() ?? ""), a = i.success ? i.parts : null;
    for (const c of t) {
      if (c === "dns") {
        const u = this.createAsyncValidator("dns");
        if (!u) continue;
        const f = await u.validateAsync(e, a);
        if (f) {
          n.push(f);
          break;
        }
        for (const m of u.getWarnings())
          o.push(m);
        continue;
      }
      const l = this.createSyncValidator(c);
      if (!l) continue;
      const d = l.validate(e, a);
      if (d) {
        n.push(d);
        break;
      }
    }
    return {
      valid: n.length === 0,
      email: e,
      errors: n,
      warnings: o,
      appliedRules: t,
      parts: a ?? void 0
    };
  }
  // ---------------------------------------------------------------------------
  // Factory de validadores síncronos
  // ---------------------------------------------------------------------------
  createSyncValidator(e) {
    const s = this.syncFactories.get(e);
    return s ? s() : null;
  }
  createAsyncValidator(e) {
    const s = this.asyncFactories.get(e);
    return s ? s() : null;
  }
  registerDefaultStrategies() {
    this.syncFactories.set("rfc", () => new E()), this.syncFactories.set("strict", () => new D()), this.syncFactories.set("spoof", () => new U()), this.syncFactories.set("filter", () => new L()), this.asyncFactories.set("dns", () => new F(this.options.dnsTimeout));
  }
  registerCustomStrategies(e) {
    if (e.syncFactories)
      for (const [s, t] of Object.entries(e.syncFactories))
        t && this.syncFactories.set(s, t);
    if (e.asyncFactories)
      for (const [s, t] of Object.entries(e.asyncFactories))
        t && this.asyncFactories.set(s, t);
  }
}
class q {
  constructor() {
    this.rules = [], this.options = {};
  }
  /**
   * Agrega validación RFC 5321/5322.
   * Equivalente a `email:rfc` en Laravel.
   *
   * @param options.strict - Si es `true`, equivale a `email:strict` (NoRFCWarningsValidation)
   */
  rfcCompliant(e = {}) {
    return this.rules.push(e.strict ? "strict" : "rfc"), this;
  }
  /**
   * Agrega validación de registro MX en DNS.
   * Equivalente a `email:dns` en Laravel.
   *
   * @param timeoutMs - Tiempo máximo de espera para la consulta DNS
   */
  validateMxRecord(e) {
    return this.rules.push("dns"), e !== void 0 && (this.options.dnsTimeout = e), this;
  }
  /**
   * Agrega validación anti-spoofing Unicode.
   * Equivalente a `email:spoof` en Laravel.
   */
  preventSpoofing() {
    return this.rules.push("spoof"), this;
  }
  /**
   * Agrega validación tipo filter_var de PHP.
   * Equivalente a `email:filter` en Laravel.
   */
  filterValidation() {
    return this.rules.push("filter"), this;
  }
  /**
   * Configura opciones adicionales del validador.
   */
  withOptions(e) {
    return this.options = { ...this.options, ...e }, this;
  }
  /**
   * Ejecuta la validación de forma síncrona (sin DNS).
   * Las reglas `dns` son ignoradas.
   */
  validate(e) {
    return new p({
      ...this.options,
      rules: this.rules
    }).validate(e);
  }
  /**
   * Ejecuta la validación de forma asíncrona (con soporte DNS).
   */
  async validateAsync(e) {
    return new p({
      ...this.options,
      rules: this.rules
    }).validateAsync(e);
  }
  /**
   * Retorna las reglas configuradas actualmente.
   */
  getRules() {
    return [...this.rules];
  }
}
function j() {
  return new q();
}
function B(r, e = ["rfc"]) {
  return new p({ rules: e }).validate(r).valid;
}
async function Q(r, e = ["rfc", "dns"]) {
  return (await new p({ rules: e }).validateAsync(r)).valid;
}
export {
  F as DNSValidator,
  q as EmailValidationBuilder,
  p as EmailValidator,
  Z as FilterUnicodeValidator,
  L as FilterValidator,
  w as RESERVED_DOMAINS,
  E as RFCValidator,
  U as SpoofValidator,
  D as StrictRFCValidator,
  G as analyzeSpoofing,
  j as email,
  B as isValidEmail,
  Q as isValidEmailAsync,
  $ as lookupDNS,
  A as parseEmail
};
