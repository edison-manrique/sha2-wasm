// file: types.ts
/**
 * SHA2-WASM – Tipos, Interfaces y Utilidades de Conversión
 *
 * OPTIMIZACIONES APLICADAS:
 * - bytesToHex: Array pre-allocado + join (1 sola alocación de string final).
 * - hexToBytes: Sin RegExp, sin string intermedio. Validación inline fail-fast.
 * - LUT como Array<string> fijo (V8 lo trata como FixedArray, acceso O(1)).
 */

// ── TIPOS ──

export type HashAlgorithm = "SHA256" | "SHA512"
export type OutputFormat = "hex" | "bytes"

export interface ShaOptions {
  format?: OutputFormat
}

// ── INTERFAZ WASM ──

/**
 * Interfaz de exportaciones del módulo WASM compilado desde AssemblyScript.
 *
 * NOTA: NO extiende WebAssembly.Exports porque su index signature
 * ([key: string]: ExportValue) rechaza `number`. AssemblyScript puede
 * exportar constantes globales como WebAssembly.Global O como number
 * plano (dependiendo de --exportRuntime y optimizaciones del compiler).
 *
 * Para usar con instance.exports, se castea:
 *   const exp = instance.exports as unknown as AsmExports
 */
export interface AsmExports {
  /** Memoria lineal compartida JS ↔ WASM. */
  memory: WebAssembly.Memory

  // ── PUNTEROS DE SCRATCHPAD ──
  // AssemblyScript exporta `const` globals como WebAssembly.Global.
  // Con --noExportRuntime o inlining, pueden aparecer como number.
  // getGlobalValue() normaliza ambos casos en runtime.

  /** Puntero base del scratchpad estático. */
  SCRATCH_PTR?: WebAssembly.Global | number
  /** Inicio zona de entrada (PARAM_IN) – típicamente 8KB–1MB. */
  PARAM_IN_PTR?: WebAssembly.Global | number
  /** Inicio zona de salida (PARAM_OUT) – típicamente 8KB. */
  PARAM_OUT_PTR?: WebAssembly.Global | number
  /** Inicio zona de trabajo criptográfico – típicamente 16KB+. */
  CRYPTO_WORK_PTR?: WebAssembly.Global | number

  // ── FUNCIONES SHA-256 ──

  /** Hash SHA-256 one-shot: H(mPtr[0..n)) → outPtr[0..32). */
  sha256_hash_raw: (outPtr: number, mPtr: number, n: number) => void
  /** HMAC-SHA256: H(k‖m) → outPtr[0..32). */
  sha256_hmac_raw: (outPtr: number, kPtr: number, kLen: number, mPtr: number, mLen: number) => void
  /** Inicializa contexto SHA-256 (112 bytes) en ctxPtr. */
  sha256_create_ctx: (ctxPtr: number) => void
  /** Alimenta n bytes al contexto SHA-256. */
  sha256_update_raw: (ctxPtr: number, mPtr: number, n: number) => void
  /** Finaliza SHA-256: padding + compresión → outPtr[0..32). */
  sha256_final_raw: (ctxPtr: number, paddedPtr: number, outPtr: number) => void

  // ── FUNCIONES SHA-512 ──

  /** Hash SHA-512 one-shot: H(mPtr[0..n)) → outPtr[0..64). */
  sha512_hash_raw: (outPtr: number, mPtr: number, n: number) => void
  /** HMAC-SHA512: H(k‖m) → outPtr[0..64). */
  sha512_hmac_raw: (outPtr: number, kPtr: number, kLen: number, mPtr: number, mLen: number) => void
  /** Inicializa contexto SHA-512 (208 bytes) en ctxPtr. */
  sha512_create_ctx: (ctxPtr: number) => void
  /** Alimenta n bytes al contexto SHA-512. */
  sha512_update_raw: (ctxPtr: number, mPtr: number, n: number) => void
  /** Finaliza SHA-512: padding + compresión → outPtr[0..64). */
  sha512_final_raw: (ctxPtr: number, paddedPtr: number, outPtr: number) => void

  // ── ABI ASSEMBLYSCRIPT ──

  /** Requerido por AS para funciones con parámetros opcionales. */
  __setArgumentsLength?: (n: number) => void
}
// ── UTILIDADES WASM ──

/**
 * Extrae el valor numérico de un global WASM o retorna el fallback.
 * Sin branching en hot-path: se llama solo en construcción (1 vez).
 */
export function getGlobalValue(val: WebAssembly.Global | number | undefined, fallback: number): number {
  if (typeof val === "number") return val
  if (val !== undefined && val !== null) return Number((val as WebAssembly.Global).value)
  return fallback
}

// ═══════════════════════════════════════════════════════════════════════════
//  CONVERSIÓN HEX – Zero intermediate strings, zero RegExp
// ═══════════════════════════════════════════════════════════════════════════

/**
 * LUT de 256 entradas: índice → string hex de 2 caracteres.
 * Array<string> fijo → V8 lo representa como FixedArray (acceso O(1), sin hash).
 * Inicializado una sola vez en carga del módulo.
 */
const HEX_LUT: string[] = new Array<string>(256)
for (let i = 0; i < 256; i++) {
  HEX_LUT[i] = (i < 16 ? "0" : "") + i.toString(16)
}

/**
 * LUT de decodificación ASCII → nibble (0-15). -1 = inválido.
 * Int8Array: acceso O(1) por charCode, sin branching interno.
 */
const HEX_DECODE_LUT = new Int8Array(256).fill(-1)
for (let i = 0; i < 10; i++) HEX_DECODE_LUT[48 + i] = i // '0'-'9'
for (let i = 0; i < 6; i++) {
  HEX_DECODE_LUT[65 + i] = 10 + i // 'A'-'F'
  HEX_DECODE_LUT[97 + i] = 10 + i // 'a'-'f'
}

/**
 * Convierte un Uint8Array a cadena hexadecimal minúscula.
 *
 * RENDIMIENTO:
 * - Pre-aloca un Array<string> de tamaño exacto (V8: FixedArray, sin resize).
 * - Una sola llamada a join("") → V8 internamente usa StringBuilder nativo.
 * - Cero concatenaciones intermedias, cero ConsString flattening.
 * - Para SHA-256 (32B): 32 lookups + 1 join = ~33 operaciones.
 * - Para SHA-512 (64B): 64 lookups + 1 join = ~65 operaciones.
 *
 * GC: Crea 1 Array (FixedArray) + 1 String final. Los strings de la LUT
 * son internados (no se re-crean). Total: 2 objetos por llamada.
 *
 * @param bytes Arreglo de bytes a convertir.
 * @returns Hexadecimal en minúsculas.
 */
export function bytesToHex(bytes: Uint8Array): string {
  const len = bytes.length
  const parts = new Array<string>(len)
  for (let i = 0; i < len; i++) {
    parts[i] = HEX_LUT[bytes[i]]
  }
  return parts.join("")
}

/**
 * Convierte una cadena hexadecimal a Uint8Array.
 *
 * RENDIMIENTO:
 * - Sin RegExp (evita compilación + ejecución de autómata).
 * - Sin string intermedio (no hay .replace(), no hay .trim()).
 * - Validación inline: un solo branch por byte (predictable: nunca tomado en input válido).
 * - Acceso a LUT por charCode: O(1) sin parseInt(), sin substring().
 *
 * SEGURIDAD:
 * - Si un carácter no es hex válido, lanza Error con posición exacta.
 * - Si la longitud es impar, lanza Error (nunca trunca silenciosamente).
 * - Acepta '0x' prefix opcional (lo detecta sin regex).
 *
 * GC: Crea exactamente 1 Uint8Array. Cero strings intermedios.
 *
 * @param hex Cadena hexadecimal (con o sin prefijo "0x").
 * @returns Uint8Array con los bytes decodificados.
 * @throws Error si contiene caracteres inválidos o longitud impar.
 */
export function hexToBytes(hex: string): Uint8Array {
  // Detectar y saltar prefijo "0x" / "0X" sin regex ni substring.
  let start = 0
  if (hex.length > 1 && hex.charCodeAt(0) === 48 && (hex.charCodeAt(1) === 120 || hex.charCodeAt(1) === 88)) {
    start = 2
  }

  const hexLen = hex.length - start

  // Validación de paridad: fail-fast, nunca truncamiento silencioso.
  if (hexLen & 1) {
    throw new Error(`hexToBytes: longitud impar (${hexLen} chars). Se esperan pares hex.`)
  }

  const byteLen = hexLen >>> 1
  const bytes = new Uint8Array(byteLen)

  for (let i = 0; i < byteLen; i++) {
    const hi = HEX_DECODE_LUT[hex.charCodeAt(start + i * 2)]
    const lo = HEX_DECODE_LUT[hex.charCodeAt(start + i * 2 + 1)]

    // Validación: si hi o lo es -1, el carácter es inválido.
    // Branch de seguridad: en input válido NUNCA se toma.
    // (h | l) < 0 es true si cualquiera es -1 (bit de signo propagado).
    if ((hi | lo) < 0) {
      const pos = start + i * 2
      throw new Error(`hexToBytes: carácter inválido '${hex[pos]}${hex[pos + 1]}' en posición ${pos}.`)
    }

    bytes[i] = (hi << 4) | lo
  }

  return bytes
}

// ── CONVERSIÓN GENÉRICA ──

/** TextEncoder singleton de módulo (evita instanciación por llamada). */
const encoder = new TextEncoder()

/**
 * Convierte string UTF-8 o Uint8Array a Uint8Array.
 * Si ya es Uint8Array, retorna la MISMA referencia (zero-copy).
 * Si es string, crea un Uint8Array (inevitable: encode() siempre aloca).
 *
 * @param input String o bytes.
 * @returns Uint8Array (misma referencia si ya era bytes).
 */
export function toUint8Array(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") {
    return encoder.encode(input)
  }
  return input
}
