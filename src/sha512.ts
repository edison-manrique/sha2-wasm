// file: sha512.ts
/**
 * SHA2-WASM – Módulo SHA-512
 *
 * OPTIMIZACIONES:
 * - Method-swapping para el estado "finalized": cero branches en el hot-path de update().
 * - digest() separado en digestHex()/digestBytes() (cero branch de formato).
 * - hashFile() con STREAMING REAL (file.stream()): el runtime pre-lee internamente
 *   y entrega chunks pequeños → JS NO acumula buffers de 64 MB (antes double-buffer
 *   mantenía ~128 MB vivos). Callback cacheado (cero optional-chaining por chunk).
 *
 * SEGURIDAD:
 * - Llamar update() tras digest() lanza Error explícito (method-swap).
 * - reset() verifica el IV del contexto y re-asigna memoria si fue sobreescrito
 *   (detección de colisión del ring buffer, nunca falla silenciosamente).
 * - hashFile() con archivo vacío → hash estándar de input vacío (fail-fast).
 */

import { OutputFormat, bytesToHex, hexToBytes } from "./types.js"
import { Sha2Wasm } from "./sha2-wasm.js"

// ═══════════════════════════════════════════════════════════════════════════
//  HASHER INCREMENTAL SHA-512
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Función que reemplaza a `update()` tras la finalización.
 * Definida a nivel de módulo: NO se re-crea por instancia (1 sola alocación global).
 * Lanza Error explícito → nunca falla silenciosamente.
 */
function throwFinalized(): never {
  throw new Error("Sha512Hasher ya finalizado. Usa reset() o crea una nueva instancia.")
}

export class Sha512Hasher {
  private wasm: Sha2Wasm
  private ctxPtr: number
  private paddedPtr: number
  private outPtr: number

  /**
   * Referencia mutable a la función update (method-swap).
   * - Estado activo: apunta a `updateImpl` (cero branches internos).
   * - Estado finalizado: apunta a `throwFinalized` (lanza Error).
   *
   * El engine JIT (V8/JSC) especializa esta indirect call tras 2-3 llamadas
   * (inline cache monomórfico). Costo: 1 indirect call (vs. 1 branch + call).
   */
  public update: (data: Uint8Array | string) => this

  constructor(wasmInstance?: Sha2Wasm) {
    this.wasm = wasmInstance || Sha2Wasm.getInstance()
    const allocator = this.wasm.getAllocator

    // SHA-512: 208B ctx + 256B padding + 64B output = 528B
    this.ctxPtr = allocator.allocateWorkMemory(528)
    this.paddedPtr = this.ctxPtr + 208
    this.outPtr = this.paddedPtr + 256

    // Inicializar contexto WASM.
    this.wasm.createSha512Ctx(this.ctxPtr)

    // Method-swap: update activo (sin branch de `finalized`).
    this.update = this.updateImpl
  }

  /**
   * Implementación real de update(). CERO branches de estado.
   * Solo delega en WASM. La validación de "finalizado" se hace por method-swap,
   * no por if/else aquí.
   */
  private updateImpl(data: Uint8Array | string): this {
    this.wasm.updateSha512Ctx(this.ctxPtr, data)
    return this
  }

  /**
   * Reinicia el hasher para reutilización.
   *
   * SEGURIDAD (detección de colisión del ring buffer): verifica que los primeros
   * 4 bytes del contexto aún contienen los 32 bits bajos del IV de SHA-512. Si otra
   * operación (otro hasher, HMAC) sobreescibió esta región, el IV no coincidirá y se
   * re-asigna memoria fresca — en vez de producir un hash incorrecto en silencio.
   *
   * @returns this para encadenamiento.
   */
  reset(): this {
    const allocator = this.wasm.getAllocator
    const heap = allocator.getHeap()

    // IV[0] de SHA-512 = 0x6a09e667f3bcc908. En little-endian, los 4 primeros bytes
    // son los 32 bits bajos: 0x08,0xc9,0xbc,0xf3 → u32 LE = 0xf3bcc908.
    // `>>> 0` es OBLIGATORIO: 0xf3 tiene el bit alto a 1; sin él, el `<< 24` produce
    // un i32 negativo y la comparación fallaría siempre (reasignando en cada reset).
    const iv0 =
      (heap[this.ctxPtr] |
        (heap[this.ctxPtr + 1] << 8) |
        (heap[this.ctxPtr + 2] << 16) |
        (heap[this.ctxPtr + 3] << 24)) >>>
      0

    if (iv0 !== 0xf3bcc908) {
      // Contexto corrompido → re-asignar región fresca.
      this.ctxPtr = allocator.allocateWorkMemory(528)
      this.paddedPtr = this.ctxPtr + 208
      this.outPtr = this.paddedPtr + 256
    }

    // Re-inicializar contexto WASM.
    this.wasm.createSha512Ctx(this.ctxPtr)

    // Reactivar update (por si se llama reset() tras digest()).
    this.update = this.updateImpl
    return this
  }

  // ── DIGEST – Separado por formato para eliminar branch ──

  digest(): string
  digest(format: "hex"): string
  digest(format: "bytes"): Uint8Array
  /**
   * Finaliza el cálculo y devuelve el digest en el formato solicitado.
   * Desactiva update() por method-swap (llamar update() después lanza Error).
   */
  digest(format: OutputFormat = "hex"): Uint8Array | string {
    this.update = throwFinalized as (data: Uint8Array | string) => this
    const bytes = this.wasm.finalSha512Ctx(this.ctxPtr, this.paddedPtr, this.outPtr)
    // Branch de formato: se evalúa UNA sola vez (no es hot-path repetido).
    if (format === "bytes") return bytes
    return bytesToHex(bytes)
  }

  /** Alternativa explícita sin branch: retorna siempre hex. */
  digestHex(): string {
    this.update = throwFinalized as (data: Uint8Array | string) => this
    const bytes = this.wasm.finalSha512Ctx(this.ctxPtr, this.paddedPtr, this.outPtr)
    return bytesToHex(bytes)
  }

  /** Alternativa explícita sin branch: retorna siempre bytes. */
  digestBytes(): Uint8Array {
    this.update = throwFinalized as (data: Uint8Array | string) => this
    return this.wasm.finalSha512Ctx(this.ctxPtr, this.paddedPtr, this.outPtr)
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  API ONE-SHOT SHA-512
// ═══════════════════════════════════════════════════════════════════════════

export class Sha512 {
  static hash(data: Uint8Array | string): string
  static hash(data: Uint8Array | string, format: "hex"): string
  static hash(data: Uint8Array | string, format: "bytes"): Uint8Array
  static hash(data: Uint8Array | string, format: OutputFormat = "hex", wasmInstance?: Sha2Wasm): Uint8Array | string {
    const wasm = wasmInstance || Sha2Wasm.getInstance()
    const bytes = wasm.sha512(data)
    if (format === "bytes") return bytes
    return bytesToHex(bytes)
  }

  static hmac(key: Uint8Array | string, data: Uint8Array | string): string
  static hmac(key: Uint8Array | string, data: Uint8Array | string, format: "hex"): string
  static hmac(key: Uint8Array | string, data: Uint8Array | string, format: "bytes"): Uint8Array
  static hmac(
    key: Uint8Array | string,
    data: Uint8Array | string,
    format: OutputFormat = "hex",
    wasmInstance?: Sha2Wasm
  ): Uint8Array | string {
    const wasm = wasmInstance || Sha2Wasm.getInstance()
    const bytes = wasm.sha512Hmac(key, data)
    if (format === "bytes") return bytes
    return bytesToHex(bytes)
  }

  /** Verifica un HMAC-SHA512 en tiempo constante. */
  static hmacVerify(
    key: Uint8Array | string,
    data: Uint8Array | string,
    mac: Uint8Array | string,
    wasmInstance?: Sha2Wasm
  ): boolean {
    const wasm = wasmInstance || Sha2Wasm.getInstance()
    const macBytes = typeof mac === "string" ? hexToBytes(mac) : mac
    return wasm.sha512HmacVerify(key, data, macBytes)
  }

  /**
   * Hashea un Blob/File de cualquier tamaño de forma asíncrona con STREAMING REAL.
   *
   * OPTIMIZACIONES:
   * - file.stream(): el runtime (browser/Bun) gestiona el read-ahead internamente
   *   y entrega chunks pequeños. JS NO acumula buffers de 64 MB (solo un chunk a
   *   la vez) → memoria plana y sin el overhead de GC del double-buffer (~128 MB).
   * - El I/O se solapa con el compute vía el buffering del propio runtime.
   * - Callback de progreso cacheado (cero optional-chaining por chunk).
   * - Sin `as any`: overloads correctos con retorno tipado.
   *
   * SEGURIDAD:
   * - Archivo vacío → hash estándar de input vacío, sin I/O.
   * - Error de lectura → la promesa rechaza (no se traga).
   */
  static async hashFile(
    file: Blob,
    format?: "hex",
    onProgress?: (processed: number, total: number) => void,
    wasmInstance?: Sha2Wasm
  ): Promise<string>
  static async hashFile(
    file: Blob,
    format: "bytes",
    onProgress?: (processed: number, total: number) => void,
    wasmInstance?: Sha2Wasm
  ): Promise<Uint8Array>
  static async hashFile(
    file: Blob,
    format: OutputFormat = "hex",
    onProgress?: (processed: number, total: number) => void,
    wasmInstance?: Sha2Wasm
  ): Promise<string | Uint8Array> {
    const wasm = wasmInstance || Sha2Wasm.getInstance()
    const hasher = new Sha512Hasher(wasm)
    const total = file.size
    const progress: (p: number, t: number) => void = onProgress || Sha512.PROGRESS_NOOP

    if (total === 0) {
      return format === "bytes" ? hasher.digest("bytes") : hasher.digest("hex")
    }

    // Ceder al event loop periódicamente para que la UI se repinte.
    // reader.read() se resuelve como microtarea cuando hay prefetch, y el navegador
    // no repinta entre microtareas → forzamos el yield cada ~5% del archivo
    // (≈20 yields, overhead mínimo ~constante). scheduler.yield() donde exista,
    // setTimeout(0) como fallback portable.
    const YIELD_BYTES = Math.max(1024 * 1024, Math.floor(total / 20))
    const sched = (globalThis as { scheduler?: { yield?: () => Promise<void> } }).scheduler
    const yieldToMain = (): Promise<void> => (sched?.yield ? sched.yield() : new Promise<void>((r) => setTimeout(r, 0)))

    let processed = 0
    let lastReported = 0
    const reader = file.stream().getReader()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (value && value.length > 0) {
        hasher.update(value)
        processed += value.length
        // Reportar + ceder cada YIELD_BYTES (no en cada chunk: evita miles de updates de DOM).
        if (processed - lastReported >= YIELD_BYTES) {
          lastReported = processed
          progress(processed, total)
          await yieldToMain()
        }
      }
    }
    // Último tramo + 100% (el bucle no reporta el tramo final < YIELD_BYTES).
    progress(processed, total)

    return format === "bytes" ? hasher.digest("bytes") : hasher.digest("hex")
  }

  /** NOOP estático para progress (1 alocación global, no por llamada). */
  private static readonly PROGRESS_NOOP: (p: number, t: number) => void = () => {}

  static createHasher(wasmInstance?: Sha2Wasm): Sha512Hasher {
    return new Sha512Hasher(wasmInstance)
  }

  /**
   * Deriva una clave con PBKDF2-HMAC-SHA512 (RFC 8018).
   * @param password   Contraseña (string UTF-8 o Uint8Array).
   * @param salt       Salt (string UTF-8 o Uint8Array).
   * @param iterations Número de iteraciones (ej. 2048 para BIP39, 4096 para WPA2).
   * @param dkLen      Longitud de la clave derivada en bytes (ej. 64 para BIP39).
   * @param format     "hex" (por defecto) o "bytes".
   */
  static pbkdf2(
    password: Uint8Array | string,
    salt: Uint8Array | string,
    iterations: number,
    dkLen: number,
    format?: "hex"
  ): string
  static pbkdf2(
    password: Uint8Array | string,
    salt: Uint8Array | string,
    iterations: number,
    dkLen: number,
    format: "bytes"
  ): Uint8Array
  static pbkdf2(
    password: Uint8Array | string,
    salt: Uint8Array | string,
    iterations: number,
    dkLen: number,
    format: OutputFormat = "hex",
    wasmInstance?: Sha2Wasm
  ): Uint8Array | string {
    const wasm = wasmInstance || Sha2Wasm.getInstance()
    const bytes = wasm.sha512Pbkdf2(password, salt, iterations, dkLen)
    return format === "bytes" ? bytes : bytesToHex(bytes)
  }
}
