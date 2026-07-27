// file: sha2-wasm.ts
/**
 * SHA2-WASM – Cargador y API de Bajo Nivel
 *
 * DISEÑO ANTI-BRANCHING:
 * - Rutas SHA-256 y SHA-512 físicamente separadas (cero if/else criptográfico).
 * - argc cacheado como función directa (cero if en hot-path).
 * - Validación de límites delegada a WasmAllocator (fail-fast en frontera).
 * - Estimación UTF-8 worst-case corregida (4 bytes/code unit, no 3).
 *
 * SEGURIDAD:
 * - Nunca se escribe fuera de zonas delimitadas.
 * - Errores de capacidad lanzan excepción (nunca corrupción silenciosa).
 * - HMAC fast-path valida capacidad ANTES de escribir.
 */

import { AsmExports, getGlobalValue } from "./types.js"
import { WasmAllocator } from "./allocator.js"

export class Sha2Wasm {
  private exp: AsmExports
  private allocator: WasmAllocator

  // ── PUNTEROS HMAC FIJOS (pre-reservados, cero alloc en runtime) ──
  private readonly hmacKeyPtr: number
  private readonly hmacIPadPtr: number
  private readonly hmacOPadPtr: number

  // ── ARGC CACHEADO – Cero branching en hot-path ──
  // AssemblyScript SIEMPRE exporta __setArgumentsLength.
  // Lo cacheamos como referencia directa: llamada incondicional, sin if.
  private readonly setArgLen: (n: number) => void

  // ── CONSTANTES PRE-CALCULADAS (evitan literales mágicos en hot-path) ──
  private static readonly SHA256_CTX_SIZE = 272 // 112 ctx + 128 pad + 32 out
  private static readonly SHA256_PAD_OFFSET = 112
  private static readonly SHA256_HASH_LEN = 32
  private static readonly SHA256_BLOCK = 64

  private static readonly SHA512_CTX_SIZE = 528 // 208 ctx + 256 pad + 64 out
  private static readonly SHA512_PAD_OFFSET = 208
  private static readonly SHA512_HASH_LEN = 64
  private static readonly SHA512_BLOCK = 128

  /** Máximo de bytes que caben en la zona de entrada (PARAM_IN). */
  private readonly maxInputBytes: number

  private static instance: Sha2Wasm | null = null

  private constructor(exp: AsmExports) {
    this.exp = exp

    const inPtr = getGlobalValue(exp.PARAM_IN_PTR, 1024)
    const outPtr = getGlobalValue(exp.PARAM_OUT_PTR, 1049600)
    const baseCryptoPtr = getGlobalValue(exp.CRYPTO_WORK_PTR, 1057792)

    // Zonas HMAC fijas: 128B key + 128B iPad + 128B oPad = 384B
    // (128B soporta SHA-512; SHA-256 usa solo los primeros 64B de cada zona)
    this.hmacKeyPtr = baseCryptoPtr
    this.hmacIPadPtr = baseCryptoPtr + 128
    this.hmacOPadPtr = baseCryptoPtr + 256

    this.allocator = new WasmAllocator(exp.memory, inPtr, outPtr, baseCryptoPtr + 384)
    this.maxInputBytes = outPtr - inPtr

    // Cacheo de argc: referencia directa, sin branch.
    // Si por alguna razón no existe (módulo no-AssemblyScript), usamos noop.
    // El noop es una función estática (no se re-crea), costo = 1 call vacía.
    this.setArgLen = exp.__setArgumentsLength || Sha2Wasm.NOOP
  }

  /** Función noop estática para argc cuando no existe __setArgumentsLength. */
  private static readonly NOOP: (n: number) => void = () => {}

  // ═══════════════════════════════════════════════════════════════════════
  //  SINGLETON Y CARGA
  // ═══════════════════════════════════════════════════════════════════════

  static getInstance(): Sha2Wasm {
    if (!this.instance) {
      throw new Error("Sha2Wasm no inicializado. Llama a load(), fromUrl() o fromBuffer() primero.")
    }
    return this.instance
  }

  static getDefaultWasmUrl(): string {
    try {
      return new URL("./sha2.wasm", import.meta.url).href
    } catch {
      return "./sha2.wasm"
    }
  }

  static async load(url?: string, imports: WebAssembly.Imports = {}): Promise<Sha2Wasm> {
    if (this.instance) return this.instance
    return this.fromUrl(url || this.getDefaultWasmUrl(), imports)
  }

  static async fromUrl(url: string, imports: WebAssembly.Imports = {}): Promise<Sha2Wasm> {
    const finalImports = Sha2Wasm.mergeImports(imports)
    let instance: WebAssembly.Instance

    if (typeof WebAssembly.instantiateStreaming === "function") {
      try {
        const response = await fetch(url)
        const result = await WebAssembly.instantiateStreaming(response, finalImports)
        instance = result.instance
      } catch {
        // Fallback: el servidor no envió Content-Type: application/wasm
        const response = await fetch(url)
        const buffer = await response.arrayBuffer()
        const result = await WebAssembly.instantiate(buffer, finalImports)
        instance = result.instance
      }
    } else {
      const response = await fetch(url)
      const buffer = await response.arrayBuffer()
      const result = await WebAssembly.instantiate(buffer, finalImports)
      instance = result.instance
    }

    this.instance = new Sha2Wasm(instance.exports as unknown as AsmExports)
    return this.instance
  }

  static async fromBuffer(buffer: ArrayBuffer | Uint8Array, imports: WebAssembly.Imports = {}): Promise<Sha2Wasm> {
    const finalImports = Sha2Wasm.mergeImports(imports)
    const buf = buffer instanceof Uint8Array ? buffer.buffer : buffer
    const { instance } = await WebAssembly.instantiate(buf, finalImports)
    this.instance = new Sha2Wasm(instance.exports as unknown as AsmExports)
    return this.instance
  }

  /** Merge de imports con defaults. Se llama solo en carga (no hot-path). */
  private static mergeImports(imports: WebAssembly.Imports): WebAssembly.Imports {
    const defaults: WebAssembly.Imports = {
      env: {
        abort() {
          console.error("WASM Abort")
        },
        seed() {
          return Math.random()
        }
      }
    }
    return {
      ...defaults,
      ...imports,
      env: { ...(defaults.env as object), ...((imports.env as object) || {}) }
    }
  }

  // ── ACCESSORS ──
  public get exports(): AsmExports {
    return this.exp
  }
  public get memory(): WebAssembly.Memory {
    return this.exp.memory
  }
  public get getAllocator(): WasmAllocator {
    return this.allocator
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RUTA SHA-256 – Cero branching criptográfico
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Hash SHA-256 interno. Retorna PUNTERO al resultado (no copia).
   * El caller decide si copiar (readBytes) o usar in-situ.
   */
  private sha256InternalPtr(data: Uint8Array | string): number {
    const ctxPtr = this.allocator.allocateWorkMemory(Sha2Wasm.SHA256_CTX_SIZE)
    const paddedPtr = ctxPtr + Sha2Wasm.SHA256_PAD_OFFSET
    const outPtr = this.allocator.outPtr

    this.setArgLen(1)
    this.exp.sha256_create_ctx(ctxPtr)

    this.updateSha256Ctx(ctxPtr, data)

    this.setArgLen(3)
    this.exp.sha256_final_raw(ctxPtr, paddedPtr, outPtr)
    return outPtr
  }

  /**
   * Hash SHA-256 one-shot. Retorna Uint8Array de 32 bytes (copia).
   */
  sha256(data: Uint8Array | string): Uint8Array {
    // One-shot: 1 sola llamada WASM. sha256_hash_raw hace init+update+final
    // internamente → ahorra 2 tramps JS→WASM por hash vs create/update/final.
    this.allocator.writeInput(data, 0)
    this.setArgLen(3)
    this.exp.sha256_hash_raw(this.allocator.outPtr, this.allocator.lastPtr, this.allocator.lastLen)
    return this.allocator.readBytes(this.allocator.outPtr, Sha2Wasm.SHA256_HASH_LEN)
  }

  /**
   * HMAC-SHA256 conforme a RFC 2104.
   *
   * ESTRATEGIA ANTI-BRANCHING:
   * - Fast-path (key+data caben en zona IN): 1 llamada WASM, cero JS crypto.
   * - Slow-path (datos masivos): HMAC manual con iPad/oPad pre-computados.
   * - La decisión fast/slow es un ÚNICO branch al inicio (predictable para
   *   el caso común: keys cortas + mensajes < 1MB → fast-path siempre).
   *
   * SEGURIDAD:
   * - Estimación UTF-8 corregida: 4 bytes/code unit (worst-case real).
   * - Validación de capacidad ANTES de escribir (fail-fast).
   */
  sha256Hmac(key: Uint8Array | string, data: Uint8Array | string): Uint8Array {
    // ── ESCRIBIR KEY EN ZONA IN ──
    this.allocator.writeInput(key, 0)
    const keyPtr = this.allocator.lastPtr
    const keyLen = this.allocator.lastLen

    // ── ESTIMACIÓN WORST-CASE UTF-8: 4 bytes por code unit ──
    // CORRECCIÓN: antes era *3, lo cual subestimaba emoji/supplementary.
    const dataLenEst = typeof data === "string" ? data.length << 2 : data.length

    // ── FAST-PATH: todo cabe en zona IN → 1 sola llamada WASM ──
    // Condición: key + 16B gap + data(worst-case) ≤ maxInputBytes
    // Branch predecible: en uso típico (keys < 64B, msgs < 1MB) SIEMPRE se toma.
    if (keyLen + 16 + dataLenEst <= this.maxInputBytes) {
      this.allocator.writeInput(data, keyLen + 16)
      this.setArgLen(5)
      this.exp.sha256_hmac_raw(this.allocator.outPtr, keyPtr, keyLen, this.allocator.lastPtr, this.allocator.lastLen)
      return this.allocator.readBytes(this.allocator.outPtr, Sha2Wasm.SHA256_HASH_LEN)
    }

    // ── SLOW-PATH: HMAC manual (datos masivos) ──
    return this.sha256HmacSlow(key, keyPtr, keyLen, data)
  }

  /**
   * Slow-path HMAC-SHA256: computa iPad/oPad en JS, delega hashing a WASM.
   * Separado en método propio para que V8 no inline el fast-path con el slow
   * (mantiene el fast-path pequeño y JIT-friendly).
   */
  private sha256HmacSlow(
    key: Uint8Array | string,
    keyPtr: number,
    keyLen: number,
    data: Uint8Array | string
  ): Uint8Array {
    const heap = this.allocator.getHeap()
    const blockSize = Sha2Wasm.SHA256_BLOCK // 64

    // Limpiar zona de key (64 bytes para SHA-256)
    heap.fill(0, this.hmacKeyPtr, this.hmacKeyPtr + blockSize)

    // Si key > blockSize, hashearla primero (RFC 2104 §2)
    if (keyLen > blockSize) {
      const hashedPtr = this.sha256InternalPtr(key)
      heap.copyWithin(this.hmacKeyPtr, hashedPtr, hashedPtr + Sha2Wasm.SHA256_HASH_LEN)
    } else {
      heap.copyWithin(this.hmacKeyPtr, keyPtr, keyPtr + keyLen)
    }

    // Computar iPad y oPad: XOR byte-a-byte.
    // NOTA: Se evalúa vectorización con Uint32Array en sección de optimización.
    // Por ahora, byte-a-byte es portable (endianness-safe) y V8 lo auto-vectoriza
    // con SIMD interno en loops tight de >16 iteraciones.
    for (let i = 0; i < blockSize; i++) {
      const k = heap[this.hmacKeyPtr + i]
      heap[this.hmacIPadPtr + i] = k ^ 0x36
      heap[this.hmacOPadPtr + i] = k ^ 0x5c
    }

    // ── INNER HASH: H(iPad ‖ message) ──
    const ctxPtr = this.allocator.allocateWorkMemory(Sha2Wasm.SHA256_CTX_SIZE)
    const paddedPtr = ctxPtr + Sha2Wasm.SHA256_PAD_OFFSET
    const finalOutPtr = this.allocator.outPtr

    this.setArgLen(1)
    this.exp.sha256_create_ctx(ctxPtr)
    this.setArgLen(3)
    this.exp.sha256_update_raw(ctxPtr, this.hmacIPadPtr, blockSize)
    this.updateSha256Ctx(ctxPtr, data)
    this.setArgLen(3)
    this.exp.sha256_final_raw(ctxPtr, paddedPtr, finalOutPtr)

    // ── OUTER HASH: H(oPad ‖ innerHash) ──
    this.setArgLen(1)
    this.exp.sha256_create_ctx(ctxPtr)
    this.setArgLen(3)
    this.exp.sha256_update_raw(ctxPtr, this.hmacOPadPtr, blockSize)
    this.setArgLen(3)
    this.exp.sha256_update_raw(ctxPtr, finalOutPtr, Sha2Wasm.SHA256_HASH_LEN)
    this.setArgLen(3)
    this.exp.sha256_final_raw(ctxPtr, paddedPtr, finalOutPtr)

    return this.allocator.readBytes(finalOutPtr, Sha2Wasm.SHA256_HASH_LEN)
  }

  /**
   * Verifica HMAC-SHA256 en tiempo constante. `mac` son los bytes crudos del
   * MAC esperado (32 bytes). Retorna true si es válido.
   */
  sha256HmacVerify(key: Uint8Array | string, data: Uint8Array | string, mac: Uint8Array): boolean {
    this.allocator.writeInput(key, 0)
    const keyPtr = this.allocator.lastPtr
    const keyLen = this.allocator.lastLen

    this.allocator.writeInput(data, keyLen + 16)
    const dataPtr = this.allocator.lastPtr
    const dataLen = this.allocator.lastLen

    this.allocator.writeInput(mac, keyLen + 16 + dataLen + 16)
    const macPtr = this.allocator.lastPtr
    const macLen = this.allocator.lastLen

    this.setArgLen(6)
    return this.exp.sha256_hmac_verify_raw(keyPtr, keyLen, dataPtr, dataLen, macPtr, macLen) !== 0
  }

  /** Inicializa contexto SHA-256 en ptr. Llamada directa, sin branching. */
  createSha256Ctx(ctxPtr: number): void {
    this.setArgLen(1)
    this.exp.sha256_create_ctx(ctxPtr)
  }

  /**
   * Alimenta datos al contexto SHA-256.
   *
   * CHUNKING:
   * - Strings: chunks de 250K chars (~1MB UTF-8 worst-case).
   *   substring() en V8 crea rope nodes (barato), pero solo para strings > 350K chars.
   *   Strings cortos se procesan en 1 sola pasada (cero substring).
   * - Uint8Array: chunks de 1MB (límite de zona IN).
   *   writeBytesDirect usa subarray (vista, no copia) + set (memmove nativo).
   */
  updateSha256Ctx(ctxPtr: number, data: Uint8Array | string): void {
    if (typeof data === "string") {
      const totalLen = data.length

      // Fast-path: string corto → 1 sola pasada, cero substring.
      // 350K chars * 4 bytes = 1.4MB worst-case > 1MB zona IN.
      // Usamos 250K como límite seguro (250K * 4 = 1MB exacto).
      if (totalLen <= 250000) {
        this.allocator.writeInput(data, 0)
        this.setArgLen(3)
        this.exp.sha256_update_raw(ctxPtr, this.allocator.lastPtr, this.allocator.lastLen)
        return
      }

      // Slow-path: chunking para strings masivos.
      let charOffset = 0
      while (charOffset < totalLen) {
        const remaining = totalLen - charOffset
        const chunkSize = remaining < 250000 ? remaining : 250000
        // substring crea un rope node (~48B). Inevitable para encodeInto.
        // Alternativa: charCodeAt loop manual (más lento para ASCII).
        const subStr = data.substring(charOffset, charOffset + chunkSize)
        this.allocator.writeInput(subStr, 0)
        this.setArgLen(3)
        this.exp.sha256_update_raw(ctxPtr, this.allocator.lastPtr, this.allocator.lastLen)
        charOffset += chunkSize
      }
      return
    }

    // ── RUTA UINT8ARRAY ──
    const len = data.length
    const maxChunk = this.maxInputBytes

    // Fast-path: cabe en 1 chunk (caso común).
    if (len <= maxChunk) {
      this.allocator.writeInput(data, 0)
      this.setArgLen(3)
      this.exp.sha256_update_raw(ctxPtr, this.allocator.lastPtr, len)
      return
    }

    // Slow-path: chunking para datos > 1MB.
    let offset = 0
    while (offset < len) {
      const remaining = len - offset
      const chunkSize = remaining < maxChunk ? remaining : maxChunk
      const dataPtr = this.allocator.writeBytesDirect(data, offset, chunkSize, 0)
      this.setArgLen(3)
      this.exp.sha256_update_raw(ctxPtr, dataPtr, chunkSize)
      offset += chunkSize
    }
  }

  /** Finaliza SHA-256 y retorna copia de 32 bytes. */
  finalSha256Ctx(ctxPtr: number, paddedPtr: number, outPtr: number): Uint8Array {
    this.setArgLen(3)
    this.exp.sha256_final_raw(ctxPtr, paddedPtr, outPtr)
    return this.allocator.readBytes(outPtr, Sha2Wasm.SHA256_HASH_LEN)
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RUTA SHA-512 – Cero branching criptográfico (espejo de SHA-256)
  // ═══════════════════════════════════════════════════════════════════════

  private sha512InternalPtr(data: Uint8Array | string): number {
    const ctxPtr = this.allocator.allocateWorkMemory(Sha2Wasm.SHA512_CTX_SIZE)
    const paddedPtr = ctxPtr + Sha2Wasm.SHA512_PAD_OFFSET
    const outPtr = this.allocator.outPtr

    this.setArgLen(1)
    this.exp.sha512_create_ctx(ctxPtr)

    this.updateSha512Ctx(ctxPtr, data)

    this.setArgLen(3)
    this.exp.sha512_final_raw(ctxPtr, paddedPtr, outPtr)
    return outPtr
  }

  sha512(data: Uint8Array | string): Uint8Array {
    this.allocator.writeInput(data, 0)
    this.setArgLen(3)
    this.exp.sha512_hash_raw(this.allocator.outPtr, this.allocator.lastPtr, this.allocator.lastLen)
    return this.allocator.readBytes(this.allocator.outPtr, Sha2Wasm.SHA512_HASH_LEN)
  }

  sha512Hmac(key: Uint8Array | string, data: Uint8Array | string): Uint8Array {
    this.allocator.writeInput(key, 0)
    const keyPtr = this.allocator.lastPtr
    const keyLen = this.allocator.lastLen

    // CORRECCIÓN: estimación UTF-8 con 4 bytes/code unit.
    const dataLenEst = typeof data === "string" ? data.length << 2 : data.length

    if (keyLen + 16 + dataLenEst <= this.maxInputBytes) {
      this.allocator.writeInput(data, keyLen + 16)
      this.setArgLen(5)
      this.exp.sha512_hmac_raw(this.allocator.outPtr, keyPtr, keyLen, this.allocator.lastPtr, this.allocator.lastLen)
      return this.allocator.readBytes(this.allocator.outPtr, Sha2Wasm.SHA512_HASH_LEN)
    }

    return this.sha512HmacSlow(key, keyPtr, keyLen, data)
  }

  private sha512HmacSlow(
    key: Uint8Array | string,
    keyPtr: number,
    keyLen: number,
    data: Uint8Array | string
  ): Uint8Array {
    const heap = this.allocator.getHeap()
    const blockSize = Sha2Wasm.SHA512_BLOCK // 128

    heap.fill(0, this.hmacKeyPtr, this.hmacKeyPtr + blockSize)

    if (keyLen > blockSize) {
      const hashedPtr = this.sha512InternalPtr(key)
      heap.copyWithin(this.hmacKeyPtr, hashedPtr, hashedPtr + Sha2Wasm.SHA512_HASH_LEN)
    } else {
      heap.copyWithin(this.hmacKeyPtr, keyPtr, keyPtr + keyLen)
    }

    for (let i = 0; i < blockSize; i++) {
      const k = heap[this.hmacKeyPtr + i]
      heap[this.hmacIPadPtr + i] = k ^ 0x36
      heap[this.hmacOPadPtr + i] = k ^ 0x5c
    }

    const ctxPtr = this.allocator.allocateWorkMemory(Sha2Wasm.SHA512_CTX_SIZE)
    const paddedPtr = ctxPtr + Sha2Wasm.SHA512_PAD_OFFSET
    const finalOutPtr = this.allocator.outPtr

    this.setArgLen(1)
    this.exp.sha512_create_ctx(ctxPtr)
    this.setArgLen(3)
    this.exp.sha512_update_raw(ctxPtr, this.hmacIPadPtr, blockSize)
    this.updateSha512Ctx(ctxPtr, data)
    this.setArgLen(3)
    this.exp.sha512_final_raw(ctxPtr, paddedPtr, finalOutPtr)

    this.setArgLen(1)
    this.exp.sha512_create_ctx(ctxPtr)
    this.setArgLen(3)
    this.exp.sha512_update_raw(ctxPtr, this.hmacOPadPtr, blockSize)
    this.setArgLen(3)
    this.exp.sha512_update_raw(ctxPtr, finalOutPtr, Sha2Wasm.SHA512_HASH_LEN)
    this.setArgLen(3)
    this.exp.sha512_final_raw(ctxPtr, paddedPtr, finalOutPtr)

    return this.allocator.readBytes(finalOutPtr, Sha2Wasm.SHA512_HASH_LEN)
  }

  /** Verifica HMAC-SHA512 en tiempo constante. `mac` son 64 bytes crudos. */
  sha512HmacVerify(key: Uint8Array | string, data: Uint8Array | string, mac: Uint8Array): boolean {
    this.allocator.writeInput(key, 0)
    const keyPtr = this.allocator.lastPtr
    const keyLen = this.allocator.lastLen

    this.allocator.writeInput(data, keyLen + 16)
    const dataPtr = this.allocator.lastPtr
    const dataLen = this.allocator.lastLen

    this.allocator.writeInput(mac, keyLen + 16 + dataLen + 16)
    const macPtr = this.allocator.lastPtr
    const macLen = this.allocator.lastLen

    this.setArgLen(6)
    return this.exp.sha512_hmac_verify_raw(keyPtr, keyLen, dataPtr, dataLen, macPtr, macLen) !== 0
  }

  createSha512Ctx(ctxPtr: number): void {
    this.setArgLen(1)
    this.exp.sha512_create_ctx(ctxPtr)
  }

  updateSha512Ctx(ctxPtr: number, data: Uint8Array | string): void {
    if (typeof data === "string") {
      const totalLen = data.length

      if (totalLen <= 250000) {
        this.allocator.writeInput(data, 0)
        this.setArgLen(3)
        this.exp.sha512_update_raw(ctxPtr, this.allocator.lastPtr, this.allocator.lastLen)
        return
      }

      let charOffset = 0
      while (charOffset < totalLen) {
        const remaining = totalLen - charOffset
        const chunkSize = remaining < 250000 ? remaining : 250000
        const subStr = data.substring(charOffset, charOffset + chunkSize)
        this.allocator.writeInput(subStr, 0)
        this.setArgLen(3)
        this.exp.sha512_update_raw(ctxPtr, this.allocator.lastPtr, this.allocator.lastLen)
        charOffset += chunkSize
      }
      return
    }

    const len = data.length
    const maxChunk = this.maxInputBytes

    if (len <= maxChunk) {
      this.allocator.writeInput(data, 0)
      this.setArgLen(3)
      this.exp.sha512_update_raw(ctxPtr, this.allocator.lastPtr, len)
      return
    }

    let offset = 0
    while (offset < len) {
      const remaining = len - offset
      const chunkSize = remaining < maxChunk ? remaining : maxChunk
      const dataPtr = this.allocator.writeBytesDirect(data, offset, chunkSize, 0)
      this.setArgLen(3)
      this.exp.sha512_update_raw(ctxPtr, dataPtr, chunkSize)
      offset += chunkSize
    }
  }

  finalSha512Ctx(ctxPtr: number, paddedPtr: number, outPtr: number): Uint8Array {
    this.setArgLen(3)
    this.exp.sha512_final_raw(ctxPtr, paddedPtr, outPtr)
    return this.allocator.readBytes(outPtr, Sha2Wasm.SHA512_HASH_LEN)
  }
}
