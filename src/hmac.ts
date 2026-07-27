// file: hmac.ts
/**
 * SHA2-WASM – Módulo HMAC
 *
 * CORRECCIÓN: Los overloads ahora exponen `wasmInstance` opcional,
 * eliminando la necesidad de `as any` en el caller.
 */

import { HashAlgorithm, OutputFormat, bytesToHex } from "./types.js"
import { Sha2Wasm } from "./sha2-wasm.js"

export class HMAC {
  public readonly key: Uint8Array | string
  public readonly algorithm: HashAlgorithm

  constructor(key: Uint8Array | string, algorithm: HashAlgorithm = "SHA256") {
    this.key = key
    this.algorithm = algorithm
  }

  // ── OVERLOADS COMPLETOS (incluyen wasmInstance) ──

  static compute(
    algorithm: HashAlgorithm,
    key: Uint8Array | string,
    data: Uint8Array | string,
    format: "hex",
    wasmInstance?: Sha2Wasm
  ): string
  static compute(
    algorithm: HashAlgorithm,
    key: Uint8Array | string,
    data: Uint8Array | string,
    format: "bytes",
    wasmInstance?: Sha2Wasm
  ): Uint8Array
  static compute(
    algorithm: HashAlgorithm,
    key: Uint8Array | string,
    data: Uint8Array | string,
    format: OutputFormat = "hex",
    wasmInstance?: Sha2Wasm
  ): Uint8Array | string {
    const wasm = wasmInstance || Sha2Wasm.getInstance()
    const rawBytes = algorithm === "SHA512" ? wasm.sha512Hmac(key, data) : wasm.sha256Hmac(key, data)

    if (format === "bytes") return rawBytes
    return bytesToHex(rawBytes)
  }

  // ── MÉTODO DE INSTANCIA – Sin `as any`, tipos seguros ──

  digest(data: Uint8Array | string): string
  digest(data: Uint8Array | string, format: "hex"): string
  digest(data: Uint8Array | string, format: "bytes"): Uint8Array
  digest(data: Uint8Array | string, format: OutputFormat = "hex"): Uint8Array | string {
    // Llamada directa con tipos correctos. Sin cast.
    if (format === "bytes") {
      return HMAC.compute(this.algorithm, this.key, data, "bytes")
    }
    return HMAC.compute(this.algorithm, this.key, data, "hex")
  }
}
