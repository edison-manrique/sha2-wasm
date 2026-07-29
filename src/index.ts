/**
 * SHA2-WASM – Punto de Entrada Principal
 *
 * Biblioteca de alto rendimiento para SHA-256, SHA-512 y HMAC implementada
 * en AssemblyScript / WebAssembly con un wrapper TypeScript completamente tipado.
 *
 * Características:
 * - 100% Zero-Allocation mediante scratchpad estático en memoria WASM.
 * - API one-shot para hashes completos en una sola llamada.
 * - API de streaming (incremental) para datos en múltiples fragmentos.
 * - Soporte para HMAC-SHA256 y HMAC-SHA512 conforme a RFC 2104.
 * - Salida en formato hexadecimal o Uint8Array (bytes crudos).
 *
 * @module sha2-wasm
 *
 * @example
 * ```ts
 * import { Sha2Wasm, Sha256, Sha512, HMAC } from "sha2-wasm"
 *
 * // Cargar el módulo WASM (solo una vez)
 * await Sha2Wasm.fromBuffer(wasmBuffer)
 *
 * // Hash SHA-256 one-shot
 * const hash = Sha256.hash("Hola Mundo")
 *
 * // Hash SHA-512 streaming
 * const hasher = Sha512.createHasher()
 * hasher.update("parte 1").update("parte 2")
 * const digest = hasher.digest()
 *
 * // HMAC-SHA256 orientado a objetos
 * const mac = new HMAC("clave-secreta", "SHA256")
 * const token = mac.digest("mensaje")
 * ```
 */

export { Sha2Wasm } from "./sha2-wasm"
export { WasmAllocator } from "./allocator"
export { Sha256, Sha256Hasher } from "./sha256"
export { Sha512, Sha512Hasher } from "./sha512"
export { HMAC } from "./hmac"
export * from "./types"
