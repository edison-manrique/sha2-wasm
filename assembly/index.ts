/**
 * SHA2-WASM – Punto de Entrada AssemblyScript
 *
 * Expone las funciones de bajo nivel compiladas a WebAssembly para:
 * - Hashes one-shot: SHA-256 y SHA-512.
 * - HMAC one-shot:   HMAC-SHA256 y HMAC-SHA512.
 * - Streaming:       Contextos SHA-256 (112 bytes) y SHA-512 (208 bytes)
 *                    con operaciones create / update / final.
 *
 * También re-exporta los punteros de scratchpad estático (SCRATCH_PTR,
 * PARAM_IN_PTR, PARAM_OUT_PTR, CRYPTO_WORK_PTR) para que el wrapper
 * TypeScript pueda localizar las zonas de I/O en la memoria lineal.
 */

import { SCRATCH_PTR, PARAM_IN_PTR, PARAM_OUT_PTR, CRYPTO_WORK_PTR } from "./memory"
import { Sha256, Sha256Context } from "./sha256"
import { Sha512, Sha512Context } from "./sha512"

// ── Exportar punteros del scratchpad estático ──────────────────────────────
export { SCRATCH_PTR, PARAM_IN_PTR, PARAM_OUT_PTR, CRYPTO_WORK_PTR }

// ── Hash One-Shot SHA-256 ──────────────────────────────────────────────────

/**
 * Calcula el hash SHA-256 de n bytes en mPtr y escribe los 32 bytes
 * resultantes en outPtr. Operación one-shot, 100% zero-alloc.
 *
 * @param outPtr Puntero de destino (mín. 32 bytes disponibles).
 * @param mPtr   Puntero al mensaje de entrada.
 * @param n      Longitud del mensaje en bytes.
 */
export function sha256_hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
  Sha256.hash_raw(outPtr, mPtr, n)
}

/**
 * Calcula HMAC-SHA256 con la clave kPtr[0..kLen) sobre el mensaje
 * mPtr[0..mLen) y escribe los 32 bytes resultantes en outPtr.
 *
 * @param outPtr Puntero de destino (mín. 32 bytes disponibles).
 * @param kPtr   Puntero a la clave HMAC.
 * @param kLen   Longitud de la clave en bytes.
 * @param mPtr   Puntero al mensaje a autenticar.
 * @param mLen   Longitud del mensaje en bytes.
 */
export function sha256_hmac_raw(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
  Sha256.hmac_raw(outPtr, kPtr, kLen, mPtr, mLen)
}

/**
 * Verifica un HMAC-SHA256 en tiempo constante.
 * Compara el HMAC calculado con macPtr[0..macLen) y retorna true si coinciden,
 * false en caso contrario. Tiempo constante (sin early-exit).
 *
 * @param kPtr   Puntero a la clave HMAC.
 * @param kLen   Longitud de la clave en bytes.
 * @param mPtr   Puntero al mensaje a autenticar.
 * @param mLen   Longitud del mensaje en bytes.
 * @param macPtr Puntero al MAC esperado.
 * @param macLen Longitud del MAC esperado (debe ser 32).
 */
export function sha256_hmac_verify_raw(
  kPtr: usize,
  kLen: isize,
  mPtr: usize,
  mLen: isize,
  macPtr: usize,
  macLen: isize
): bool {
  return Sha256.hmac_verify_raw(kPtr, kLen, mPtr, mLen, macPtr, macLen)
}

// ── Hash One-Shot SHA-512 ──────────────────────────────────────────────────

/**
 * Calcula el hash SHA-512 de n bytes en mPtr y escribe los 64 bytes
 * resultantes en outPtr. Operación one-shot, 100% zero-alloc.
 *
 * @param outPtr Puntero de destino (mín. 64 bytes disponibles).
 * @param mPtr   Puntero al mensaje de entrada.
 * @param n      Longitud del mensaje en bytes.
 */
export function sha512_hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
  Sha512.hash_raw(outPtr, mPtr, n)
}

/**
 * Calcula HMAC-SHA512 con la clave kPtr[0..kLen) sobre el mensaje
 * mPtr[0..mLen) y escribe los 64 bytes resultantes en outPtr.
 *
 * @param outPtr Puntero de destino (mín. 64 bytes disponibles).
 * @param kPtr   Puntero a la clave HMAC.
 * @param kLen   Longitud de la clave en bytes.
 * @param mPtr   Puntero al mensaje a autenticar.
 * @param mLen   Longitud del mensaje en bytes.
 */
export function sha512_hmac_raw(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
  Sha512.hmac_raw(outPtr, kPtr, kLen, mPtr, mLen)
}

/**
 * Verifica un HMAC-SHA512 en tiempo constante (constant-time).
 * Compara el HMAC calculado con macPtr[0..macLen) y retorna true si coinciden,
 * false en caso contrario. Tiempo constante (sin early-exit).
 *
 * @param kPtr   Puntero a la clave HMAC.
 * @param kLen   Longitud de la clave en bytes.
 * @param mPtr   Puntero al mensaje a autenticar.
 * @param mLen   Longitud del mensaje en bytes.
 * @param macPtr Puntero al MAC esperado.
 * @param macLen Longitud del MAC esperado (debe ser 64).
 */
export function sha512_hmac_verify_raw(
  kPtr: usize,
  kLen: isize,
  mPtr: usize,
  mLen: isize,
  macPtr: usize,
  macLen: isize
): bool {
  return Sha512.hmac_verify_raw(kPtr, kLen, mPtr, mLen, macPtr, macLen)
}

// ── Contexto Streaming SHA-256 ─────────────────────────────────────────────

/**
 * Inicializa un contexto SHA-256 unmanaged de 112 bytes en ctxPtr.
 * Debe llamarse una sola vez antes de `sha256_update_raw` y `sha256_final_raw`.
 *
 * @param ctxPtr Puntero a una región de mín. 112 bytes donde se almacenará el contexto.
 */
export function sha256_create_ctx(ctxPtr: usize): void {
  const ctx = changetype<Sha256Context>(ctxPtr)
  ctx.init()
}

/**
 * Alimenta n bytes en mPtr al contexto SHA-256 ubicado en ctxPtr.
 * Puede llamarse múltiples veces para procesar datos en streaming.
 *
 * @param ctxPtr Puntero al contexto SHA-256 activo.
 * @param mPtr   Puntero al fragmento de datos a procesar.
 * @param n      Longitud del fragmento en bytes.
 */
export function sha256_update_raw(ctxPtr: usize, mPtr: usize, n: isize): void {
  const ctx = changetype<Sha256Context>(ctxPtr)
  Sha256.update(ctx, mPtr, n)
}

/**
 * Finaliza el hash SHA-256, aplica el padding estándar y escribe los
 * 32 bytes resultantes en outPtr.
 *
 * @param ctxPtr    Puntero al contexto SHA-256 activo.
 * @param paddedPtr Puntero al buffer de padding temporal (mín. 128 bytes).
 * @param outPtr    Puntero de destino para los 32 bytes del hash.
 */
export function sha256_final_raw(ctxPtr: usize, paddedPtr: usize, outPtr: usize): void {
  const ctx = changetype<Sha256Context>(ctxPtr)
  Sha256.final(ctx, paddedPtr, outPtr)
}

// ── Contexto Streaming SHA-512 ─────────────────────────────────────────────

/**
 * Inicializa un contexto SHA-512 unmanaged de 208 bytes en ctxPtr.
 * Debe llamarse una sola vez antes de `sha512_update_raw` y `sha512_final_raw`.
 *
 * @param ctxPtr Puntero a una región de mín. 208 bytes donde se almacenará el contexto.
 */
export function sha512_create_ctx(ctxPtr: usize): void {
  const ctx = changetype<Sha512Context>(ctxPtr)
  ctx.init()
}

/**
 * Alimenta n bytes en mPtr al contexto SHA-512 ubicado en ctxPtr.
 * Puede llamarse múltiples veces para procesar datos en streaming.
 *
 * @param ctxPtr Puntero al contexto SHA-512 activo.
 * @param mPtr   Puntero al fragmento de datos a procesar.
 * @param n      Longitud del fragmento en bytes.
 */
export function sha512_update_raw(ctxPtr: usize, mPtr: usize, n: isize): void {
  const ctx = changetype<Sha512Context>(ctxPtr)
  Sha512.update(ctx, mPtr, n)
}

/**
 * Finaliza el hash SHA-512, aplica el padding estándar y escribe los
 * 64 bytes resultantes en outPtr.
 *
 * @param ctxPtr    Puntero al contexto SHA-512 activo.
 * @param paddedPtr Puntero al buffer de padding temporal (mín. 256 bytes).
 * @param outPtr    Puntero de destino para los 64 bytes del hash.
 */
export function sha512_final_raw(ctxPtr: usize, paddedPtr: usize, outPtr: usize): void {
  const ctx = changetype<Sha512Context>(ctxPtr)
  Sha512.final(ctx, paddedPtr, outPtr)
}
