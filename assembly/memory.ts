/**
 * Reservado estático en el Data Segment de WASM en TIEMPO DE COMPILACIÓN.
 * Zero alloc en runtime, 0 llamadas al heap, protegido contra colisiones por el linker.
 */
export const PARAM_IN_SIZE: usize   = 1048576               // 1 MB buffer para I/O masivo de alta velocidad
export const PARAM_OUT_SIZE: usize  = 8192                  // 8 KB buffer de salida
export const WORK_SIZE: usize       = 32768                 // 32 KB zona de contextos criptográficos

export const SCRATCH_SIZE: usize = PARAM_IN_SIZE + PARAM_OUT_SIZE + WORK_SIZE // ~1.08 MB
export const SCRATCH_PTR: usize = memory.data(<i32>SCRATCH_SIZE)

// Zonas de I/O de la aplicación (Mapeadas a múltiplos de 8 bytes)
export const PARAM_IN_PTR: usize    = SCRATCH_PTR
export const PARAM_OUT_PTR: usize   = SCRATCH_PTR + PARAM_IN_SIZE
export const CRYPTO_WORK_PTR: usize = PARAM_OUT_PTR + PARAM_OUT_SIZE

/**
 * Helper de alineación estricta a 8 bytes en inline.
 * Redondea cualquier puntero al siguiente múltiplo de 8.
 */
// @ts-ignore
// prettier-ignore
@inline
export function align8(ptr: usize): usize {
  return (ptr + 7) & ~7
}