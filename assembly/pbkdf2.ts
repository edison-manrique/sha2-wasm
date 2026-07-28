// file: assembly/pbkdf2.ts
import { CRYPTO_WORK_PTR, align8 } from "./memory"
import { Sha256, Sha256Context } from "./sha256"
import { Sha512, Sha512Context } from "./sha512"

/**
 * PBKDF2 (RFC 8018) sobre HMAC-SHA256 / HMAC-SHA512.
 *
 * Zero-alloc: todos los buffers viven en el scratchpad estático (CRYPTO_WORK_PTR),
 * con un layout fijo calculado en tiempo de compilación.
 *
 * Optimización clave: los estados ipad/opad se precomputan UNA sola vez por clave
 * (no por iteración), ahorrando ~2 compresiones por iteración vs un HMAC naive.
 *
 * Nota: BLOCK/HASH se declaran como literales i32 locales (autocontenidos) para
 * evitar conversiones isize↔i32 (warnings AS201) y no depender de constants.ts.
 */
export class Pbkdf2 {
  // ═══════════════════════════════════════════════════════════════════════
  //  PBKDF2-HMAC-SHA256
  // ═══════════════════════════════════════════════════════════════════════

  static sha256_raw(
    outPtr: usize,
    passwordPtr: usize,
    passwordLen: i32,
    saltPtr: usize,
    saltLen: i32,
    iterations: i32,
    dkLen: i32
  ): void {
    const BLOCK: i32 = 64 // tamaño de bloque SHA-256
    const HASH: i32 = 32 // longitud del digest SHA-256
    const CTX = Sha256Context.SIZE // usize (112); solo se suma a punteros
    const PADDED: i32 = 128 // buffer de padding

    // Layout fijo del scratch (offsets múltiplos de 8 → alineados)
    const scratch = align8(CRYPTO_WORK_PTR)
    const ipadState = scratch // estado ipad precomputado
    const opadState = ipadState + CTX // estado opad precomputado
    const stInner = opadState + CTX // estado de trabajo inner
    const stOuter = stInner + CTX // estado de trabajo outer
    const padded = stOuter + CTX // buffer de padding
    const ipad = padded + PADDED // bloque key^0x36
    const opad = ipad + BLOCK // bloque key^0x5c
    const U = opad + BLOCK // U de la iteración
    const T = U + HASH // acumulador XOR
    const outHMAC = T + HASH // salida del HMAC
    const saltBlock = outHMAC + HASH // salt || INT_32_BE

    // 1. Clave: si password > BLOCK, hashearla (reusa stInner/padded → outHMAC)
    let keyPtr: usize
    let keyLen: i32
    if (passwordLen > BLOCK) {
      const ctx = changetype<Sha256Context>(stInner)
      ctx.init()
      Sha256.update(ctx, passwordPtr, passwordLen)
      Sha256.final(ctx, padded, outHMAC)
      keyPtr = outHMAC
      keyLen = HASH
    } else {
      keyPtr = passwordPtr
      keyLen = passwordLen
    }

    // 2. Bloques ipad/opad
    for (let i: i32 = 0; i < BLOCK; i++) {
      const k: u8 = i < keyLen ? load<u8>(keyPtr + i) : 0
      store<u8>(ipad + i, k ^ 0x36)
      store<u8>(opad + i, k ^ 0x5c)
    }

    // 3. Precomputar estados ipad/opad (UNA sola vez)
    const ipadCtx = changetype<Sha256Context>(ipadState)
    ipadCtx.init()
    Sha256.update(ipadCtx, ipad, BLOCK)
    const opadCtx = changetype<Sha256Context>(opadState)
    opadCtx.init()
    Sha256.update(opadCtx, opad, BLOCK)

    // 4. Bloques F() de PBKDF2
    const numBlocks: i32 = (dkLen + HASH - 1) / HASH
    memory.copy(saltBlock, saltPtr, saltLen)

    for (let blockIdx: i32 = 1; blockIdx <= numBlocks; blockIdx++) {
      // saltBlock = salt || INT_32_BE(blockIdx)
      const idxOff: i32 = saltLen
      store<u8>(saltBlock + idxOff + 0, <u8>((blockIdx >>> 24) & 0xff))
      store<u8>(saltBlock + idxOff + 1, <u8>((blockIdx >>> 16) & 0xff))
      store<u8>(saltBlock + idxOff + 2, <u8>((blockIdx >>> 8) & 0xff))
      store<u8>(saltBlock + idxOff + 3, <u8>(blockIdx & 0xff))

      // U_1 = HMAC(ipad/opad precomputados, salt || INT)
      Pbkdf2.hmacPre256(ipadState, opadState, saltBlock, saltLen + 4, outHMAC, stInner, stOuter, padded)
      memory.copy(T, outHMAC, HASH)
      memory.copy(U, outHMAC, HASH)

      // U_2 .. U_iterations  →  T ^= U_i
      for (let iter: i32 = 1; iter < iterations; iter++) {
        Pbkdf2.hmacPre256(ipadState, opadState, U, HASH, outHMAC, stInner, stOuter, padded)
        memory.copy(U, outHMAC, HASH)
        for (let j: i32 = 0; j < HASH; j += 8) {
          store<u64>(T + j, load<u64>(T + j) ^ load<u64>(U + j))
        }
      }

      const offset: i32 = (blockIdx - 1) * HASH
      const copyLen: i32 = min<i32>(HASH, dkLen - offset)
      memory.copy(outPtr + offset, T, copyLen)
    }
  }

  /** HMAC-SHA256 con estados ipad/opad precomputados (zero-alloc). */
  private static hmacPre256(
    ipadState: usize,
    opadState: usize,
    msgPtr: usize,
    msgLen: i32,
    outPtr: usize,
    stI: usize,
    stO: usize,
    padded: usize
  ): void {
    const CTX = Sha256Context.SIZE
    // Inner: H(ipad || msg)
    memory.copy(stI, ipadState, CTX)
    const ctxI = changetype<Sha256Context>(stI)
    Sha256.update(ctxI, msgPtr, msgLen)
    Sha256.final(ctxI, padded, outPtr)
    // Outer: H(opad || innerHash)   (32 = longitud del digest SHA-256)
    memory.copy(stO, opadState, CTX)
    const ctxO = changetype<Sha256Context>(stO)
    Sha256.update(ctxO, outPtr, 32)
    Sha256.final(ctxO, padded, outPtr)
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  PBKDF2-HMAC-SHA512
  // ═══════════════════════════════════════════════════════════════════════

  static sha512_raw(
    outPtr: usize,
    passwordPtr: usize,
    passwordLen: i32,
    saltPtr: usize,
    saltLen: i32,
    iterations: i32,
    dkLen: i32
  ): void {
    const BLOCK: i32 = 128 // tamaño de bloque SHA-512
    const HASH: i32 = 64 // longitud del digest SHA-512
    const CTX = Sha512Context.SIZE // usize (208); solo se suma a punteros
    const PADDED: i32 = 256 // buffer de padding

    // Layout fijo del scratch (offsets múltiplos de 8 → alineados)
    const scratch = align8(CRYPTO_WORK_PTR)
    const ipadState = scratch
    const opadState = ipadState + CTX
    const stInner = opadState + CTX
    const stOuter = stInner + CTX
    const padded = stOuter + CTX
    const ipad = padded + PADDED
    const opad = ipad + BLOCK
    const U = opad + BLOCK
    const T = U + HASH
    const outHMAC = T + HASH
    const saltBlock = outHMAC + HASH

    // 1. Clave: si password > BLOCK, hashearla (reusa stInner/padded → outHMAC)
    let keyPtr: usize
    let keyLen: i32
    if (passwordLen > BLOCK) {
      const ctx = changetype<Sha512Context>(stInner)
      ctx.init()
      Sha512.update(ctx, passwordPtr, passwordLen)
      Sha512.final(ctx, padded, outHMAC)
      keyPtr = outHMAC
      keyLen = HASH
    } else {
      keyPtr = passwordPtr
      keyLen = passwordLen
    }

    // 2. Bloques ipad/opad
    for (let i: i32 = 0; i < BLOCK; i++) {
      const k: u8 = i < keyLen ? load<u8>(keyPtr + i) : 0
      store<u8>(ipad + i, k ^ 0x36)
      store<u8>(opad + i, k ^ 0x5c)
    }

    // 3. Precomputar estados ipad/opad (UNA sola vez)
    const ipadCtx = changetype<Sha512Context>(ipadState)
    ipadCtx.init()
    Sha512.update(ipadCtx, ipad, BLOCK)
    const opadCtx = changetype<Sha512Context>(opadState)
    opadCtx.init()
    Sha512.update(opadCtx, opad, BLOCK)

    // 4. Bloques F() de PBKDF2
    const numBlocks: i32 = (dkLen + HASH - 1) / HASH
    memory.copy(saltBlock, saltPtr, saltLen)

    for (let blockIdx: i32 = 1; blockIdx <= numBlocks; blockIdx++) {
      // saltBlock = salt || INT_32_BE(blockIdx)
      const idxOff: i32 = saltLen
      store<u8>(saltBlock + idxOff + 0, <u8>((blockIdx >>> 24) & 0xff))
      store<u8>(saltBlock + idxOff + 1, <u8>((blockIdx >>> 16) & 0xff))
      store<u8>(saltBlock + idxOff + 2, <u8>((blockIdx >>> 8) & 0xff))
      store<u8>(saltBlock + idxOff + 3, <u8>(blockIdx & 0xff))

      // U_1 = HMAC(ipad/opad precomputados, salt || INT)
      Pbkdf2.hmacPre512(ipadState, opadState, saltBlock, saltLen + 4, outHMAC, stInner, stOuter, padded)
      memory.copy(T, outHMAC, HASH)
      memory.copy(U, outHMAC, HASH)

      // U_2 .. U_iterations  →  T ^= U_i
      for (let iter: i32 = 1; iter < iterations; iter++) {
        Pbkdf2.hmacPre512(ipadState, opadState, U, HASH, outHMAC, stInner, stOuter, padded)
        memory.copy(U, outHMAC, HASH)
        for (let j: i32 = 0; j < HASH; j += 8) {
          store<u64>(T + j, load<u64>(T + j) ^ load<u64>(U + j))
        }
      }

      const offset: i32 = (blockIdx - 1) * HASH
      const copyLen: i32 = min<i32>(HASH, dkLen - offset)
      memory.copy(outPtr + offset, T, copyLen)
    }
  }

  /** HMAC-SHA512 con estados ipad/opad precomputados (zero-alloc). */
  private static hmacPre512(
    ipadState: usize,
    opadState: usize,
    msgPtr: usize,
    msgLen: i32,
    outPtr: usize,
    stI: usize,
    stO: usize,
    padded: usize
  ): void {
    const CTX = Sha512Context.SIZE
    // Inner: H(ipad || msg)
    memory.copy(stI, ipadState, CTX)
    const ctxI = changetype<Sha512Context>(stI)
    Sha512.update(ctxI, msgPtr, msgLen)
    Sha512.final(ctxI, padded, outPtr)
    // Outer: H(opad || innerHash)   (64 = longitud del digest SHA-512)
    memory.copy(stO, opadState, CTX)
    const ctxO = changetype<Sha512Context>(stO)
    Sha512.update(ctxO, outPtr, 64)
    Sha512.final(ctxO, padded, outPtr)
  }
}
