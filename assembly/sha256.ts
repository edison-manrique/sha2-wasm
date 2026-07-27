import { SHA256_K, SHA256_IV } from "./constants"
import { CRYPTO_WORK_PTR, align8 } from "./memory"
// prettier-ignore
import {
  store32_be,
  sigma0_256,
  sigma1_256,
  Sigma0_256,
  Sigma1_256,
  Ch32,
  Maj32
} from "./common"

/**
 * Contexto SHA256 unmanaged (112 bytes exactos).
 * Funciona como una estructura de C sobre un puntero usize.
 * Cero costo de asignación en Heap / GC.
 */
@unmanaged
export class Sha256Context {
  static readonly SIZE: usize = 112

  @inline get statePtr(): usize {
    return changetype<usize>(this)
  }
  @inline get bufferPtr(): usize {
    return changetype<usize>(this) + 32
  }

  @inline
  getTotalLen(): u64 {
    return load<u64>(changetype<usize>(this) + 96)
  }

  @inline
  setTotalLen(val: u64): void {
    store<u64>(changetype<usize>(this) + 96, val)
  }

  @inline
  getBufferLen(): u32 {
    return load<u32>(changetype<usize>(this) + 104)
  }

  @inline
  setBufferLen(val: u32): void {
    store<u32>(changetype<usize>(this) + 104, val)
  }

  @inline
  init(): void {
    const st = this.statePtr
    store<u64>(st + 0, unchecked(SHA256_IV[0]))
    store<u64>(st + 8, unchecked(SHA256_IV[1]))
    store<u64>(st + 16, unchecked(SHA256_IV[2]))
    store<u64>(st + 24, unchecked(SHA256_IV[3]))
    this.setTotalLen(0)
    this.setBufferLen(0)
  }
}

export class Sha256 {
  /**
   * Bucle de compresión interno sobre bloques de 64 bytes.
   */
  static compress(stPtr: usize, mPtr: usize, n: isize): isize {
    let h0 = load<u32>(stPtr + 0)
    let h1 = load<u32>(stPtr + 4)
    let h2 = load<u32>(stPtr + 8)
    let h3 = load<u32>(stPtr + 12)
    let h4 = load<u32>(stPtr + 16)
    let h5 = load<u32>(stPtr + 20)
    let h6 = load<u32>(stPtr + 24)
    let h7 = load<u32>(stPtr + 28)

    let pos: usize = 0

    while (n >= 64) {
      let a = h0,
        b = h1,
        c = h2,
        d = h3
      let e = h4,
        f = h5,
        g = h6,
        h = h7

      let w0 = bswap(load<u32>(mPtr + pos + 0))
      h += Sigma1_256(e) + Ch32(e, f, g) + 0x428a2f98 + w0
      d += h
      h += Sigma0_256(a) + Maj32(a, b, c)
      let w1 = bswap(load<u32>(mPtr + pos + 4))
      g += Sigma1_256(d) + Ch32(d, e, f) + 0x71374491 + w1
      c += g
      g += Sigma0_256(h) + Maj32(h, a, b)
      let w2 = bswap(load<u32>(mPtr + pos + 8))
      f += Sigma1_256(c) + Ch32(c, d, e) + 0xb5c0fbcf + w2
      b += f
      f += Sigma0_256(g) + Maj32(g, h, a)
      let w3 = bswap(load<u32>(mPtr + pos + 12))
      e += Sigma1_256(b) + Ch32(b, c, d) + 0xe9b5dba5 + w3
      a += e
      e += Sigma0_256(f) + Maj32(f, g, h)
      let w4 = bswap(load<u32>(mPtr + pos + 16))
      d += Sigma1_256(a) + Ch32(a, b, c) + 0x3956c25b + w4
      h += d
      d += Sigma0_256(e) + Maj32(e, f, g)
      let w5 = bswap(load<u32>(mPtr + pos + 20))
      c += Sigma1_256(h) + Ch32(h, a, b) + 0x59f111f1 + w5
      g += c
      c += Sigma0_256(d) + Maj32(d, e, f)
      let w6 = bswap(load<u32>(mPtr + pos + 24))
      b += Sigma1_256(g) + Ch32(g, h, a) + 0x923f82a4 + w6
      f += b
      b += Sigma0_256(c) + Maj32(c, d, e)
      let w7 = bswap(load<u32>(mPtr + pos + 28))
      a += Sigma1_256(f) + Ch32(f, g, h) + 0xab1c5ed5 + w7
      e += a
      a += Sigma0_256(b) + Maj32(b, c, d)
      let w8 = bswap(load<u32>(mPtr + pos + 32))
      h += Sigma1_256(e) + Ch32(e, f, g) + 0xd807aa98 + w8
      d += h
      h += Sigma0_256(a) + Maj32(a, b, c)
      let w9 = bswap(load<u32>(mPtr + pos + 36))
      g += Sigma1_256(d) + Ch32(d, e, f) + 0x12835b01 + w9
      c += g
      g += Sigma0_256(h) + Maj32(h, a, b)
      let w10 = bswap(load<u32>(mPtr + pos + 40))
      f += Sigma1_256(c) + Ch32(c, d, e) + 0x243185be + w10
      b += f
      f += Sigma0_256(g) + Maj32(g, h, a)
      let w11 = bswap(load<u32>(mPtr + pos + 44))
      e += Sigma1_256(b) + Ch32(b, c, d) + 0x550c7dc3 + w11
      a += e
      e += Sigma0_256(f) + Maj32(f, g, h)
      let w12 = bswap(load<u32>(mPtr + pos + 48))
      d += Sigma1_256(a) + Ch32(a, b, c) + 0x72be5d74 + w12
      h += d
      d += Sigma0_256(e) + Maj32(e, f, g)
      let w13 = bswap(load<u32>(mPtr + pos + 52))
      c += Sigma1_256(h) + Ch32(h, a, b) + 0x80deb1fe + w13
      g += c
      c += Sigma0_256(d) + Maj32(d, e, f)
      let w14 = bswap(load<u32>(mPtr + pos + 56))
      b += Sigma1_256(g) + Ch32(g, h, a) + 0x9bdc06a7 + w14
      f += b
      b += Sigma0_256(c) + Maj32(c, d, e)
      let w15 = bswap(load<u32>(mPtr + pos + 60))
      a += Sigma1_256(f) + Ch32(f, g, h) + 0xc19bf174 + w15
      e += a
      a += Sigma0_256(b) + Maj32(b, c, d)

      for (let i = 16; i < 64; i += 16) {
        let kPtr = changetype<usize>(SHA256_K) + (i << 2)

        w0 += sigma1_256(w14) + w9 + sigma0_256(w1)
        h += Sigma1_256(e) + Ch32(e, f, g) + load<u32>(kPtr + 0) + w0
        d += h
        h += Sigma0_256(a) + Maj32(a, b, c)
        w1 += sigma1_256(w15) + w10 + sigma0_256(w2)
        g += Sigma1_256(d) + Ch32(d, e, f) + load<u32>(kPtr + 4) + w1
        c += g
        g += Sigma0_256(h) + Maj32(h, a, b)
        w2 += sigma1_256(w0) + w11 + sigma0_256(w3)
        f += Sigma1_256(c) + Ch32(c, d, e) + load<u32>(kPtr + 8) + w2
        b += f
        f += Sigma0_256(g) + Maj32(g, h, a)
        w3 += sigma1_256(w1) + w12 + sigma0_256(w4)
        e += Sigma1_256(b) + Ch32(b, c, d) + load<u32>(kPtr + 12) + w3
        a += e
        e += Sigma0_256(f) + Maj32(f, g, h)
        w4 += sigma1_256(w2) + w13 + sigma0_256(w5)
        d += Sigma1_256(a) + Ch32(a, b, c) + load<u32>(kPtr + 16) + w4
        h += d
        d += Sigma0_256(e) + Maj32(e, f, g)
        w5 += sigma1_256(w3) + w14 + sigma0_256(w6)
        c += Sigma1_256(h) + Ch32(h, a, b) + load<u32>(kPtr + 20) + w5
        g += c
        c += Sigma0_256(d) + Maj32(d, e, f)
        w6 += sigma1_256(w4) + w15 + sigma0_256(w7)
        b += Sigma1_256(g) + Ch32(g, h, a) + load<u32>(kPtr + 24) + w6
        f += b
        b += Sigma0_256(c) + Maj32(c, d, e)
        w7 += sigma1_256(w5) + w0 + sigma0_256(w8)
        a += Sigma1_256(f) + Ch32(f, g, h) + load<u32>(kPtr + 28) + w7
        e += a
        a += Sigma0_256(b) + Maj32(b, c, d)

        w8 += sigma1_256(w6) + w1 + sigma0_256(w9)
        h += Sigma1_256(e) + Ch32(e, f, g) + load<u32>(kPtr + 32) + w8
        d += h
        h += Sigma0_256(a) + Maj32(a, b, c)
        w9 += sigma1_256(w7) + w2 + sigma0_256(w10)
        g += Sigma1_256(d) + Ch32(d, e, f) + load<u32>(kPtr + 36) + w9
        c += g
        g += Sigma0_256(h) + Maj32(h, a, b)
        w10 += sigma1_256(w8) + w3 + sigma0_256(w11)
        f += Sigma1_256(c) + Ch32(c, d, e) + load<u32>(kPtr + 40) + w10
        b += f
        f += Sigma0_256(g) + Maj32(g, h, a)
        w11 += sigma1_256(w9) + w4 + sigma0_256(w12)
        e += Sigma1_256(b) + Ch32(b, c, d) + load<u32>(kPtr + 44) + w11
        a += e
        e += Sigma0_256(f) + Maj32(f, g, h)
        w12 += sigma1_256(w10) + w5 + sigma0_256(w13)
        d += Sigma1_256(a) + Ch32(a, b, c) + load<u32>(kPtr + 48) + w12
        h += d
        d += Sigma0_256(e) + Maj32(e, f, g)
        w13 += sigma1_256(w11) + w6 + sigma0_256(w14)
        c += Sigma1_256(h) + Ch32(h, a, b) + load<u32>(kPtr + 52) + w13
        g += c
        c += Sigma0_256(d) + Maj32(d, e, f)
        w14 += sigma1_256(w12) + w7 + sigma0_256(w15)
        b += Sigma1_256(g) + Ch32(g, h, a) + load<u32>(kPtr + 56) + w14
        f += b
        b += Sigma0_256(c) + Maj32(c, d, e)
        w15 += sigma1_256(w13) + w8 + sigma0_256(w0)
        a += Sigma1_256(f) + Ch32(f, g, h) + load<u32>(kPtr + 60) + w15
        e += a
        a += Sigma0_256(b) + Maj32(b, c, d)
      }

      h0 += a
      h1 += b
      h2 += c
      h3 += d
      h4 += e
      h5 += f
      h6 += g
      h7 += h
      pos += 64
      n -= 64
    }

    store<u32>(stPtr + 0, h0)
    store<u32>(stPtr + 4, h1)
    store<u32>(stPtr + 8, h2)
    store<u32>(stPtr + 12, h3)
    store<u32>(stPtr + 16, h4)
    store<u32>(stPtr + 20, h5)
    store<u32>(stPtr + 24, h6)
    store<u32>(stPtr + 28, h7)

    return n
  }

  /**
   * Procesa streaming de datos actualizando el estado en el contexto.
   */
  static update(ctx: Sha256Context, mPtr: usize, n: isize): void {
    if (n <= 0) return

    ctx.setTotalLen(ctx.getTotalLen() + <u64>n)
    let r = ctx.getBufferLen()
    let pos: isize = 0
    const stPtr = ctx.statePtr
    const bufPtr = ctx.bufferPtr

    if (r > 0) {
      let copiable = min(n, 64 - <isize>r)
      memory.copy(bufPtr + r, mPtr, copiable)
      r += <u32>copiable
      n -= copiable
      pos += copiable
      if (r === 64) {
        Sha256.compress(stPtr, bufPtr, 64)
        r = 0
      }
    }

    if (n >= 64) {
      let blocks_len = n & ~63
      Sha256.compress(stPtr, mPtr + pos, blocks_len)
      pos += blocks_len
      n -= blocks_len
    }

    if (n > 0) {
      memory.copy(bufPtr, mPtr + pos, n)
      r = <u32>n
    }

    ctx.setBufferLen(r)
  }

  /**
   * Finaliza el cálculo del hash e inyecta los 32 bytes resultantes en outPtr.
   */
  static final(ctx: Sha256Context, paddedPtr: usize, outPtr: usize): void {
    const r = ctx.getBufferLen()
    const t = ctx.getTotalLen()
    const stPtr = ctx.statePtr
    const bufPtr = ctx.bufferPtr

    memory.copy(paddedPtr, bufPtr, r)
    store<u8>(paddedPtr + r, 0x80)

    if (r < 56) {
      memory.fill(paddedPtr + r + 1, 0, 64 - r - 1)
      store32_be(paddedPtr + 64 - 8, <u32>((t << 3) >> 32))
      store32_be(paddedPtr + 64 - 4, <u32>(t << 3))
      Sha256.compress(stPtr, paddedPtr, 64)
    } else {
      memory.fill(paddedPtr + r + 1, 0, 128 - r - 1)
      store32_be(paddedPtr + 128 - 8, <u32>((t << 3) >> 32))
      store32_be(paddedPtr + 128 - 4, <u32>(t << 3))
      Sha256.compress(stPtr, paddedPtr, 128)
    }

    store32_be(outPtr + 0, load<u32>(stPtr + 0))
    store32_be(outPtr + 4, load<u32>(stPtr + 4))
    store32_be(outPtr + 8, load<u32>(stPtr + 8))
    store32_be(outPtr + 12, load<u32>(stPtr + 12))
    store32_be(outPtr + 16, load<u32>(stPtr + 16))
    store32_be(outPtr + 20, load<u32>(stPtr + 20))
    store32_be(outPtr + 24, load<u32>(stPtr + 24))
    store32_be(outPtr + 28, load<u32>(stPtr + 28))
  }

  /**
   * SHA256 Hash One-Shot (100% Zero-Alloc)
   * Escribe el Hash directamente en outPtr.
   */
  static hash_raw(outPtr: usize, mPtr: usize, n: isize): void {
    const scratchPtr = align8(CRYPTO_WORK_PTR)
    const ctx = changetype<Sha256Context>(scratchPtr)
    const paddedPtr = align8(scratchPtr + Sha256Context.SIZE)

    ctx.init()
    Sha256.update(ctx, mPtr, n)
    Sha256.final(ctx, paddedPtr, outPtr)
  }

  /**
   * HMAC-SHA256 (100% Zero-Alloc)
   * Escribe el resultado directamente en outPtr.
   */
  static hmac_raw(outPtr: usize, kPtr: usize, kLen: isize, mPtr: usize, mLen: isize): void {
    const scratchPtr = align8(CRYPTO_WORK_PTR)
    const k_buf = scratchPtr // 64 bytes
    const b = align8(k_buf + 64) // 64 bytes
    const ctx = changetype<Sha256Context>(align8(b + 64)) // 112 bytes
    const padded = align8(changetype<usize>(ctx) + Sha256Context.SIZE) // 128 bytes

    memory.fill(k_buf, 0, 64)
    if (kLen > 64) {
      Sha256.hash_raw(k_buf, kPtr, kLen)
      kLen = 32
    } else if (kLen > 0) {
      memory.copy(k_buf, kPtr, kLen)
    }

    // Inner Hash
    for (let i = 0; i < 64; i++) {
      store<u8>(b + i, load<u8>(k_buf + i) ^ 0x36)
    }

    ctx.init()
    Sha256.update(ctx, b, 64)
    Sha256.update(ctx, mPtr, mLen)
    Sha256.final(ctx, padded, outPtr)

    // Outer Hash
    for (let i = 0; i < 64; i++) {
      store<u8>(b + i, load<u8>(k_buf + i) ^ 0x5c)
    }

    ctx.init()
    Sha256.update(ctx, b, 64)
    Sha256.update(ctx, outPtr, 32)
    Sha256.final(ctx, padded, outPtr)
  }
}
