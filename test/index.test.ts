import { describe, test, expect, beforeAll } from "bun:test"
import fs from "node:fs"
import path from "node:path"
import { Sha2Wasm, Sha256, Sha512, HMAC, Sha256Hasher, Sha512Hasher, bytesToHex, hexToBytes } from "../src/index"

describe("SHA2-WASM Correctness Test Suite", () => {
  let wasm: Sha2Wasm

  beforeAll(async () => {
    const wasmPath = path.join(import.meta.dir, "../dist/sha2.wasm")
    const wasmBuffer = fs.readFileSync(wasmPath)
    wasm = await Sha2Wasm.fromBuffer(wasmBuffer)
  })

  test("1. Cargar WASM desde búfer local", () => {
    expect(wasm).toBeDefined()
    expect(wasm.memory).toBeDefined()
  })

  // ── NIST FIPS 180-4 SHA-256 Test Vectors ──────────────────────────────────
  test("2. Vectores de prueba NIST SHA-256", () => {
    // Vector 1: cadena vacía ""
    expect(Sha256.hash("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    // Vector 2: "abc"
    expect(Sha256.hash("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    // Vector 3: NIST FIPS 180-4 §B.3 (448-bit message)
    expect(Sha256.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopq")).toBe(
      "05d04bc63888c9dcebd92f74f280620ea15b67327162cbf6bdee25061023a3e6"
    )
  })

  // ── NIST FIPS 180-4 SHA-512 Test Vectors ──────────────────────────────────
  test("3. Vectores de prueba NIST SHA-512", () => {
    // Vector 1: cadena vacía ""
    expect(Sha512.hash("")).toBe(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    )

    // Vector 2: "abc"
    expect(Sha512.hash("abc")).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )

    // Vector 3: 512-bit message (NIST §B.3)
    expect(Sha512.hash("abcdefghbcdefghiabcdefghbcdefghiabcdefghbcdefghiabcdefghbcdefghi")).toBe(
      "6df6b70e6921bfbd665e77acb8e90e83dfeafa4ced6e0c4fb6967b7828dbc4fe485ffc70db580fd023b7eff79ce7cdcf8464bbd4b2ae15479be2bb34a80d32de"
    )
  })

  // ── RFC 4231 HMAC Test Vectors ─────────────────────────────────────────────
  test("4. HMAC-SHA256 – Vectores RFC 4231 (Test Case 1)", () => {
    const key = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    const expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

    // API estática
    expect(Sha256.hmac(key, "Hi There")).toBe(expected)

    // API orientada a objetos
    expect(new HMAC(key, "SHA256").digest("Hi There")).toBe(expected)
  })

  test("5. HMAC-SHA512 – Vectores RFC 4231 (Test Case 1)", () => {
    const key = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    const expected =
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"

    // API estática
    expect(Sha512.hmac(key, "Hi There")).toBe(expected)

    // API orientada a objetos
    expect(new HMAC(key, "SHA512").digest("Hi There")).toBe(expected)
  })

  // ── Streaming Hasher API ───────────────────────────────────────────────────
  test("6. Hashing incremental en streaming (Sha256Hasher y Sha512Hasher)", () => {
    // SHA-256: procesar en 3 fragmentos y comparar contra one-shot
    const input256 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopq"
    const chunk1 = "abcdbcdecdef"
    const chunk2 = "defgefghfghi"
    const chunk3 = "ghijhijkijkljklmklmnlmnomnopq"

    const hasher256 = new Sha256Hasher(wasm)
    hasher256.update(chunk1).update(chunk2).update(chunk3)
    expect(hasher256.digest("hex")).toBe(Sha256.hash(input256))

    // SHA-512: procesar en 4 fragmentos y comparar contra one-shot
    const input512 = "abcdefghbcdefghiabcdefghbcdefghiabcdefghbcdefghiabcdefghbcdefghi"
    const hasher512 = new Sha512Hasher(wasm)
    hasher512
      .update("abcdefghbcdefghi")
      .update("abcdefghbcdefghi")
      .update("abcdefghbcdefghi")
      .update("abcdefghbcdefghi")
    expect(hasher512.digest("hex")).toBe(Sha512.hash(input512))
  })

  // ── Formato de Salida ──────────────────────────────────────────────────────
  test("7. Formato de salida Uint8Array ('bytes')", () => {
    // SHA-256 como bytes
    const bytes256 = Sha256.hash("abc", "bytes")
    expect(bytes256).toBeInstanceOf(Uint8Array)
    expect(bytes256.length).toBe(32)
    expect(bytesToHex(bytes256)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    // SHA-512 como bytes
    const bytes512 = Sha512.hash("abc", "bytes")
    expect(bytes512).toBeInstanceOf(Uint8Array)
    expect(bytes512.length).toBe(64)
    expect(bytesToHex(bytes512)).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
  })

  // ── Reutilización con .reset() ─────────────────────────────────────────────
  test("8. Reutilización de Hasher mediante reset()", () => {
    const hasher = new Sha256Hasher(wasm)
    hasher.update("primera llamada")
    const hash1 = hasher.digest("hex")

    hasher.reset()
    hasher.update("segunda llamada con el mismo hasher")
    const hash2 = hasher.digest("hex")

    expect(hash1).toBe(Sha256.hash("primera llamada"))
    expect(hash2).toBe(Sha256.hash("segunda llamada con el mismo hasher"))
  })

  // ── HMAC Streaming Fallback (> 1 MB) ───────────────────────────────────────
  test("9. HMAC con datos de gran tamaño (> 1 MB zero-alloc fallback)", () => {
    const largeData = new Uint8Array(1500000).fill(0x61) // 1.5 MB de 'a'
    const key = "clave-secreta-hmac"

    const hmac256 = Sha256.hmac(key, largeData)
    expect(hmac256).toBeDefined()
    expect(hmac256.length).toBe(64)

    const hmac512 = Sha512.hmac(key, largeData)
    expect(hmac512).toBeDefined()
    expect(hmac512.length).toBe(128)
  })
})
