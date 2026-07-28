// file: bench.ts
/**
 * SHA2-WASM – Benchmark reproducible (Bun) + comparativa vs hash-wasm
 *
 * Corre con:
 *   bun run bench.ts                       # correctitud + compute + HMAC + verify
 *   bun run bench.ts <ruta-archivo>        # + I/O puro + hashFile (el caso real)
 *   bun run bench.ts <ruta-archivo> <ruta-wasm>
 *
 * Qué mide (todo con mediana de N muestras):
 *   1. CORRECTITUD     → hash y HMAC de sha2-wasm Y hash-wasm vs node:crypto (oráculo),
 *                        incluyendo HMAC verify (bytes, hex y detección de alteración).
 *   2. COMPUTE PURO    → 500 MB en RAM, sin disco (sha2-wasm vs hash-wasm).
 *   3. COMPARATIVA     → ratio sha2-wasm / hash-wasm (>1 = sha2-wasm gana).
 *   4. HMAC THROUGHPUT → HMAC-SHA256/512 one-shot sobre 256 MB (MB/s).
 *   5. HMAC VERIFY     → hmacVerify constant-time sobre payload de 1 KB (ops/s).
 *   6. I/O PURO        → lee el archivo en chunks de 64 MB SIN hashear.
 *   7. HASHFILE        → Sha256/Sha512.hashFile(Bun.file(path)) con streaming real.
 *
 * NOTA: MB = 1024*1024 (binario).
 */

import path from "node:path"
import { createHash, createHmac, pbkdf2Sync } from "node:crypto"
import { createSHA256, createSHA512, sha256 as hwSha256, sha512 as hwSha512 } from "hash-wasm"
import { Sha2Wasm, Sha256, Sha512, hexToBytes } from "../src/index"

// ── CONSTANTES ──
const MB = 1024 * 1024
const CHUNK = 64 * MB
const COMPUTE_BUF_MB = 500 // bloque de 500 MB por muestra
const COMPUTE_ITERS = 1 // 1 × 500 MB = 500 MB por muestra
const COMPUTE_SAMPLES = 5
const HASHFILE_SAMPLES = 5
const IO_SAMPLES = 2
const WARMUP = 2

// HMAC
const HMAC_BUF_MB = 256 // buffer para el throughput de HMAC
const HMAC_VERIFY_PAYLOAD = 1024 // payload pequeño para verify (debe caber en PARAM_IN)
const HMAC_SAMPLES = 5
const HMAC_OPS_ITERS = 50000 // iteraciones por muestra en el bench de verify

function verifyPbkdf2(): void {
  const password = "password"
  const salt = "salt"
  const iterations = 2048

  // Oráculo node:crypto
  const oracle256 = pbkdf2Sync(password, salt, iterations, 32, "sha256").toString("hex")
  const oracle512 = pbkdf2Sync(password, salt, iterations, 64, "sha512").toString("hex")

  const got256 = Sha256.pbkdf2(password, salt, iterations, 32)
  const got512 = Sha512.pbkdf2(password, salt, iterations, 64)

  const ok256 = got256 === oracle256
  const ok512 = got512 === oracle512
  console.log(`  ${ok256 ? "✅" : "❌"} PBKDF2-HMAC-SHA256 (2048 it, dkLen 32) == node:crypto`)
  console.log(`  ${ok512 ? "✅" : "❌"} PBKDF2-HMAC-SHA512 (2048 it, dkLen 64) == node:crypto`)
  if (!(ok256 && ok512)) throw new Error("PBKDF2 FALLÓ")
}

function benchPbkdf2(): void {
  const password = "password"
  const salt = "salt"
  const iters = 2048
  const ITERS_BENCH = 200 // derivaciones por muestra

  const run = (name: string, fn: () => unknown): void => {
    for (let w = 0; w < 2; w++) fn()
    const samples: number[] = []
    for (let r = 0; r < 5; r++) {
      const t0 = performance.now()
      for (let i = 0; i < ITERS_BENCH; i++) fn()
      samples.push(ITERS_BENCH / ((performance.now() - t0) / 1000))
    }
    const med = median(samples)
    console.log(`  ${name.padEnd(28)} mediana ${med.toFixed(0).padStart(8)} deriv/s`)
  }

  console.log(`PBKDF2 (2048 iter, dkLen 64/32):`)
  run("PBKDF2-HMAC-SHA256", () => Sha256.pbkdf2(password, salt, iters, 32, "bytes"))
  run("PBKDF2-HMAC-SHA512", () => Sha512.pbkdf2(password, salt, iters, 64, "bytes"))
}

// ── HELPERS DE ESTADÍSTICA ──

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b)
  const m = s.length >> 1
  return s.length & 1 ? s[m] : (s[m - 1] + s[m]) / 2
}

function report(label: string, samples: number[]): void {
  const med = median(samples)
  const list = samples.map((x) => x.toFixed(0)).join(", ")
  console.log(`  ${label.padEnd(22)} mediana ${med.toFixed(1).padStart(8)} MB/s   [${list}]`)
}

function reportOps(label: string, samples: number[]): void {
  const med = median(samples)
  const list = samples.map((x) => x.toFixed(0)).join(", ")
  console.log(`  ${label.padEnd(22)} mediana ${med.toFixed(0).padStart(12)} ops/s   [${list}]`)
}

// ── CARGA DEL WASM ──

async function loadWasm(p: string): Promise<Sha2Wasm> {
  const buf = await Bun.file(p).arrayBuffer()
  return Sha2Wasm.fromBuffer(buf)
}

// ── 1. CORRECTITUD ──

/** Valida el hash de sha2-wasm contra node:crypto. Aborta si falla. */
function verifyCorrectness(): void {
  const oracle = (algo: "sha256" | "sha512", input: string): string => createHash(algo).update(input).digest("hex")

  const checks: Array<[string, string, string, string]> = [
    ["SHA-256", "abc", Sha256.hash("abc"), oracle("sha256", "abc")],
    ["SHA-256", "", Sha256.hash(""), oracle("sha256", "")],
    ["SHA-512", "abc", Sha512.hash("abc"), oracle("sha512", "abc")],
    ["SHA-512", "", Sha512.hash(""), oracle("sha512", "")]
  ]

  let ok = true
  for (const [name, input, got, want] of checks) {
    const pass = got === want
    ok = ok && pass
    const shown = input === "" ? "∅ vacío" : `"${input}"`
    console.log(
      `  ${pass ? "✅" : "❌"} sha2-wasm ${name}(${shown}) ${pass ? "OK" : `FALLO\n     got : ${got}\n     want: ${want}`}`
    )
  }
  if (!ok) throw new Error("CORRECTITUD sha2-wasm FALLÓ. No se mide.")
}

/** Valida hash-wasm contra node:crypto (sanity de la comparación). */
async function verifyHashWasm(): Promise<void> {
  const oracle = (algo: "sha256" | "sha512", input: string): string => createHash(algo).update(input).digest("hex")

  const checks: Array<[string, string, string]> = [
    ["SHA-256", await hwSha256("abc"), oracle("sha256", "abc")],
    ["SHA-512", await hwSha512("abc"), oracle("sha512", "abc")]
  ]

  let ok = true
  for (const [name, got, want] of checks) {
    const pass = got === want
    ok = ok && pass
    console.log(
      `  ${pass ? "✅" : "❌"} hash-wasm ${name}("abc") ${pass ? "OK" : `FALLO\n     got : ${got}\n     want: ${want}`}`
    )
  }
  if (!ok) throw new Error("CORRECTITUD hash-wasm FALLÓ. Comparación inválida.")
}

/**
 * Valida HMAC (cálculo) y HMAC verify (constant-time) contra node:crypto.
 * Cubre: cálculo == oráculo, verify con bytes, verify con hex, y detección
 * de alteración (tamper) en SHA-256 y SHA-512. Aborta si algo falla.
 */
function verifyHmac(): void {
  const key = "clave-secreta"
  const msg = "mensaje a autenticar"

  // Oráculo HMAC (node:crypto) en hex
  const oracle256 = createHmac("sha256", key).update(msg).digest("hex")
  const oracle512 = createHmac("sha512", key).update(msg).digest("hex")

  // Cálculo con sha2-wasm (hex)
  const mac256 = Sha256.hmac(key, msg, "hex")
  const mac512 = Sha512.hmac(key, msg, "hex")

  // MAC alterados (tamper) → verify debe dar false
  const t256 = hexToBytes(mac256)
  t256[0] ^= 0xff
  const t512 = hexToBytes(mac512)
  t512[0] ^= 0xff

  const checks: Array<[string, boolean]> = [
    ["HMAC-SHA256 cálculo == node:crypto", mac256 === oracle256],
    ["HMAC-SHA512 cálculo == node:crypto", mac512 === oracle512],
    ["HMAC-SHA256 verify (bytes)", Sha256.hmacVerify(key, msg, hexToBytes(mac256)) === true],
    ["HMAC-SHA256 verify (hex)", Sha256.hmacVerify(key, msg, mac256) === true],
    ["HMAC-SHA512 verify (bytes)", Sha512.hmacVerify(key, msg, hexToBytes(mac512)) === true],
    ["HMAC-SHA512 verify (hex)", Sha512.hmacVerify(key, msg, mac512) === true],
    ["HMAC-SHA256 tamper detectado", Sha256.hmacVerify(key, msg, t256) === false],
    ["HMAC-SHA512 tamper detectado", Sha512.hmacVerify(key, msg, t512) === false]
  ]

  let ok = true
  for (const [name, pass] of checks) {
    ok = ok && pass
    console.log(`  ${pass ? "✅" : "❌"} ${name}`)
  }
  if (!ok) throw new Error("HMAC / HMAC-verify FALLÓ. No se mide.")
}

// ── 2. COMPUTE PURO (runner común para ambas libs) ──

type HasherLike = {
  reset(): void
  update(d: Uint8Array): void
  digest(...args: any[]): unknown
}

function benchComputeOne(name: string, mk: () => HasherLike, buf: Uint8Array): number[] {
  const h = mk()
  for (let w = 0; w < WARMUP; w++) {
    h.reset()
    h.update(buf)
    h.digest("bytes")
  }
  const samples: number[] = []
  for (let r = 0; r < COMPUTE_SAMPLES; r++) {
    h.reset()
    const t0 = performance.now()
    for (let i = 0; i < COMPUTE_ITERS; i++) h.update(buf)
    const t1 = performance.now()
    h.digest("bytes")
    samples.push((COMPUTE_ITERS * COMPUTE_BUF_MB) / ((t1 - t0) / 1000))
  }
  report(name, samples)
  return samples
}

async function benchCompute(
  wasm: Sha2Wasm
): Promise<{ ours: { sha256: number; sha512: number }; hw: { sha256: number; sha512: number } }> {
  const buf = new Uint8Array(COMPUTE_BUF_MB * MB)
  buf.fill(0x5a)

  console.log(`COMPUTE PURO (RAM, ${COMPUTE_BUF_MB} MB/muestra, ${COMPUTE_SAMPLES} muestras, sin I/O):`)

  const ours256 = benchComputeOne("SHA-256 sha2-wasm", () => Sha256.createHasher(wasm), buf)
  const ours512 = benchComputeOne("SHA-512 sha2-wasm", () => Sha512.createHasher(wasm), buf)

  const hw256 = await createSHA256()
  const hw512 = await createSHA512()
  const adapter256: HasherLike = {
    reset: () => void hw256.init(),
    update: (d) => void hw256.update(d),
    digest: () => hw256.digest("binary")
  }
  const adapter512: HasherLike = {
    reset: () => void hw512.init(),
    update: (d) => void hw512.update(d),
    digest: () => hw512.digest("binary")
  }
  const hwS256 = benchComputeOne("SHA-256 hash-wasm", () => adapter256, buf)
  const hwS512 = benchComputeOne("SHA-512 hash-wasm", () => adapter512, buf)

  const ours = { sha256: median(ours256), sha512: median(ours512) }
  const hw = { sha256: median(hwS256), sha512: median(hwS512) }

  console.log("─".repeat(72))
  console.log(" COMPARATIVA COMPUTE (mediana, MB/s)  ·  ratio = sha2-wasm / hash-wasm")
  console.log("─".repeat(72))
  const r256 = ours.sha256 / hw.sha256
  const r512 = ours.sha512 / hw.sha512
  console.log(
    `  SHA-256   sha2-wasm ${ours.sha256.toFixed(1).padStart(8)}   hash-wasm ${hw.sha256
      .toFixed(1)
      .padStart(8)}   ratio ${r256.toFixed(2)}x ${r256 >= 1 ? "✅" : "🔻"}`
  )
  console.log(
    `  SHA-512   sha2-wasm ${ours.sha512.toFixed(1).padStart(8)}   hash-wasm ${hw.sha512
      .toFixed(1)
      .padStart(8)}   ratio ${r512.toFixed(2)}x ${r512 >= 1 ? "✅" : "🔻"}`
  )
  console.log(`  (ratio > 1 = sha2-wasm más rápido; < 1 = hash-wasm más rápido)\n`)

  return { ours, hw }
}

// ── 4. HMAC THROUGHPUT (MB/s) ──

/**
 * Mide el throughput de HMAC one-shot sobre un buffer grande (MB/s).
 * Usa el formato "bytes" para evitar el overhead de la conversión a hex.
 * (HMAC de datos grandes va por el slow-path interno: ipad/opad + streaming.)
 */
function benchHmac(): { sha256: number; sha512: number } {
  const key = new TextEncoder().encode("benchmark-hmac-secret-key-32bytes!")
  const buf = new Uint8Array(HMAC_BUF_MB * MB)
  buf.fill(0xa5)

  const run = (name: string, fn: () => unknown): number[] => {
    for (let w = 0; w < WARMUP; w++) fn()
    const samples: number[] = []
    for (let r = 0; r < HMAC_SAMPLES; r++) {
      const t0 = performance.now()
      fn()
      const t1 = performance.now()
      samples.push(HMAC_BUF_MB / ((t1 - t0) / 1000))
    }
    report(name, samples)
    return samples
  }

  console.log(`HMAC THROUGHPUT (RAM, ${HMAC_BUF_MB} MB/muestra, one-shot "bytes"):`)
  const s256 = run("HMAC-SHA256", () => Sha256.hmac(key, buf, "bytes"))
  const s512 = run("HMAC-SHA512", () => Sha512.hmac(key, buf, "bytes"))
  console.log()
  return { sha256: median(s256), sha512: median(s512) }
}

// ── 5. HMAC VERIFY (ops/s, constant-time) ──

/**
 * Mide el rendimiento de hmacVerify (constant-time) sobre un payload pequeño,
 * en ops/s. Es el caso real de verificación (tokens/mensajes cortos).
 * El verify one-shot requiere key+payload+mac en PARAM_IN (≤ ~1 MB).
 */
function benchHmacVerify(): { sha256: number; sha512: number } {
  const key = new TextEncoder().encode("benchmark-hmac-secret-key-32bytes!")
  const payload = new Uint8Array(HMAC_VERIFY_PAYLOAD)
  payload.fill(0x3c)

  // MAC válidos precalculados (la lib ya está validada vs node:crypto en verifyHmac)
  const mac256 = Sha256.hmac(key, payload, "bytes") as Uint8Array
  const mac512 = Sha512.hmac(key, payload, "bytes") as Uint8Array

  const run = (name: string, fn: () => boolean): number[] => {
    for (let w = 0; w < WARMUP; w++) fn()
    const samples: number[] = []
    for (let r = 0; r < HMAC_SAMPLES; r++) {
      const t0 = performance.now()
      for (let i = 0; i < HMAC_OPS_ITERS; i++) fn()
      const t1 = performance.now()
      samples.push(HMAC_OPS_ITERS / ((t1 - t0) / 1000))
    }
    reportOps(name, samples)
    return samples
  }

  console.log(`HMAC VERIFY (constant-time, payload ${HMAC_VERIFY_PAYLOAD} B, ${HMAC_OPS_ITERS} ops/muestra):`)
  const s256 = run("HMAC-SHA256 verify", () => Sha256.hmacVerify(key, payload, mac256))
  const s512 = run("HMAC-SHA512 verify", () => Sha512.hmacVerify(key, payload, mac512))
  console.log()
  return { sha256: median(s256), sha512: median(s512) }
}

// ── 6. I/O PURO ──

async function benchIO(p: string): Promise<number> {
  const file = Bun.file(p)
  const total = file.size

  const readChunk = (start: number): Promise<ArrayBuffer> => {
    const end = start + CHUNK < total ? start + CHUNK : total
    return file.slice(start, end).arrayBuffer()
  }

  const samples: number[] = []
  for (let r = 0; r < IO_SAMPLES + WARMUP; r++) {
    let cursor = CHUNK < total ? CHUNK : total
    let pending = readChunk(0)
    const t0 = performance.now()
    while (true) {
      const b = await pending
      let next: Promise<ArrayBuffer> | null = null
      if (cursor < total) {
        next = readChunk(cursor)
        cursor = cursor + CHUNK < total ? cursor + CHUNK : total
      }
      void b.byteLength
      if (next === null) break
      pending = next
    }
    const secs = (performance.now() - t0) / 1000
    if (r >= WARMUP) samples.push(total / MB / secs)
  }
  report("I/O puro", samples)
  console.log()
  return median(samples)
}

// ── 7. HASHFILE REAL ──

async function benchHashFile(
  p: string,
  wasm: Sha2Wasm
): Promise<{ sha256: number; sha512: number; h256: string; h512: string }> {
  const file = Bun.file(p)

  const run = async (name: string, fn: (f: any) => Promise<string>): Promise<{ med: number; hash: string }> => {
    const samples: number[] = []
    let hash = ""
    for (let r = 0; r < HASHFILE_SAMPLES + WARMUP; r++) {
      const t0 = performance.now()
      const hex = await fn(file)
      const secs = (performance.now() - t0) / 1000
      hash = hex
      if (r >= WARMUP) samples.push(file.size / MB / secs)
    }
    report(`${name} hashFile`, samples)
    return { med: median(samples), hash }
  }

  console.log(`HASHFILE real (archivo ${(file.size / MB).toFixed(1)} MB, streaming real):`)
  const r256 = await run("SHA-256", (f) => Sha256.hashFile(f, "hex", undefined, wasm))
  const r512 = await run("SHA-512", (f) => Sha512.hashFile(f, "hex", undefined, wasm))
  console.log(`  hash SHA-256: ${r256.hash}`)
  console.log(`  hash SHA-512: ${r512.hash}\n`)
  return { sha256: r256.med, sha512: r512.med, h256: r256.hash, h512: r512.hash }
}

// ── DIAGNÓSTICO ──

function diagnose(algo: string, hashFile: number, compute: number, io: number | null): void {
  if (io === null) {
    console.log(`  ${algo.padEnd(8)} → sin archivo: solo compute medido (${compute.toFixed(0)} MB/s)`)
    console.log(`           ℹ️ pasa un archivo para medir I/O + hashFile y ver el cuello`)
    return
  }
  const ioBound = io < compute
  const floor = Math.min(io, compute)
  const ratio = hashFile / floor
  const tag = ioBound
    ? `I/O-BOUND (disco ${io.toFixed(0)} < compute ${compute.toFixed(0)} → piso ≈ ${floor.toFixed(0)} MB/s)`
    : `COMPUTE-BOUND (compute ${compute.toFixed(0)} < disco ${io.toFixed(0)} → piso ≈ ${floor.toFixed(0)} MB/s)`
  const verdict =
    ratio >= 0.9
      ? "✅ hashFile ≈ piso físico: pipeline óptimo, sin margen en JS"
      : ratio >= 0.7
        ? "🟡 hashFile algo bajo el piso: overhead leve de JS/promesas"
        : "🔴 hashFile muy bajo el piso: overhead de JS real"
  console.log(`  ${algo.padEnd(8)} hashFile/floor = ${ratio.toFixed(2)}  →  ${tag}`)
  console.log(`           ${verdict}`)
}

// ── MAIN ──

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const filePath = args[0] ?? null
  const wasmPath = args[1] ?? path.resolve(__dirname, "../dist/sha2.wasm")

  console.log("═".repeat(72))
  console.log(" SHA2-WASM BENCHMARK  ·  Bun / JavaScriptCore  ·  vs hash-wasm")
  console.log("═".repeat(72))
  console.log(`  wasm  : ${wasmPath}`)
  console.log(`  file  : ${filePath ?? "(ninguno → solo compute/HMAC)"}`)
  console.log(`  unidad: MB = 1024*1024 (binario)\n`)

  if (!Bun.file(wasmPath).size) {
    console.error(`❌ No encuentro el WASM en "${wasmPath}".`)
    process.exit(1)
  }
  const wasm = await loadWasm(wasmPath)
  console.log("WASM cargado.\n")

  verifyPbkdf2()
  benchPbkdf2()

  // 1. Correctitud (hash + hash-wasm + HMAC + HMAC-verify)
  console.log("─".repeat(72))
  console.log("CORRECTITUD (sha2-wasm + hash-wasm vs node:crypto)")
  console.log("─".repeat(72))
  verifyCorrectness()
  await verifyHashWasm()
  verifyHmac()
  console.log("  ✅ Hash, HMAC y HMAC-verify verificados.\n")

  // 2-3. Compute puro + comparativa
  console.log("─".repeat(72))
  const compute = await benchCompute(wasm)

  // 4. HMAC throughput
  console.log("─".repeat(72))
  const hmac = benchHmac()
  console.log(`  Resumen HMAC:  SHA-256 ${hmac.sha256.toFixed(1)} MB/s  ·  SHA-512 ${hmac.sha512.toFixed(1)} MB/s\n`)

  // 5. HMAC verify
  console.log("─".repeat(72))
  const verify = benchHmacVerify()
  console.log(
    `  Resumen verify: SHA-256 ${verify.sha256.toFixed(0)} ops/s  ·  SHA-512 ${verify.sha512.toFixed(0)} ops/s\n`
  )

  // 6-7. I/O + hashFile (solo si hay archivo)
  let io: number | null = null
  let hf: { sha256: number; sha512: number } | null = null
  if (filePath) {
    if (!Bun.file(filePath).size) {
      console.error(`❌ Archivo no encontrado o vacío: "${filePath}"`)
      process.exit(1)
    }
    console.log("─".repeat(72))
    io = await benchIO(filePath)
    console.log("─".repeat(72))
    hf = await benchHashFile(filePath, wasm)
  }

  // Diagnóstico
  console.log("═".repeat(72))
  console.log(" DIAGNÓSTICO  (hashFile vs piso físico = min(compute, I/O))")
  console.log("═".repeat(72))
  if (hf) {
    diagnose("SHA-256", hf.sha256, compute.ours.sha256, io)
    diagnose("SHA-512", hf.sha512, compute.ours.sha512, io)
  } else {
    diagnose("SHA-256", 0, compute.ours.sha256, null)
    diagnose("SHA-512", 0, compute.ours.sha512, null)
    console.log("\n  💡 Pasa un archivo para medir I/O + hashFile:")
    console.log("     bun run bench.ts <ruta-archivo>")
  }
  console.log("═".repeat(72))
}

main().catch((e) => {
  console.error("\n💥 bench falló:", e)
  process.exit(1)
})
