// file: bench.ts
/**
 * SHA2-WASM – Benchmark reproducible (Bun) + comparativa vs hash-wasm
 *
 * Corre con:
 *   bun run bench.ts                       # correctitud + compute (sha2-wasm vs hash-wasm)
 *   bun run bench.ts <ruta-archivo>        # + I/O puro + hashFile (el caso real)
 *   bun run bench.ts <ruta-archivo> <ruta-wasm>
 *
 * Qué mide (todo con mediana de N muestras, bloques de 500 MB):
 *   1. CORRECTITUD   → sha2-wasm Y hash-wasm de "abc"/"" vs node:crypto (oráculo).
 *   2. COMPUTE PURO  → 500 MB en RAM, sin disco. Para sha2-wasm y hash-wasm.
 *   3. COMPARATIVA   → ratio sha2-wasm / hash-wasm (>1 = sha2-wasm gana).
 *   4. I/O PURO      → lee el archivo en chunks de 64 MB SIN hashear.
 *   5. HASHFILE      → Sha256/Sha512.hashFile(Bun.file(path)) con double-buffer.
 *
 * NOTA: MB = 1024*1024 (binario).
 */

import { createHash } from "node:crypto"
import path from "node:path"
import { createSHA256, createSHA512, sha256 as hwSha256, sha512 as hwSha512 } from "hash-wasm"
import { Sha2Wasm, Sha256, Sha512 } from "../src/index"

// ── CONSTANTES ──
const MB = 1024 * 1024
const CHUNK = 64 * MB
const COMPUTE_BUF_MB = 500 // bloque de 500 MB por muestra
const COMPUTE_ITERS = 1 // 1 × 500 MB = 500 MB por muestra
const COMPUTE_SAMPLES = 7 // 7 muestras → mediana robusta (cada una ya es grande)
const HASHFILE_SAMPLES = 5
const IO_SAMPLES = 3
const WARMUP = 2 // 2 × 500 MB = 1 GB de warmup (JIT + caché de página)

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

// ── CARGA DEL WASM ──

async function loadWasm(p: string): Promise<Sha2Wasm> {
  const buf = await Bun.file(p).arrayBuffer()
  return Sha2Wasm.fromBuffer(buf)
}

// ── 1. CORRECTITUD ──

/** Valida sha2-wasm contra node:crypto. Aborta si falla. */
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

// ── 2. COMPUTE PURO (runner común para ambas libs) ──

/** Interfaz mínima que cumplen tanto nuestro hasher como el adapter de hash-wasm. */
type HasherLike = {
  reset(): void
  update(d: Uint8Array): void
  digest(...args: any[]): unknown
}

function benchComputeOne(name: string, mk: () => HasherLike, buf: Uint8Array): number[] {
  const h = mk()
  // warmup: sube el hot-loop a DFG/FTL (JSC) y llena caché de página
  for (let w = 0; w < WARMUP; w++) {
    h.reset()
    h.update(buf)
    h.digest("bytes")
  }
  const samples: number[] = []
  for (let r = 0; r < COMPUTE_SAMPLES; r++) {
    h.reset()
    const t0 = performance.now()
    for (let i = 0; i < COMPUTE_ITERS; i++) h.update(buf) // 500 MB por muestra
    const t1 = performance.now()
    h.digest("bytes") // fuera del timing
    samples.push((COMPUTE_ITERS * COMPUTE_BUF_MB) / ((t1 - t0) / 1000))
  }
  report(name, samples)
  return samples
}

async function benchCompute(
  wasm: Sha2Wasm
): Promise<{ ours: { sha256: number; sha512: number }; hw: { sha256: number; sha512: number } }> {
  const buf = new Uint8Array(COMPUTE_BUF_MB * MB)
  buf.fill(0x5a) // datos no comprimibles

  console.log(`COMPUTE PURO (RAM, ${COMPUTE_BUF_MB} MB/muestra, ${COMPUTE_SAMPLES} muestras, sin I/O):`)

  // ── sha2-wasm (nuestro) ──
  const ours256 = benchComputeOne("SHA-256 sha2-wasm", () => Sha256.createHasher(wasm), buf)
  const ours512 = benchComputeOne("SHA-512 sha2-wasm", () => Sha512.createHasher(wasm), buf)

  // ── hash-wasm (adapter a HasherLike; init() ≡ reset()) ──
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

  // ── 3. COMPARATIVA ──
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

// ── 4. I/O PURO ──

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

// ── 5. HASHFILE REAL ──

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

  console.log(`HASHFILE real (archivo ${(file.size / MB).toFixed(1)} MB, double-buffer):`)
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
  console.log(`  file  : ${filePath ?? "(ninguno → solo compute)"}`)
  console.log(`  unidad: MB = 1024*1024 (binario)\n`)

  if (!Bun.file(wasmPath).size) {
    console.error(`❌ No encuentro el WASM en "${wasmPath}".`)
    process.exit(1)
  }
  const wasm = await loadWasm(wasmPath)
  console.log("WASM cargado.\n")

  console.log("─".repeat(72))
  console.log("CORRECTITUD (sha2-wasm + hash-wasm vs node:crypto)")
  console.log("─".repeat(72))
  verifyCorrectness()
  await verifyHashWasm()
  console.log("  ✅ Ambas librerías verificadas.\n")

  console.log("─".repeat(72))
  const compute = await benchCompute(wasm)

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
