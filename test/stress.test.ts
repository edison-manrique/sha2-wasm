import { describe, test, expect, beforeAll } from "bun:test"
import { readFileSync } from "node:fs"
import path from "node:path"
import { Sha2Wasm, Sha256, Sha512 } from "../src/index"

describe("SHA2-WASM Full Memory & Performance Stress Test", () => {
  let wasm: Sha2Wasm
  let wasmMemory: WebAssembly.Memory

  beforeAll(async () => {
    const wasmPath = path.join(import.meta.dir, "../dist/sha2.wasm")
    const wasmBuffer = readFileSync(wasmPath)
    wasm = await Sha2Wasm.fromBuffer(wasmBuffer)
    wasmMemory = wasm.memory
  })

  test("Sanity Check before Stress", () => {
    const res256 = Sha256.hash("abc")
    const res512 = Sha512.hash("abc")
    expect(res256).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    expect(res512).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
  })

  const rounds = [10_000, 50_000, 100_000, 500_000]

  for (const count of rounds) {
    test(`Stress Round: ${count.toLocaleString()} SHA-256 / SHA-512 iterations`, async () => {
      const sampleData = new TextEncoder().encode("Performance and zero-memory allocation test payload for WASM crypto")

      if (globalThis.gc) globalThis.gc()
      await new Promise((r) => setTimeout(r, 50))

      const memBefore = process.memoryUsage()
      const wasmBytesBefore = wasmMemory ? wasmMemory.buffer.byteLength : 0

      const start = performance.now()

      for (let i = 0; i < count; i++) {
        if (i % 2 === 0) {
          wasm.sha256(sampleData)
        } else {
          wasm.sha512(sampleData)
        }
      }

      const elapsed = (performance.now() - start).toFixed(2)
      console.log(`\n  Time taken: ${count.toLocaleString()} iterations = ${elapsed} ms`)

      if (globalThis.gc) globalThis.gc()
      await new Promise((r) => setTimeout(r, 50))

      const memAfter = process.memoryUsage()
      const wasmBytesAfter = wasmMemory ? wasmMemory.buffer.byteLength : 0

      const heapDeltaMB = (memAfter.heapUsed - memBefore.heapUsed) / (1024 * 1024)
      const wasmGrowthBytes = wasmBytesAfter - wasmBytesBefore

      expect(wasmGrowthBytes).toBe(0)
      expect(heapDeltaMB).toBeLessThan(10)

      // Post-round integrity check
      const postCheck256 = Sha256.hash("abc")
      expect(postCheck256).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }, 20000)
  }
})
