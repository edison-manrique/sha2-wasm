# ⚡ sha2-wasm

> Hash criptográfico de alto rendimiento — **SHA-256 · SHA-512 · HMAC** — compilado de AssemblyScript a WebAssembly, con un wrapper de TypeScript completamente tipado y **zero-allocation**.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![WASM size](https://img.shields.io/badge/wasm-12%20KB-6366f1.svg)]()
[![Runtime](https://img.shields.io/badge/runtime-browser%20%7C%20bun%20%7C%20node-10b981.svg)]()

`sha2-wasm` es una biblioteca de hashing que corre el núcleo criptográfico en WebAssembly y expone una API limpia y segura en TypeScript. Está diseñada para ser rápida, predecible y no generar presión sobre el recolector de basura: todas las zonas de I/O viven en un _scratchpad_ estático reservado en tiempo de compilación.

---

## 📑 Índice

- [Características](#-características)
- [Rendimiento](#-rendimiento)
- [Instalación](#-instalación)
- [Inicio rápido](#-inicio-rápido)
- [Uso](#-uso)
  - [Hash one-shot](#hash-one-shot)
  - [HMAC](#hmac)
  - [Streaming (hash incremental)](#streaming-hash-incremental)
  - [Hashing de archivos](#hashing-de-archivos)
  - [Formatos de salida](#formatos-de-salida)
  - [Utilidades](#utilidades)
- [API de bajo nivel](#-api-de-bajo-nivel)
- [Arquitectura zero-allocation](#-arquitectura-zero-allocation)
- [Desarrollo y build](#-desarrollo-y-build)
- [Benchmark](#-benchmark)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Licencia](#-licencia)

---

## ✨ Características

- **SHA-256 y SHA-512** one-shot y en streaming (incremental).
- **HMAC-SHA256 / HMAC-SHA512** conforme a [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
- **Zero-allocation**: sin reservas en el heap de JS ni del runtime WASM durante la I/O.
- **Hashing de archivos** de cualquier tamaño con _streaming real_ (`file.stream()`) y callback de progreso — memoria plana, sin acumular buffers.
- **Salida en hexadecimal o bytes crudos** (`Uint8Array`).
- **Núcleo en WebAssembly** (AssemblyScript) con wrapper TypeScript tipado.
- **Binario de ~12 KB**.
- **Correctitud validada** contra `node:crypto`.

---

## 🚀 Rendimiento

Medido con Bun (JavaScriptCore) sobre un CPU x86-64 moderno, en single-thread:

| Métrica                     | SHA-256   | SHA-512   |
| --------------------------- | --------- | --------- |
| **Streaming de archivos**   | ~212 MB/s | ~257 MB/s |
| **Hashes pequeños** (ops/s) | ~2.20 M   | ~1.85 M   |
| **Compute puro** (RAM)      | ~212 MB/s | ~318 MB/s |

**Comparativa (single-thread):**

| Contra                                                 | Resultado            |
| ------------------------------------------------------ | -------------------- |
| [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) | **+5 %** más rápido  |
| C nativo (`gcc -O3 -march=native`)                     | **~68 %** del nativo |

> El ~68 % frente a C nativo es la banda alta esperada para WebAssembly (que no accede a instrucciones específicas de CPU como `-march=native`). A cambio obtienes portabilidad total: el mismo binario corre en cualquier navegador, Bun o Node.

---

## 📦 Instalación

```bash
npm install sha2-wasm
# o
bun add sha2-wasm
# o
pnpm add sha2-wasm
```
