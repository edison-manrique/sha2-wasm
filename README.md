# 🔐 SHA2 WASM

Biblioteca criptográfica de hashing ultra-rápida y de alto rendimiento compilada en WebAssembly (WASM) utilizando AssemblyScript y empaquetada con un wrapper TypeScript Zero-Allocation.

Soporta **SHA-256**, **SHA-512**, **HMAC-SHA256** y **HMAC-SHA512** con rendimiento extremo (**> 212 MB/s** en streaming de archivos, **~2.2 M hashes/s** en hashes pequeños) y **0 % de presión sobre el Garbage Collector (GC)**.

---

## 🚀 Características Principales

- ⚡ **Máximo Rendimiento**: Núcleo de compresión desplegado en WebAssembly con más de **212 MB/s** de throughput en streaming y **~2.2 millones de hashes por segundo** en mensajes pequeños.
- 🧹 **Zero-Alloc (Cero Alocaciones GC)**: Usa un asignador de memoria _scratchpad_ estático (`WasmAllocator`) reservado en tiempo de compilación — ninguna operación reserva memoria en el heap en runtime.
- 🌐 **Multiplataforma**: Funciona sin modificaciones en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, etc.).
- 🛡️ **Seguridad Crypto**:
  - Algoritmos estándar **SHA-256 / SHA-512** (FIPS 180-4) y **HMAC** (RFC 2104).
  - Correctitud **validada contra `node:crypto`**.
  - Detección de colisiones del _ring buffer_ en `reset()` — nunca produce un hash corrupto en silencio.
- 🔄 **Streaming Real**: Hashing de archivos de cualquier tamaño con `file.stream()` y callback de progreso — memoria plana, sin acumular buffers.
- 📦 **Binario Compacto**: ~12 KB de WebAssembly optimizado.

---

## 📦 Instalación

```bash
npm install @edison-manrique/sha2-wasm
```

O con Bun / Yarn / pnpm:

```bash
bun add @edison-manrique/sha2-wasm
```

---

## 💻 Guía de Uso

### 1. Inicializar la biblioteca

```ts
import { Sha2Wasm, Sha256, Sha512 } from "@edison-manrique/sha2-wasm"

// Carga automática desde la URL por defecto (navegador / bundler)
await Sha2Wasm.load()

// O cargando desde un buffer binario explícito (útil para Node.js / Bun):
// import { readFileSync } from "node:fs"
// const wasmBuffer = readFileSync("node_modules/@edison-manrique/sha2-wasm/dist/sha2.wasm")
// await Sha2Wasm.fromBuffer(wasmBuffer)
```

> La carga se realiza **una sola vez**. Después puedes usar `Sha256` / `Sha512` directamente (usan el singleton global).

### 2. SHA-256 (Hash One-Shot)

Ideal para hashear datos completos de una sola vez. Devuelve un digest de **32 bytes**.

```ts
import { Sha256 } from "sha2-wasm"

const texto = "Hola Mundo desde sha2-wasm 👋"

// 🔐 Hash SHA-256 (devuelve hexadecimal por defecto)
const hash = Sha256.hash(texto)
console.log(hash)
// → "c61d9e960e9c88c8baed5e49c59da2f779af1b204bf18b4edce461e2a902762c"

// 📦 Hash como bytes crudos (Uint8Array de 32 bytes)
const bytes = Sha256.hash(texto, "bytes") // Uint8Array(32)

// 🔢 También acepta Uint8Array como entrada
const fromBytes = Sha256.hash(new Uint8Array([0x68, 0x6f, 0x6c, 0x61]))
```

### 3. SHA-512 (Hash One-Shot)

Misma API que SHA-256, pero produce un digest de **64 bytes** (128 caracteres hex).

```ts
import { Sha512 } from "sha2-wasm"

const hash512 = Sha512.hash("Mensaje importante")
// → string hexadecimal de 128 caracteres

const bytes512 = Sha512.hash("Mensaje importante", "bytes") // Uint8Array(64)
```

### 4. HMAC (Código de Autenticación de Mensajes)

Autentica un mensaje con una clave secreta conforme a **RFC 2104**.

```ts
import { Sha256, Sha512, HMAC } from "sha2-wasm"

const clave = "mi-clave-secreta-super-segura"
const mensaje = "Mensaje confidencial para firmar"

// 🔑 HMAC-SHA256 (API estática)
const mac = Sha256.hmac(clave, mensaje)

// 🔑 HMAC-SHA512
const mac512 = Sha512.hmac(clave, mensaje, "hex")

// 🔄 API orientada a objetos (reutiliza clave y algoritmo en varios mensajes)
const hmac = new HMAC(clave, "SHA256")
const token1 = hmac.digest("mensaje 1")
const token2 = hmac.digest("mensaje 2")

// 🧮 Cálculo estático explícito
const mac2 = HMAC.compute("SHA512", clave, mensaje, "bytes") // Uint8Array(64)
```

### 5. Streaming (Hash Incremental)

Para datos que llegan en fragmentos (chunks de red, trozos de archivo, streams). Procesa el hash **sin acumular todo en memoria**.

```ts
import { Sha256 } from "sha2-wasm"

// 🔄 Crea un hasher incremental
const hasher = Sha256.createHasher()

// Alimenta fragmentos (encadenable)
hasher.update("primera parte ").update("segunda parte ")
hasher.update(new Uint8Array([0x74, 0x65, 0x72, 0x63, 0x65, 0x72, 0x61]))

// ✅ Finaliza y obtén el digest
const hash = hasher.digestHex() // hex (sin branch de formato)
// o
const bytes = hasher.digestBytes() // Uint8Array
const hex2 = hasher.digest() // hex por defecto

// ♻️ Reutiliza el hasher SIN reasignar memoria
hasher.reset()
hasher.update("nuevo mensaje")
const otro = hasher.digestHex()
```

> ⚠️ Llamar `update()` después de `digest()` lanza un `Error` explícito (no falla en silencio). Usa `reset()` para reutilizar la instancia.

### 6. Hashing de Archivos (con Progreso)

Hashea un `Blob` / `File` de **cualquier tamaño** con streaming real y memoria plana.

```ts
import { Sha256 } from "sha2-wasm"

// 📁 Selecciona un archivo (input type="file")
const file = document.querySelector<HTMLInputElement>("input[type=file]")!.files![0]

// 🔄 Hashea con callback de progreso
const hash = await Sha256.hashFile(file, "hex", (processed, total) => {
  const pct = Math.round((processed / total) * 100)
  console.log(`Progreso: ${pct}%`)
})

console.log("SHA-256 del archivo:", hash)
// También disponible: Sha512.hashFile(file, "bytes", onProgress)
```

- **Memoria plana**: usa `file.stream()` y procesa chunk a chunk; no acumula buffers grandes en JS.
- **Solapamiento I/O ↔ compute**: el _read-ahead_ lo gestiona el runtime (navegador / Bun).

### 7. Formatos de Salida y Utilidades

Todos los métodos aceptan el formato de salida (`"hex"` por defecto o `"bytes"`):

```ts
Sha256.hash(data) // → string hex (por defecto)
Sha256.hash(data, "hex") // → string hex
Sha256.hash(data, "bytes") // → Uint8Array
```

Utilidades de conversión incluidas:

```ts
import { bytesToHex, hexToBytes, toUint8Array } from "sha2-wasm"

const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])) // "deadbeef"
const bytes = hexToBytes("deadbeef") // Uint8Array(4)
const buf = toUint8Array("texto") // string → Uint8Array (UTF-8)
```

---

## 📊 Benchmarks de Rendimiento

Pruebas ejecutadas en Bun (JavaScriptCore) sobre un procesador x86-64 moderno, en single-thread:

| Algoritmo | Caso                   | Throughput    | Ops/seg           |
| --------- | ---------------------- | ------------- | ----------------- |
| SHA-256   | Archivo (streaming)    | **~212 MB/s** | —                 |
| SHA-512   | Archivo (streaming)    | **~257 MB/s** | —                 |
| SHA-256   | Hashes pequeños (55 B) | ~114 MB/s     | **~2.20 M ops/s** |
| SHA-512   | Hashes pequeños (55 B) | ~95 MB/s      | **~1.85 M ops/s** |
| SHA-256   | Compute puro (RAM)     | **~212 MB/s** | —                 |
| SHA-512   | Compute puro (RAM)     | **~318 MB/s** | —                 |

**Comparativa (single-thread):**

| Contra                                                 | Resultado            |
| ------------------------------------------------------ | -------------------- |
| [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) | **+5 %** más rápido  |
| C nativo (`gcc -O3 -march=native`)                     | **~68 %** del nativo |

> El ~68 % frente a C nativo es la banda alta esperada para WebAssembly (sin acceso a instrucciones específicas de CPU como `-march=native`). A cambio obtienes **portabilidad total**: el mismo binario de 14 KB corre en cualquier navegador, Bun o Node.

---

## 🏗️ Arquitectura Zero-Allocation

- **Scratchpad estático**: las zonas de entrada (`PARAM_IN`), salida (`PARAM_OUT`) y trabajo criptográfico (`CRYPTO_WORK`) se reservan en el _data segment_ del WASM en **tiempo de compilación**.
- **Punteros fijos**: los resultados se devuelven en propiedades primitivas (`lastPtr`, `lastLen`) en lugar de objetos intermedios.
- **Única asignación**: el `Uint8Array` final que se entrega al usuario (inevitable para devolver el hash).
- **Detección de colisiones**: los hashers verifican el IV del contexto en `reset()` y reasignan memoria si otra operación sobrescribió su región.

---

## 🛠️ Comandos de Desarrollo

```bash
# Compilar binario WASM (AssemblyScript) + bundle TypeScript (esbuild minificado)
bun run build

# Compilar solo el binario WASM
bun run asbuild          # release → dist/sha2.wasm
bun run asbuild:debug    # debug → build/debug.wasm + .wat + sourcemap

# Verificación de tipos
bun run typecheck

# Ejecutar el benchmark comparativo (vs hash-wasm) + validación de correctitud
bun run bench
bun run bench ./ruta/al/archivo.mp4   # con archivo: + I/O puro + hashFile + diagnóstico

# Tests
bun test test/
```

---

## 📁 Estructura del Proyecto

```
sha2-wasm/
├── assembly/            # Núcleo en AssemblyScript (→ WebAssembly)
│   ├── index.ts         # Exportaciones WASM (hash, hmac, ctx streaming)
│   ├── sha256.ts        # SHA-256 (compress, update, final, hmac)
│   ├── sha512.ts        # SHA-512
│   ├── constants.ts     # Constantes K e IV
│   ├── common.ts        # Helpers (bswap, Ch, Maj, Sigma, sigma)
│   └── memory.ts        # Scratchpad estático (punteros)
├── src/                 # Wrapper en TypeScript
│   ├── index.ts         # Punto de entrada (re-exports)
│   ├── sha2-wasm.ts     # Cargador + API de bajo nivel
│   ├── allocator.ts     # Alocador del scratchpad (zero-alloc)
│   ├── sha256.ts        # Sha256 + Sha256Hasher
│   ├── sha512.ts        # Sha512 + Sha512Hasher
│   ├── hmac.ts          # Clase HMAC
│   └── types.ts         # Tipos, interfaces y utilidades
├── test/                # Benchmarks
│   └── full.bench.ts    # Bench comparativo (vs hash-wasm)
├── dist/                # Build (generado)
├── asconfig.json        # Configuración de AssemblyScript
├── package.json
├── tsconfig.json
├── LICENSE              # Apache-2.0
└── README.md
```

---

## 📜 Licencia

[Apache License 2.0](./LICENSE) © **Edison Manrique**

> **Exención de responsabilidad:** este software se proporciona "tal cual" (AS IS), sin garantía de ningún tipo. Aunque SHA-256, SHA-512 y HMAC son algoritmos estándar (FIPS 180-4 / RFC 2104), esta implementación no ha sido auditada formalmente y no debe emplearse en aplicaciones de seguridad crítica sin verificación independiente.
