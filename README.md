# 🔐 SHA2 WASM

Biblioteca criptográfica de hashing ultra-rápida y de alto rendimiento compilada en WebAssembly (WASM) utilizando AssemblyScript y empaquetada con un wrapper TypeScript Zero-Allocation.

Soporta **SHA-256**, **SHA-512**, **HMAC-SHA256**, **HMAC-SHA512** y **PBKDF2** (derivación de claves, RFC 8018) —con **verificación de HMAC en tiempo constante** (a prueba de _timing attacks_)— con rendimiento extremo (**> 217 MB/s** en compute puro, **~2.2 M hashes/s** en hashes pequeños, **~155 K HMAC-verify/s**, **~765 derivaciones PBKDF2/s**) y **0 % de presión sobre el Garbage Collector (GC)**.

---

## 🚀 Características Principales

- ⚡ **Máximo Rendimiento**: Núcleo de compresión desplegado en WebAssembly con más de **217 MB/s** de throughput en compute puro y **~2.2 millones de hashes por segundo** en mensajes pequeños.
- 🧹 **Zero-Alloc (Cero Alocaciones GC)**: Usa un asignador de memoria _scratchpad_ estático (`WasmAllocator`) reservado en tiempo de compilación — ninguna operación reserva memoria en el heap en runtime.
- 🌐 **Multiplataforma**: Funciona sin modificaciones en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, etc.).
- 🛡️ **Seguridad Crypto**:
  - Algoritmos estándar **SHA-256 / SHA-512** (FIPS 180-4), **HMAC** (RFC 2104) y **PBKDF2** (RFC 8018).
  - **Verificación HMAC en tiempo constante** (`hmacVerify`): comparación por XOR acumulativo sin _early-exit_, inmune a ataques de timing.
  - Correctitud **validada contra `node:crypto`** (hash, HMAC, HMAC-verify y PBKDF2, incluida la detección de alteración).
  - Detección de colisiones del _ring buffer_ en `reset()` — nunca produce un hash corrupto en silencio.
- 🔑 **Derivación de Claves (PBKDF2)**: PBKDF2-HMAC-SHA256/512 con **precomputación de los estados ipad/opad** (~2× más rápido por iteración que un HMAC naive). Ideal para BIP39, WPA2 y almacenamiento de contraseñas.
- 🔄 **Streaming Real**: Hashing de archivos de cualquier tamaño con `file.stream()` y callback de progreso — memoria plana, sin acumular buffers.
- 📦 **Binario Compacto**: ~13.2 KB de WebAssembly optimizado.

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
import { Sha256 } from "@edison-manrique/sha2-wasm"

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
import { Sha512 } from "@edison-manrique/sha2-wasm"

const hash512 = Sha512.hash("Mensaje importante")
// → string hexadecimal de 128 caracteres

const bytes512 = Sha512.hash("Mensaje importante", "bytes") // Uint8Array(64)
```

### 4. HMAC (Código de Autenticación de Mensajes)

Autentica un mensaje con una clave secreta conforme a **RFC 2104**.

```ts
import { Sha256, Sha512, HMAC } from "@edison-manrique/sha2-wasm"

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

### 5. Verificación de HMAC (Constant-Time)

Verifica un MAC **en tiempo constante** — la comparación recorre siempre los 32/64 bytes con XOR acumulativo y sin _early-exit_, por lo que **no revela información por timing** (esencial para no exponer la validación a ataques de canal lateral).

```ts
import { Sha256, HMAC, hexToBytes } from "@edison-manrique/sha2-wasm"

const clave = "mi-clave-secreta"
const mensaje = "mensaje a autenticar"

// 🔏 Genera el MAC
const mac = Sha256.hmac(clave, mensaje) // string hex

// ✅ Verifica (acepta el MAC como hex o como bytes)
const valido = Sha256.hmacVerify(clave, mensaje, mac) // true
const validoBytes = Sha256.hmacVerify(clave, mensaje, hexToBytes(mac)) // true

// ❌ Un MAC alterado o incorrecto → false (sin filtrar cuántos bytes coincidían)
const falso = Sha256.hmacVerify(clave, mensaje, "00".repeat(32)) // false

// 🔄 Con la API orientada a objetos
const hmac = new HMAC(clave, "SHA256")
const ok = hmac.verify(mensaje, mac) // true
```

> Disponible también en `Sha512.hmacVerify(...)` (MAC de 64 bytes).

### 6. PBKDF2 (Derivación de Claves)

Deriva una clave criptográfica a partir de una contraseña con **PBKDF2-HMAC-SHA256/512** (RFC 8018). Usa precomputación de los estados ipad/opad para acelerar las iteraciones.

```ts
import { Sha256, Sha512 } from "@edison-manrique/sha2-wasm"

const password = "mi-contraseña-super-secreta"
const salt = "salt-aleatorio-único-por-usuario"

// 🔑 PBKDF2-HMAC-SHA256 (ej. 2048 iteraciones, clave de 32 bytes)
const key256 = Sha256.pbkdf2(password, salt, 2048, 32) // string hex
const key256Bytes = Sha256.pbkdf2(password, salt, 2048, 32, "bytes") // Uint8Array(32)

// 🔑 PBKDF2-HMAC-SHA512 (ej. BIP39: 2048 iteraciones, seed de 64 bytes)
const seed = Sha512.pbkdf2(password, salt, 2048, 64) // string hex (128 chars)
```

> 🔐 **Recomendaciones**: usa siempre un **salt aleatorio único** por usuario (≥ 16 bytes) y un número de iteraciones alto (OWASP recomienda 600 000+ para PBKDF2-HMAC-SHA256 en almacenamiento de contraseñas). A más iteraciones, más costo para un atacante por fuerza bruta.

### 7. Streaming (Hash Incremental)

Para datos que llegan en fragmentos (chunks de red, trozos de archivo, streams). Procesa el hash **sin acumular todo en memoria**.

```ts
import { Sha256 } from "@edison-manrique/sha2-wasm"

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

### 8. Hashing de Archivos (con Progreso)

Hashea un `Blob` / `File` de **cualquier tamaño** con streaming real y memoria plana.

```ts
import { Sha256 } from "@edison-manrique/sha2-wasm"

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

### 9. Formatos de Salida y Utilidades

Todos los métodos aceptan el formato de salida (`"hex"` por defecto o `"bytes"`):

```ts
Sha256.hash(data) // → string hex (por defecto)
Sha256.hash(data, "hex") // → string hex
Sha256.hash(data, "bytes") // → Uint8Array
```

Utilidades de conversión incluidas:

```ts
import { bytesToHex, hexToBytes, toUint8Array } from "@edison-manrique/sha2-wasm"

const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])) // "deadbeef"
const bytes = hexToBytes("deadbeef") // Uint8Array(4)
const buf = toUint8Array("texto") // string → Uint8Array (UTF-8)
```

---

## 📊 Benchmarks de Rendimiento

Pruebas ejecutadas en Bun (JavaScriptCore) sobre un procesador x86-64 moderno, en single-thread (mediana de 5 muestras):

| Algoritmo | Caso                           | Throughput    | Ops/seg           |
| --------- | ------------------------------ | ------------- | ----------------- |
| SHA-256   | Compute puro (RAM, 500 MB)     | **217 MB/s**  | —                 |
| SHA-512   | Compute puro (RAM, 500 MB)     | **314 MB/s**  | —                 |
| SHA-256   | HMAC throughput (RAM, 256 MB)  | **209 MB/s**  | —                 |
| SHA-512   | HMAC throughput (RAM, 256 MB)  | **302 MB/s**  | —                 |
| SHA-256   | HMAC verify (1 KB, const-time) | —             | **~155 K ops/s**  |
| SHA-512   | HMAC verify (1 KB, const-time) | —             | **~180 K ops/s**  |
| SHA-256   | PBKDF2 (2048 it, dkLen 32)     | —             | **~765 deriv/s**  |
| SHA-512   | PBKDF2 (2048 it, dkLen 64)     | —             | **~556 deriv/s**  |
| SHA-256   | Hashes pequeños (55 B)         | ~114 MB/s     | **~2.20 M ops/s** |
| SHA-512   | Hashes pequeños (55 B)         | ~95 MB/s      | **~1.85 M ops/s** |
| SHA-256   | Archivo (streaming)            | **~200 MB/s** | —                 |
| SHA-512   | Archivo (streaming)            | **~300 MB/s** | —                 |

**Comparativa (single-thread):**

| Contra                                                 | Resultado                                                    |
| ------------------------------------------------------ | ------------------------------------------------------------ |
| [`hash-wasm`](https://www.npmjs.com/package/hash-wasm) | **+5–7 %** más rápido (SHA-256 **1.05×**, SHA-512 **1.07×**) |
| C nativo (`gcc -O3 -march=native`)                     | **~68 %** del nativo                                         |

> El ~68 % frente a C nativo es la banda alta esperada para WebAssembly (sin acceso a instrucciones específicas de CPU como `-march=native`). A cambio obtienes **portabilidad total**: el mismo binario de 13.2 KB corre en cualquier navegador, Bun o Node.

---

## 🏗️ Arquitectura Zero-Allocation

- **Scratchpad estático**: las zonas de entrada (`PARAM_IN`), salida (`PARAM_OUT`) y trabajo criptográfico (`CRYPTO_WORK`) se reservan en el _data segment_ del WASM en **tiempo de compilación**.
- **Punteros fijos**: los resultados se devuelven en propiedades primitivas (`lastPtr`, `lastLen`) en lugar de objetos intermedios.
- **Única asignación**: el `Uint8Array` final que se entrega al usuario (inevitable para devolver el hash o la clave derivada).
- **Detección de colisiones**: los hashers verifican el IV del contexto en `reset()` y reasignan memoria si otra operación sobrescribió su región.
- **Comparación constant-time**: `hmac_verify_raw` compara el MAC calculado con el esperado mediante XOR + OR acumulativo de longitud fija (32/64 iteraciones, sin branches dependientes de los datos), evitando fugas por timing.
- **PBKDF2 optimizado**: los estados ipad/opad del HMAC se precomputan **una sola vez por clave** y se reutilizan en cada iteración (copia de estado + 2 compresiones por iteración, en vez de 4), reduciendo ~2× el costo del bucle de iteraciones.

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

# Benchmark comparativo (vs hash-wasm) + validación de correctitud
# (hash, HMAC, HMAC-verify y PBKDF2 contra node:crypto, incluida detección de alteración)
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
│   ├── index.ts         # Exportaciones WASM (hash, hmac, hmac_verify, pbkdf2, ctx streaming)
│   ├── sha256.ts        # SHA-256 (compress, update, final, hmac, hmac_verify)
│   ├── sha512.ts        # SHA-512
│   ├── pbkdf2.ts        # PBKDF2-HMAC-SHA256/512 (RFC 8018, zero-alloc)
│   ├── constants.ts     # Constantes K e IV
│   ├── common.ts        # Helpers (bswap, Ch, Maj, Sigma, sigma)
│   └── memory.ts        # Scratchpad estático (punteros)
├── src/                 # Wrapper en TypeScript
│   ├── index.ts         # Punto de entrada (re-exports)
│   ├── sha2-wasm.ts     # Cargador + API de bajo nivel
│   ├── allocator.ts     # Alocador del scratchpad (zero-alloc)
│   ├── sha256.ts        # Sha256 + Sha256Hasher (hash, hmac, hmacVerify, pbkdf2)
│   ├── sha512.ts        # Sha512 + Sha512Hasher
│   ├── hmac.ts          # Clase HMAC (digest + verify)
│   └── types.ts         # Tipos, interfaces y utilidades
├── test/                # Benchmarks
│   └── bench.ts         # Bench comparativo (vs hash-wasm) + HMAC + verify + PBKDF2
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

> **Exención de responsabilidad:** este software se proporciona "tal cual" (AS IS), sin garantía de ningún tipo. Aunque SHA-256, SHA-512, HMAC y PBKDF2 son algoritmos estándar (FIPS 180-4 / RFC 2104 / RFC 8018), esta implementación no ha sido auditada formalmente y no debe emplearse en aplicaciones de seguridad crítica sin verificación independiente.
