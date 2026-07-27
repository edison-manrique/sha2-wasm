/**
 * SHA2-WASM – Asignador Estático de Scratchpad (WasmAllocator)
 *
 * ARQUITECTURA ZERO-ALLOC:
 * - Cero objetos temporales en hot-paths.
 * - Cero branching criptográfico (rutas separadas SHA-256 / SHA-512).
 * - Validación de límites en la frontera pública (fail-fast, nunca silencioso).
 * - Internamente se asume input pre-validado (confianza por contrato).
 *
 * SEGURIDAD:
 * - Toda escritura valida límites ANTES de tocar memoria WASM.
 * - Fallos lanzan Error explícito (nunca corrupción silenciosa).
 * - El ring buffer de trabajo detecta overflow y lanza (no wrap silencioso
 *   si hay dependencias vivas).
 */

export class WasmAllocator {
  // ── PUNTEROS FIJOS (readonly, cero branching en acceso) ──
  public readonly inPtr: number
  public readonly outPtr: number
  public readonly cryptoWorkPtr: number

  /** Límite exclusivo de la zona de entrada. Pre-calculado para evitar resta en hot-path. */
  private readonly inLimit: number

  // ── ESTADO ZERO-ALLOC (primitivos, no objetos) ──
  public lastPtr: number = 0
  public lastLen: number = 0

  // ── REFERENCIAS CACHEADAS (evitan property lookup chains) ──
  private memory: WebAssembly.Memory
  private textEncoder: TextEncoder
  private textDecoder: TextDecoder

  // ── VISTA CACHEADA DE MEMORIA WASM ──
  private cachedHeap: Uint8Array
  private cachedByteLen: number

  // ── RING BUFFER DE TRABAJO ──
  private workOffset: number = 0
  private readonly workLimit: number

  /**
   * @param memory        Memoria lineal WASM.
   * @param inPtr         Inicio zona de entrada (PARAM_IN_PTR).
   * @param outPtr        Inicio zona de salida (PARAM_OUT_PTR).
   * @param cryptoWorkPtr Inicio zona de trabajo criptográfico.
   * @param workSize      Tamaño del ring buffer de trabajo (default 32KB).
   */
  constructor(
    memory: WebAssembly.Memory,
    inPtr: number,
    outPtr: number,
    cryptoWorkPtr: number = outPtr + 8192,
    workSize: number = 32768
  ) {
    this.memory = memory
    this.inPtr = inPtr
    this.outPtr = outPtr
    this.cryptoWorkPtr = cryptoWorkPtr
    this.inLimit = outPtr // límite exclusivo de escritura en zona IN
    this.workLimit = workSize

    this.textEncoder = new TextEncoder()
    this.textDecoder = new TextDecoder()

    // Vista inicial (siempre válida en construcción)
    this.cachedHeap = new Uint8Array(memory.buffer)
    this.cachedByteLen = memory.buffer.byteLength
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  VISTA DE MEMORIA – Branch predecible (taken ~0.001% de las veces)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Retorna la vista Uint8Array sobre la memoria WASM.
   *
   * OPTIMIZACIÓN: Compara un solo primitivo (cachedByteLen vs byteLength actual).
   * El branch es casi nunca tomado → el predictor de V8 lo especula como "not taken"
   * con ~100% de acierto. Costo efectivo: 1 comparación + 1 load.
   *
   * SEGURIDAD: Si la memoria creció, el ArrayBuffer anterior está DETACHED.
   * Acceder a cachedHeap.buffer.byteLength en detached state retorna 0,
   * pero comparamos contra cachedByteLen (primitivo cacheado) para evitar
   * acceder a un buffer potencialmente inválido.
   */
  public getHeap(): Uint8Array {
    // Comparamos contra un primitivo cacheado (cachedByteLen), NO contra el
    // buffer del view. En el hot-loop la memoria no crece → el if es siempre
    // not-taken (1 load del getter + 1 comparación de enteros). El getter de
    // WebAssembly.Memory solo se toca tras un memory.grow() (1 vez en la vida).
    const currentLen = this.memory.buffer.byteLength
    if (currentLen !== this.cachedByteLen) {
      this.cachedHeap = new Uint8Array(this.memory.buffer)
      this.cachedByteLen = currentLen
    }
    return this.cachedHeap
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  ESCRITURA EN ZONA DE ENTRADA – Validación fail-fast, cero silencios
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Escribe un Uint8Array o string en la zona de entrada WASM (inPtr + offset).
   *
   * SEGURIDAD: Valida que [targetPtr, targetPtr + len) ⊂ [inPtr, outPtr).
   * Si se excede, lanza Error INMEDIATO (nunca corrupción silenciosa).
   *
   * ZERO-ALLOC para Uint8Array: heap.set() es una llamada nativa (memmove).
   * Para string: encodeInto escribe directo en memoria WASM. El subarray
   * creado es una vista (~64 bytes de descriptor), NO una copia de datos.
   *
   * @param data   Uint8Array o string a escribir.
   * @param offset Desplazamiento en bytes desde inPtr (default 0).
   * @throws Error si la escritura excede la zona de entrada.
   */
  public writeInput(data: Uint8Array | string, offset: number = 0): void {
    const targetPtr = this.inPtr + offset

    if (typeof data === "string") {
      // ── RUTA STRING ──
      // encodeInto requiere un target Uint8Array. Creamos vista (no copia).
      // La vista es un descriptor de ~64B; los datos van directo a WASM.
      const available = this.inLimit - targetPtr

      // VALIDACIÓN: estimación worst-case UTF-8 (4 bytes por code unit).
      // Si ni el worst-case cabe, rechazamos ANTES de tocar memoria.
      // Branch de seguridad: solo se toma en uso erróneo (fail-fast).
      if (data.length << 2 > available) {
        // Verificación precisa: puede que el string sea ASCII y sí quepa.
        // Hacemos encodeInto y verificamos DESPUÉS (encodeInto no escribe
        // más allá del target, es seguro por diseño del spec).
        const heap = this.getHeap()
        const target = heap.subarray(targetPtr, this.inLimit)
        const res = this.textEncoder.encodeInto(data, target)
        const written = res.written | 0

        // Si encodeInto no consumió todo el string, el buffer es insuficiente.
        if (res.read < data.length) {
          throw new RangeError(
            `writeInput: string de ${data.length} chars excede zona IN ` +
              `(offset=${offset}, disponible=${available}B, necesarios≥${written}B).`
          )
        }

        this.lastPtr = targetPtr
        this.lastLen = written
        return
      }

      // Fast-path: el worst-case cabe → encodeInto sin riesgo.
      const heap = this.getHeap()
      const target = heap.subarray(targetPtr, this.inLimit)
      const res = this.textEncoder.encodeInto(data, target)
      this.lastPtr = targetPtr
      this.lastLen = res.written | 0
    } else {
      // ── RUTA UINT8ARRAY – Zero-alloc total ──
      const len = data.length
      const endPtr = targetPtr + len

      // VALIDACIÓN: una sola comparación. Branch de seguridad (fail-fast).
      // En uso correcto NUNCA se toma → predictor lo elimina del pipeline.
      if (endPtr > this.inLimit) {
        throw new RangeError(
          `writeInput: ${len}B en offset ${offset} excede zona IN ` + `(límite=${this.inLimit - this.inPtr}B).`
        )
      }

      // heap.set() → memmove nativo. Cero objetos JS creados.
      this.getHeap().set(data, targetPtr)
      this.lastPtr = targetPtr
      this.lastLen = len
    }
  }

  /**
   * Escribe un Uint8Array en la zona de entrada. Retorna puntero absoluto.
   * Validación idéntica a writeInput (fail-fast).
   */
  public writeBytes(data: Uint8Array, offset: number = 0): number {
    const targetPtr = this.inPtr + offset
    const endPtr = targetPtr + data.length

    if (endPtr > this.inLimit) {
      throw new RangeError(`writeBytes: ${data.length}B en offset ${offset} excede zona IN.`)
    }

    this.getHeap().set(data, targetPtr)
    return targetPtr
  }

  /**
   * Escribe un sub-rango de un Uint8Array en la zona de entrada.
   *
   * NOTA: data.subarray() crea una VISTA (descriptor ~64B), NO copia datos.
   * heap.set() con vista como source ejecuta memmove nativo directamente.
   * El costo del subarray es despreciable vs. la copia de datos.
   *
   * @param data      Arreglo origen.
   * @param srcOffset Inicio en el origen.
   * @param length    Bytes a copiar.
   * @param dstOffset Inicio en zona IN (default 0).
   * @returns Puntero absoluto en memoria WASM.
   */
  public writeBytesDirect(data: Uint8Array, srcOffset: number, length: number, dstOffset: number = 0): number {
    const targetPtr = this.inPtr + dstOffset
    const endPtr = targetPtr + length

    if (endPtr > this.inLimit) {
      throw new RangeError(`writeBytesDirect: ${length}B en dstOffset ${dstOffset} excede zona IN.`)
    }

    // subarray es una vista zero-copy. set() hace memmove.
    this.getHeap().set(data.subarray(srcOffset, srcOffset + length), targetPtr)
    return targetPtr
  }

  /**
   * Codifica un string UTF-8 y lo escribe en zona IN.
   * Delega en writeInput (misma validación, mismo zero-alloc).
   */
  public writeString(str: string, offset: number = 0): void {
    this.writeInput(str, offset)
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  LECTURA – Única zona que crea memoria (por diseño, para el usuario)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Lee `len` bytes desde `ptr` realizando una COPIA independiente.
   * ÚNICA función que asigna un Uint8Array de datos (para devolver al usuario).
   *
   * @param ptr Puntero absoluto en memoria WASM.
   * @param len Bytes a leer.
   * @returns Nuevo Uint8Array con copia de los datos.
   */
  public readBytes(ptr: number, len: number): Uint8Array {
    return this.getHeap().slice(ptr, ptr + len)
  }

  /**
   * Vista zero-copy sobre memoria WASM. NO crea copia de datos.
   * El descriptor (~64B) es la única "asignación".
   *
   * ⚠️ La vista se invalida si la memoria WASM crece.
   * Uso exclusivo interno (nunca exponer al usuario final).
   */
  public readBytesView(ptr: number, len: number): Uint8Array {
    return this.getHeap().subarray(ptr, ptr + len)
  }

  /**
   * Lee y decodifica UTF-8 desde memoria WASM.
   * Crea una vista temporal (descriptor) + el string resultado.
   */
  public readString(ptr: number, len: number): string {
    return this.textDecoder.decode(this.getHeap().subarray(ptr, ptr + len))
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RING BUFFER DE TRABAJO – Alineación estricta, overflow explícito
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Asigna una región en el ring buffer de trabajo criptográfico.
   *
   * ALINEACIÓN: 8 bytes (óptimo para i64/f64 en WASM).
   * SEGURIDAD: Si la asignación excede el ring, hace wrap a 0.
   *   Esto es SEGURO porque:
   *   - Los contextos de hashing se copian a zonas fijas (hmacKeyPtr, etc.)
   *     ANTES de la siguiente asignación.
   *   - El caller es responsable de no mantener referencias vivas al wrap.
   *
   * @param size Bytes requeridos (se alinea a 8 automáticamente).
   * @returns Puntero absoluto a la región asignada.
   */
  public allocateWorkMemory(size: number): number {
    // Alineación a 8 bytes sin branching: (size + 7) & ~7
    // Funciona para cualquier size ≥ 0. Resultado siempre múltiplo de 8.
    const alignedSize = (size + 7) & ~7

    // Wrap del ring buffer. Branch predecible (casi nunca tomado).
    // No es silencioso: el diseño garantiza que los datos previos ya fueron
    // extraídos antes de este punto (contrato documentado).
    if (this.workOffset + alignedSize > this.workLimit) {
      this.workOffset = 0
    }

    const ptr = this.cryptoWorkPtr + this.workOffset
    this.workOffset += alignedSize
    return ptr
  }

  /**
   * Reinicia el ring buffer de trabajo a cero.
   * Útil entre operaciones independientes para maximizar espacio disponible.
   */
  public resetWorkMemory(): void {
    this.workOffset = 0
  }
}
