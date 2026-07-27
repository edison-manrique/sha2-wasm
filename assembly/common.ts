// @ts-ignore
@inline
export function load32_be(ptr: usize): u32 {
  return bswap(load<u32>(ptr))
}

// @ts-ignore
@inline
export function store32_be(ptr: usize, u: u32): void {
  store<u32>(ptr, bswap(u))
}

// @ts-ignore
@inline
export function load64_be(ptr: usize): u64 {
  return bswap(load<u64>(ptr))
}

// @ts-ignore
@inline
export function store64_be(ptr: usize, u: u64): void {
  store<u64>(ptr, bswap(u))
}

// SHA256 Bitwise helpers (Inlined Direct WASM Operations)
// @ts-ignore
@inline
export function sigma0_256(x: u32): u32 {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

// @ts-ignore
@inline
export function sigma1_256(x: u32): u32 {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

// @ts-ignore
@inline
export function Sigma0_256(x: u32): u32 {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

// @ts-ignore
@inline
export function Sigma1_256(x: u32): u32 {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

// @ts-ignore
@inline
export function Ch32(x: u32, y: u32, z: u32): u32 {
  return z ^ (x & (y ^ z))
}

// @ts-ignore
@inline
export function Maj32(x: u32, y: u32, z: u32): u32 {
  return (x & y) ^ (z & (x ^ y))
}

// SHA512 Bitwise helpers
// @ts-ignore
@inline
export function sigma0_512(x: u64): u64 {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

// @ts-ignore
@inline
export function sigma1_512(x: u64): u64 {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

// @ts-ignore
@inline
export function Sigma0_512(x: u64): u64 {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

// @ts-ignore
@inline
export function Sigma1_512(x: u64): u64 {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

// @ts-ignore
@inline
export function Ch64(x: u64, y: u64, z: u64): u64 {
  return z ^ (x & (y ^ z))
}

// @ts-ignore
@inline
export function Maj64(x: u64, y: u64, z: u64): u64 {
  return (x & y) ^ (z & (x ^ y))
}