import * as secp256k1 from './noble-secp256k1';

const { CURVE, etc } = secp256k1;
const N = CURVE.n; // Curve order
const fLen = 32;   // Field length (32 bytes)

/**
 * Generate a deterministic k value based on RFC6979
 * @param msgHash - Message hash (32 bytes)
 * @param privateKey - Private key
 * @param options - Options
 * @param options.extraEntropy - Additional entropy (optional)
 * @returns Deterministically generated k value
 */
export async function getDeterministicK(msgHash: secp256k1.Bytes, privateKey: secp256k1.Bytes | bigint, options: {
  extraEntropy?: boolean | secp256k1.Bytes;
} = {}) {
  // Prepare arguments
  const h1i = secp256k1.bits2int_modN(secp256k1.toU8(msgHash));
  const h1o = etc.numberToBytesBE(h1i);
  const d = secp256k1.toPriv(privateKey);
  const do_ = etc.numberToBytesBE(d);

  // Prepare seed
  const seed = [do_, h1o];

  if (options.extraEntropy) {
    let ent = options.extraEntropy;
    if (ent === true) {
      // If true, generate random bytes
      ent = etc.randomBytes(fLen);
    } else {
      // Otherwise, use the provided entropy
      ent = secp256k1.toU8(ent);
    }
    seed.push(ent);
  }

  // Use HMAC-DRBG from RFC6979 to generate k value
  const v = new Uint8Array(fLen).fill(1);
  const k = new Uint8Array(fLen).fill(0);

  // HMAC function
  if (typeof etc.hmacSha256Async !== 'function') {
    throw new Error('etc.hmacSha256Async not available');
  }
  const h = (...b: secp256k1.Bytes[]) => etc.hmacSha256Async(k, v, ...b);

  // Apply initial seed
  const concatenatedSeed = etc.concatBytes(...seed);

  // Step D - Initialization
  let newK = await h(k, v, new Uint8Array([0x00]), concatenatedSeed);
  let newV = await h(newK, v);

  // Step E - If additional entropy is provided
  if (concatenatedSeed.length) {
    newK = await h(newK, newV, new Uint8Array([0x01]), concatenatedSeed);
    newV = await h(newK, newV);
  }

  // Step F, G - Generate k value
  let kVal;
  let counter = 0;

  while (true) {
    if (counter++ > 1000) throw new Error('Tried 1000 k values, all were invalid');
    newV = await h(newK, newV);

    const T = newV;
    kVal = etc.bytesToNumberBE(T);

    // Check if k value is in valid range
    if (kVal > 0n && kVal < N) {
      break;
    }

    // If k value is invalid, generate a new seed
    newK = await h(newK, newV, new Uint8Array([0x00]));
    newV = await h(newK, newV);
  }

  return kVal;
}
