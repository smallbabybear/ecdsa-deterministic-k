import { getDeterministicK } from './deterministic';
import { createHash } from 'crypto';

const sha256 = (message: string): Buffer => {
  return createHash('sha256').update(message).digest();
}

const main = async () => {
  const testMessage = 'Hello, world!';
  const testMessage2 = 'Hello, deterministic K!';
  const testPrivateKey = new Uint8Array(Buffer.from('b99ef08467e4d9a3d2d38f39b77743128c2f60f67db79486cfb55eb24523a45d', 'hex'));
  const testPrivateKey2 = new Uint8Array(Buffer.from('919577c76375c453ec980013b4b4dc181131de9e2d88fab0354bad5333f06a8a', 'hex'));
  const msgHash = sha256(testMessage);
  const msgHash2 = sha256(testMessage2);

  const k1 = await getDeterministicK(msgHash, testPrivateKey);
  console.log('Deterministic k (first run):', k1.toString(16));

  // Same message and private key
  // Should k1 == k2
  const k2 = await getDeterministicK(msgHash, testPrivateKey);
  console.log('Deterministic k (second run):', k2.toString(16));

  // Different message
  // Should k1 != k3
  const k3 = await getDeterministicK(msgHash2, testPrivateKey);
  console.log('Deterministic k (different message):', k3.toString(16));

  // Different private key
  // Should k1 != k4
  const k4 = await getDeterministicK(msgHash, testPrivateKey2);
  console.log('Deterministic k (different private key):', k4.toString(16));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
