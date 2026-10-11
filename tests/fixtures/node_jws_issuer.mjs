// Independent RFC 7515 compact JWS producer/crypto verifier used by Python tests.
// No production Python serializer, signing helper, or trust code is imported.
// Keys are ephemeral test keys. This fixture is not an attestation authority.
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const request = JSON.parse(readFileSync(0, 'utf8'));
const encode = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
if (request.operation === 'sign') {
  const privateKey = request.privateJwk
    ? createPrivateKey({ key: request.privateJwk, format: 'jwk' })
    : generateKeyPairSync('ed25519').privateKey;
  const protectedHeader = encode(request.header);
  // Whitespace and property order intentionally need not match Python output.
  const payload = encode(request.payloadText ?? JSON.stringify(request.claims, null, 2));
  const signingInput = `${protectedHeader}.${payload}`;
  const signature = sign(null, Buffer.from(signingInput, 'ascii'), privateKey).toString('base64url');
  process.stdout.write(JSON.stringify({ token: `${signingInput}.${signature}`,
    publicJwk: createPublicKey(privateKey).export({ format: 'jwk' }),
    privateJwk: privateKey.export({ format: 'jwk' }) }));
} else if (request.operation === 'verify') {
  const parts = request.token.split('.');
  if (parts.length !== 3) throw new Error('compact JWS required');
  const publicKey = createPublicKey({ key: request.publicJwk, format: 'jwk' });
  const verified = verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
    publicKey, Buffer.from(parts[2], 'base64url'));
  process.stdout.write(JSON.stringify({ verified }));
} else {
  throw new Error('unknown operation');
}
