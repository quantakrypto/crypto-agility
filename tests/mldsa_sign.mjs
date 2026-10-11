// Independent JWS producer using maintained Node.js crypto (RFC9964 pure ML-DSA).
import { generateKeyPairSync, sign, createHash } from 'node:crypto'
let input = ''
for await (const part of process.stdin) input += part
const { claims, header, mode = 'normal', keyType = 'ml-dsa-65' } = JSON.parse(input)
const { privateKey, publicKey } = generateKeyPairSync(keyType)
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url')
const unsigned = `${encode(header)}.${encode(claims)}`
const message = mode === 'prehashed' ? createHash('sha256').update(unsigned).digest() : Buffer.from(unsigned)
const options = mode === 'context' ? { key: privateKey, context: Buffer.from('not-empty') } : privateKey
const signature = sign(null, message, options)
process.stdout.write(JSON.stringify({
  token: `${unsigned}.${signature.toString('base64url')}`,
  publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  algorithm: publicKey.asymmetricKeyType,
  node: process.version,
  openssl: process.versions.openssl
}))
