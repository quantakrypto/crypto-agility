// Independent JSON Schema 2020-12 consumer. This checks structural conformance,
// not evidence truth, issuer trust, negotiation, or semantic freshness policy.
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const input = JSON.parse(readFileSync(0, 'utf8'));
const ajv = new Ajv2020({ strict: false, allErrors: false, validateFormats: true });
addFormats(ajv);
const validate = ajv.compile(input.schema);
process.stdout.write(JSON.stringify(input.cases.map(item => ({ id: item.id, valid: validate(item.manifest) }))));
