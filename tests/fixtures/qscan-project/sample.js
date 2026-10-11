const crypto = require('node:crypto');
crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
