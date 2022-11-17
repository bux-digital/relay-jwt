# relay-jwt
Tools for constructing and parsing the subject field for the Badger Relay Server JWT

# Install

```bash
$ npm install jsonwebtoken
$ npm install relayjwt
```

Installing ```jsonwebtoken``` will install ```jwa```, which is a necessary requirement for this module.

# Usage

Example:

```js
const jwt = require('jsonwebtoken');
const jwa = require('jwa');
const crypto = require('crypto');
const { decodeSubject, encodeSubject } = require("relay-jwt");

// Generate a new random keypair in PEM format
const { 
    publicKey, 
    privateKey 
} = crypto.generateKeyPairSync( 'ec', {
    namedCurve: 'secp256k1',
    'publicKeyEncoding': {
        'type': 'spki',
        'format': 'pem'
    },
    'privateKeyEncoding': {
        'type': 'pkcs8',
        'format': 'pem'
    }
});

// Create base fee subject
const subParams = {
    version: 1, // Int - 1 is standard
    type: 0, // 0 = percentage, 1 = fixed
    amount: 50, // Int - If percentage, amount/1000 / if fixed, base units
    publicKey, // PEM encoded string
    previous: '' // string (optional) - base64 of subject of JWT token for upstream relay
};

// Do the token
// Set algorithm
const algorithm = 'ES256';
// create jwa object
const ecdsa = jwa(algorithm);
// generate token with relay jwt subject
const token = jwt.sign({}, privateKey, { 
    algorithm,
    subject: encodeSubject(subParams, privateKey, ecdsa.sign).toString("base64")
});
// decode token
const decoded = jwt.verify(token, publicKey);
// decode subject. Returns same object as subParams
// Throws error if doesn't verify
const decodedSub = decodeSubject(decoded.sub, ecdsa.verify);
// First public key in subject must match public key for token
console.log("public keys match?", publicKey === decodedSub.publicKey);
```