# relay-jwt
Tools for constructing and parsing the subject field for the Badger Relay Server JWT

# Install

```bash
$ npm install jsonwebtoken
$ npm install relay-jwt
```

Installing ```jsonwebtoken``` will install ```jwa```, which is a necessary requirement for this module.

# Usage

Example:

```js
const jwt = require('jsonwebtoken');
const jwa = require('jwa');
const crypto = require('crypto');
const { 
    decodeSubjectChain,
    encodeSubject, 
    calculateGross,
    calculateNet
} = require("relay-jwt");

// Set algorithm
const algorithm = 'ES256';
// create jwa object
const ecdsa = jwa(algorithm);

// Parameters for the relays, with Relay 0 at the 0 index
const chainParams = [
    {
        type: 0,
        amount: 50
    },
    {
        type: 1,
        amount: 5000
    },
    {
        type: 0,
        amount: 80
    }
];

let subject = '';
let privateKey;
let publicKey;

for (let i = 0; i < chainParams.length; i++ ) {
// Generate a new random keypair in PEM format
    const keyPair = crypto.generateKeyPairSync( 'ec', {
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

    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    // Create base fee subject
    const subParams = {
        version: 1, // Int - 1 is standard
        type: chainParams[i].type, // 0 = percentage, 1 = fixed
        amount: chainParams[i].amount, // Int - If percentage, amount/1000 / if fixed, base units
        publicKey, // PEM encoded string
        previous: subject
    };

    subject = encodeSubject(subParams, privateKey, ecdsa.sign).toString("base64");
}

// Do the token
// generate token with relay jwt subject
const token = jwt.sign({}, privateKey, { 
    algorithm,
    subject
});
// decode token
const decoded = jwt.decode(token)
// Decode subject chain. Returns array of subParams objects as above
// Index 0 represents first fee to be added (first relay server to receive request)
// Last index represents BUX API (Relay 0)
const decodedChain = decodeSubjectChain(decoded.sub, ecdsa.verify);
console.log("decodedChain", decodedChain);
// First public key in subject must match public key for token
const verified = jwt.verify(token, decodedChain[0].publicKey);
console.log("jwt verified?", verified ? true : false);

// Do some fee calculations
// Calculate the total amount paid if the merchant submits 10
const gross = calculateGross(10, decodedChain, 4);
console.log("gross", gross);
// Calculate the amount the merchant must submit for the customer to pay 10
const net = calculateNet(10, decodedChain, 4);
console.log("net", net);
```