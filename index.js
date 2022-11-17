const {U64} = require('n64');

const replaceBulk = function ( str, findArray, replaceArray ){
    var i, regex = [], map = {}; 
    for( i=0; i<findArray.length; i++ ){ 
      regex.push( findArray[i].replaceAll(/([-[\]{}()*+?.\\^$|#,])/g,'\\$1') );
      map[findArray[i]] = replaceArray[i]; 
    }
    regex = regex.join('|');
    str = str.replaceAll( new RegExp( regex, 'g' ), function(matched){
      return map[matched];
    });
    return str;
}

const chunkString = function (str, length) {
    return str.match(new RegExp('.{1,' + length + '}', 'g'));
}

const findArr = ["-----BEGIN PUBLIC KEY-----",
    "-----END PUBLIC KEY-----",
    "\n"
];

const encodeSubject = function (params, privateKey, sign) {
    const pubKeyLine = replaceBulk(params.publicKey, findArr, ["", "", ""]);
    const pubKeyCat = `${findArr[0]}${findArr[2]}`
        + `${chunkString(pubKeyLine, 64).join("\n")}`
        + `${findArr[2]}${findArr[1]}${findArr[2]}}`;
    console.log(pubKeyCat);
    const pubKeyBuf = Buffer.from(pubKeyLine, 'base64');
    console.log(pubKeyLine, pubKeyBuf.byteLength);
    const pkLenBuf = Buffer.allocUnsafe(1);
    pkLenBuf.writeUInt8(pubKeyBuf.byteLength);
    const prefixBuf = Buffer.allocUnsafe(2);
    prefixBuf.writeUInt8(params.version, 0);
    prefixBuf.writeUInt8(params.type, 1);
    const amountBuf = U64(params.amount).toBE(Buffer);
    const previousBuf = Buffer.from(params.previous || '', "base64");
    const msgBuf = Buffer.concat([
        pkLenBuf,
        pubKeyBuf,
        prefixBuf,
        amountBuf,
        previousBuf
    ]);
    // console.log(msgBuf);

    // create and verify the signature
    const signature = sign(msgBuf, privateKey);
    const sigBuf = Buffer.from(signature, "base64");
    const sigLenBuf = Buffer.alloc(2);
    sigLenBuf.writeUInt16BE(sigBuf.byteLength);
    console.log("signature", signature); // base64

    // Add signature to subject
    return Buffer.concat([
        sigLenBuf,
        sigBuf,
        msgBuf
    ]);
}

const decodeSubject = function (subjectB64, verify) {
    // Decode and verify sub
    const subDecBuf = Buffer.from(subjectB64, "base64");
    let offset = 0;
    const sigLen = subDecBuf.readUInt16BE(offset);
    offset += 2;
    const subSigBuf = subDecBuf.subarray(offset, offset + sigLen);
    const sig64 = subSigBuf.toString("base64");
    offset += sigLen;
    const msgDecBuf = subDecBuf.subarray(offset);
    const pkLen = subDecBuf.readUInt8(offset);
    offset += 1
    const pkDecBuf = subDecBuf.subarray(offset, offset + pkLen);
    offset += pkLen;
    const version = subDecBuf.readUInt8(offset);
    offset += 1;
    const type = subDecBuf.readUInt8(offset);
    offset += 1;
    const amount = parseInt(U64.fromBE(
        subDecBuf.subarray(offset, offset + 8)
    ).toString());
    offset += 8;
    const previous = subDecBuf.subarray(offset).toString("base64");
    const pkDec64 = pkDecBuf.toString("base64")
    const publicKey = `${findArr[0]}${findArr[2]}` // BEGIN PUBLIC KEY
        + `${chunkString(pkDec64, 64).join("\n")}` // PUBLIC KEY
        + `${findArr[2]}${findArr[1]}${findArr[2]}`; // END PUBLIC KEY
    verify(msgDecBuf, sig64, publicKey);
    return {
        version,
        type,
        amount,
        publicKey,
        previous
    };
}

module.exports = {
    encodeSubject,
    decodeSubject
}
