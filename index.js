const {U64} = require('n64');

const isBase64 = function (str) {
    const base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
    return base64regex.test(str);
}

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
    const pubKeyBuf = Buffer.from(pubKeyLine, 'base64');
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
    const verified = verify(msgDecBuf, sig64, publicKey);
    if (!verified)
        throw new Error("Invalid signature in subject");
    return {
        version,
        type,
        amount,
        publicKey,
        previous
    };
}

const decodeSubjectChain = function (subjectB64, verify) {
    const decodedSub = decodeSubject(subjectB64, verify);

    const decodedChain = [decodedSub];
    let previous = decodedSub.previous;
    while (previous.length > 0) {
        const decodedPrev = decodeSubject(previous, verify);
        decodedChain.push(decodedPrev);
        previous = decodedPrev.previous;
    }
    return decodedChain;
}

const calculateGross = function (netAmount, subjectChain, decimals) {
    if (!Number.isInteger(decimals))
        throw new Error ("Must specify decimal precision (int) for token / currency");
    if (!Number.isInteger(netAmount))
        throw new Error ("Invalid netAmount. Must be a number");
    if (!Array.isArray(subjectChain))
        throw new Error ("Subject chain array must be provided")

    for (let i = 0; i < subjectChain.length; i++) {
        const cert = subjectChain[i];
        if (cert.type === 0) {
            // calculate by percentage (amount value is x/1000)
            netAmount += netAmount * (cert.amount / 1000);
        } else if (cert.type === 1) {
            netAmount += cert.amount / (10 ** decimals);
        } else {
            throw new Error("Invalid type in certificate");
        }
    }

    return netAmount;
}

const calculateNet = function (grossAmount, subjectChain, decimals) {
    if (!Number.isInteger(decimals))
        throw new Error ("Must specify decimal precision (int) for token / currency");
    if (!Number.isInteger(grossAmount))
        throw new Error ("Invalid grossAmount. Must be a number");
    if (!Array.isArray(subjectChain))
        throw new Error ("Subject chain array must be provided")

    for (let i = subjectChain.length - 1; i >= 0; i--) {
        const cert = subjectChain[i];
        if (cert.type === 0) {
            // calculate by percentage (amount value is x/1000)
            grossAmount = grossAmount / (1 + (cert.amount / 1000));
        } else if (cert.type === 1) {
            grossAmount -= cert.amount / (10 ** decimals);
        } else {
            throw new Error("Invalid type in certificate");
        }
    }

    return Number(grossAmount.toFixed(decimals));
}

module.exports = {
    encodeSubject,
    decodeSubject,
    decodeSubjectChain,
    calculateGross,
    calculateNet
}
