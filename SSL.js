const crypto = require('crypto')
const express = require('express')
var app = express()
const bodyParser = require('body-parser')

var algorithm = 'aes256'
var inputEncoding = 'utf8'
var outputEncoding = 'hex'
var ivlength = 16

const getSignatureByInput = (input, key) => {
    let sign = crypto.createSign('RSA-SHA256')
    sign.update(input)
    let signature = sign.sign(key, 'hex')
  
    return signature
}

const getSignatureVerifyResult = (input, _publicKey, signatureSignedByPrivateKey) => {
    const verifier = crypto.createVerify('RSA-SHA256');

    verifier.update(input, 'ascii');

    const publicKeyBuf = Buffer.from(_publicKey, 'ascii');
    const signatureBuf = Buffer.from(signatureSignedByPrivateKey, 'hex');
    const result = verifier.verify(publicKeyBuf, signatureBuf);

    return result;
};

const hash = (input_text) => {
    hasher = crypto.createHash('sha256');
    hasher.update(input_text, 'utf8');
    hexString = hasher.digest('hex');
    return hexString;
}

const encrypt = (input_text, key) => {
    var iv = crypto.randomBytes(ivlength);
    var cipher = crypto.createCipheriv(algorithm, key, iv);
    var ciphered = cipher.update(input_text, inputEncoding, outputEncoding);
    ciphered += cipher.final(outputEncoding);
    var ciphertext = iv.toString(outputEncoding) + ':' + ciphered

    return ciphertext;
}

const decrypt = (hexString, key) => {
    var components = hexString.split(':');
    var iv_from_ciphertext = Buffer.from(components.shift(), outputEncoding);
    var decipher = crypto.createDecipheriv(algorithm, key, iv_from_ciphertext);
    var deciphered = decipher.update(components.join(':'), outputEncoding, inputEncoding);
    deciphered += decipher.final(inputEncoding);

    return deciphered;
}

// create key on server
const {publicKey, privateKey} = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

app.get('/cert', function(req, res) {
    // server cert
    var cert_encrypted = {
        'host': 'vinhmai.com',
        'public_key': 'a',
        'signature': 'b'
    }

    // export public key
    let privatePem = privateKey.export({ format: 'pem', type:  'pkcs1'});
    let _privateKey = privatePem.toString('ascii');

    // export private key
    let publicPem = publicKey.export({ format: 'pem', type:  'pkcs1'});
    let _publicKey = publicPem.toString('ascii');

    // sign
    cert_encrypted.public_key = _publicKey;
    cert_encrypted.signature = getSignatureByInput(cert_encrypted.host + cert_encrypted.public_key, _privateKey);

    res.json(cert_encrypted);
})

app.post('/ans', (req, res) => {
    let client_key = crypto.privateDecrypt(privateKey, Buffer.from(req.body.key))
    // log on server data has been taken from client within key send with
    console.log(decrypt(req.body.text, client_key.toString('ascii')))
    res.send('OK')
})

app.listen(3000, function() {
    console.log('Listening on port 3000')
})