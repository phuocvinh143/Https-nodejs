const request = require('request')
const crypto = require('crypto')
const bodyParser = require('body-parser')

var algorithm = 'aes256'
var inputEncoding = 'utf8'
var outputEncoding = 'hex'
var ivlength = 16

const getSignatureVerifyResult = (input, _publicKey, signatureSignedByPrivateKey) => {
    const verifier = crypto.createVerify('RSA-SHA256')

    verifier.update(input, 'ascii')

    const publicKeyBuf = Buffer.from(_publicKey, 'ascii')
    const signatureBuf = Buffer.from(signatureSignedByPrivateKey, 'hex')
    const result = verifier.verify(publicKeyBuf, signatureBuf)

    return result
}

const encrypt = (input_text, key) => {
    var iv = crypto.randomBytes(ivlength)
    var cipher = crypto.createCipheriv(algorithm, key, iv)
    var ciphered = cipher.update(input_text, inputEncoding, outputEncoding)
    ciphered += cipher.final(outputEncoding)
    var ciphertext = iv.toString(outputEncoding) + ':' + ciphered

    return ciphertext
}

const decrypt = (hexString, key) => {
    var components = hexString.split(':')
    var iv_from_ciphertext = Buffer.from(components.shift(), outputEncoding)
    var decipher = crypto.createDecipheriv(algorithm, key, iv_from_ciphertext)
    var deciphered = decipher.update(components.join(':'), outputEncoding, inputEncoding)
    deciphered += decipher.final(inputEncoding)

    return deciphered
}

let _response = "error!"
const client_symmetric_key = "ciw7p02f70000ysjon7gztjn71234567"

request.get('http://localhost:3000/cert', (err, res, body) => {
    if (err) 
        throw err

    let obj = JSON.parse(body)

     // client take the public key of server and encrypt a symmetric key by public key and send it back to server
    if (getSignatureVerifyResult(obj.host + obj.public_key, obj.public_key, obj.signature)) {
        client_key_encrypted = crypto.publicEncrypt(obj.public_key, Buffer.from(client_symmetric_key))
        _response = client_key_encrypted
    }   

    // send key and data (B1805835) if everything is OK
    if (_response !== 'error!') {
        request({
            url: 'http://localhost:3000/ans', 
            method: 'POST',
            json: {text: encrypt('B1805835', client_symmetric_key), key: _response}
        }, (err, res, body) => {
            if (err) throw err
            console.log('OK')
        })
    }
})