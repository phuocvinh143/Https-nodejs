const crypto = require('crypto');

const {publicKey, privateKey} = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
});

const data = "task 2 kho vl";

const encryptedData = crypto.publicEncrypt(
    {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
    },
    Buffer.from(data)
)

const decryptedData = crypto.privateDecrypt(
    {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
    },
    Buffer.from(encryptedData)
)

console.log("encryptedData: ", encryptedData.toString("base64"))
console.log("decryptedData: ", decryptedData.toString())