const { User } = require('../models/user');
const express = require('express');
const router = express.Router();
const Joi = require('joi');
const _ = require('lodash');
const EC = require('elliptic').ec;
const crypto = require('crypto');

router.post('/', async (req, res) => {
    const { error } = validate(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
    }

    let user = await User.findOne({ name: req.body.name });
    if (!user) {
        return res.status(400).send('This is user doesn\'t exists!');
    }

    var ec = new EC('secp256k1');
    var pair_key = ec.keyFromPrivate(req.body.name);
    var private_key = pair_key.getPrivate("hex");

    var _public_key = user.public_key;

    var msg = req.body.name;
    var msgHash = crypto.createHash('sha256').update(msg).digest();

    var signature = ec.sign(msgHash, private_key, "hex", {canonical: true});

    var hex2dec = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);

    var public_key_recovered = ec.recoverPubKey(
        hex2dec(msgHash), signature, signature.recoveryParam, "hex"
    );

    var valid = public_key_recovered.encodeCompressed("hex") === _public_key;
    
    res.send(valid);
});

function validate(req) {
    const schema = Joi.object({
        name: Joi.string().min(5).max(255).required()
    })

    return schema.validate(req);
}

module.exports = router;