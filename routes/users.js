const {User, validate} = require('../models/user');
const express = require('express');
const router = express.Router();
const _ = require('lodash');
const EC = require('elliptic').ec;

router.post('/', async (req, res) => {
    const {error} = validate(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
    }

    var ec = new EC('secp256k1');
    var pair_key = ec.keyFromPrivate(req.body.name);
    var _public_key = pair_key.getPublic();

    let user = await User.findOne({name: req.body.name});
    if (user) {
        return res.status(400).send('That user already exists!');
    } else {
        user = new User({
            name: req.body.name,
            public_key: _public_key.encodeCompressed("hex")
        });
        await user.save();
        res.status(200).send("OK!");
    }
});

module.exports = router;