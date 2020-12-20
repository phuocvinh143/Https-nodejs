const Joi = require('joi');
const mongoose = require('mongoose');

const User = mongoose.model('User', mongoose.Schema({
    name: {
        type: String,
        required: true,
        minLength: 5,
        maxLength: 50,
        unique: true
    },
    public_key: {
        type: String,
        minLength: 5,
        maxLength: 255,
        unique: true
    }
}));

function validateUser(user) {
    const schema = Joi.object({
        name: Joi.string().min(5).max(50).required(),
        public_key: Joi.string().min(5).max(255)
    })
    return schema.validate(user);
}

exports.User = User;
exports.validate = validateUser;