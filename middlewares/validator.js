const Joi = require('joi');

exports.signupSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),

    password: Joi.string()
        .required()
        .min(8)
        .pattern(new RegExp('^[a-zA-Z0-9!@#$%^&*]{8,30}$'))
        .message('Password must be between 8 and 30 characters and include letters, numbers, or special characters like !@#$%^&*')
});

exports.signinSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),

    password: Joi.string()
        .required()
        .min(8)
        .pattern(new RegExp('^[a-zA-Z0-9!@#$%^&*]{8,30}$'))
        .message('Password must be between 8 and 30 characters and include letters, numbers, or special characters like !@#$%^&*')
});