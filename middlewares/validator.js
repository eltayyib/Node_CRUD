const Joi = require('joi');

// Schema for signup
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

// Schema for signin
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

// Schema for accepting code (for forgot password)
exports.acceptCodeSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),
    providedCode: Joi.number()
        .required()
});

exports.changePasswordSchema = Joi.object({
    newPassword: Joi.string()
        .required()
        .min(8)
        .pattern(new RegExp('^[a-zA-Z0-9!@#$%^&*]{8,30}$'))
        .message('Password must be between 8 and 30 characters and include letters, numbers, or special characters like !@#$%^&*'),
    oldPassword: Joi.string()
        .required()
        .min(8)
        .pattern(new RegExp('^[a-zA-Z0-9!@#$%^&*]{8,30}$'))
        .message('Password must be between 8 and 30 characters and include letters, numbers, or special characters like !@#$%^&*')
});


exports.acceptFPCodeSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({ tlds: { allow: ['com', 'net'] } }),
    providedCode: Joi.number()
        .required(),
});

exports.createPostSchema = Joi.object({
    title: Joi.string()
        .min(6)
        .max(60)
        .required(),
     
    description: Joi.string()
        .min(6)
        .max(60)
        .required()
});
