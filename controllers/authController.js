const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const { signupSchema, signinSchema, acceptCodeSchema, changePasswordSchema, acceptFPCodeSchema } = require("../middlewares/validator");
const User = require("../models/usersModel");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashin");
const transport = require('../middlewares/sendMail');

exports.signup = async (req, res) => {
    const { email, password } = req.body;

    try {
        const { error, value } = signupSchema.validate({ email, password });
        if (error) {
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ success: false, message: "User already exists!" });
        }

        const hashedPassword = await doHash(password, 12);
        const newUser = new User({ email, password: hashedPassword });
        const result = await newUser.save();
        result.password = undefined;

        return res.status(201).json({
            success: true,
            message: "Account created successfully",
            result,
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.signin = async (req, res) => {
    const { email, password } = req.body;

    try {
        const { error, value } = signinSchema.validate({ email, password });
        if (error) {
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        const existingUser = await User.findOne({ email }).select('+password');
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        const isValidPassword = await doHashValidation(password, existingUser.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: "Credentials invalid!" });
        }

        const token = jwt.sign(
            { userId: existingUser._id, email: existingUser.email, verified: existingUser.verified },
            process.env.TOKEN_SECRET,
            { expiresIn: '8h' }
        );

        res.cookie('Authorization', 'Bearer ' + token, {
            expires: new Date(Date.now() + 8 * 3600000),
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NODE_ENV === 'production',
        });

        return res.status(200).json({
            success: true,
            token,
            message: "Logged in successfully",
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.signout = async (req, res) => {
    res.clearCookie('Authorization').status(200).json({ success: true, message: 'Logged out successfully' });
};

exports.sendVerificationCode = async (req, res) => {
    const { email } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        if (existingUser.verified) {
            return res.status(400).json({ success: false, message: "You are already verified!" });
        }

        const codeValue = Math.floor(Math.random() * 1000000).toString();
        const info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: "Verification code",
            html: `<h1>${codeValue}</h1>`
        });

        if (info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now();
            await existingUser.save();
            return res.status(200).json({ success: true, message: 'Code sent!' });
        }
        return res.status(400).json({ success: false, message: 'Code sending failed!' });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.verificationCode = async (req, res) => {
    const { email, providedCode } = req.body;

    try {
        const { error } = acceptCodeSchema.validate({ email, providedCode });
        if (error) {
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        const existingUser = await User.findOne({ email }).select("+verificationCode +verificationCodeValidation");
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        if (existingUser.verified) {
            return res.status(400).json({ success: false, message: "You are already verified!" });
        }

        if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
            return res.status(400).json({ success: false, message: "Invalid code or validation data!" });
        }

        const expirationTime = 5 * 60 * 1000;
        if (Date.now() - existingUser.verificationCodeValidation > expirationTime) {
            return res.status(400).json({ success: false, message: "Code expired!" });
        }

        const hashedCodeValue = hmacProcess(providedCode.toString(), process.env.HMAC_VERIFICATION_CODE_SECRET);
        if (hashedCodeValue !== existingUser.verificationCode) {
            return res.status(400).json({ success: false, message: "Invalid verification code!" });
        }

        existingUser.verified = true;
        existingUser.verificationCode = undefined;
        existingUser.verificationCodeValidation = undefined;
        await existingUser.save();

        return res.status(200).json({ success: true, message: "Your account is verified!" });
    } catch (error) {
        console.error("Verification Error:", error.message);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.changePassword = async (req, res) => {
    const { userId, verified } = req.user;
    const { oldPassword, newPassword } = req.body;

    try {
        const { error } = changePasswordSchema.validate({ oldPassword, newPassword });
        if (error) {
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        if (!verified) {
            return res.status(401).json({ success: false, message: 'You are not verified' });
        }

        const existingUser = await User.findOne({ _id: userId }).select('+password');
        if (!existingUser) {
            return res.status(404).json({ success: false, message: 'User does not exist!' });
        }

        const isValidPassword = await doHashValidation(oldPassword, existingUser.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Invalid credentials!' });
        }

        const hashedPassword = await doHash(newPassword, 12);
        existingUser.password = hashedPassword;
        await existingUser.save();

        return res.status(200).json({ success: true, message: 'Password updated successfully!' });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.sendForgotPasswordCode = async (req, res) => {
    const { email } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        const codeValue = Math.floor(Math.random() * 1000000).toString();
        const info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: "Forgot Password Code",
            html: `<h1>${codeValue}</h1>`
        });

        if (info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
            existingUser.forgotPasswordCode = hashedCodeValue;
            existingUser.forgotPasswordCodeValidation = Date.now();
            await existingUser.save();
            return res.status(200).json({ success: true, message: 'Code sent!' });
        }
        return res.status(400).json({ success: false, message: 'Failed to send code!' });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.verifyForgotPasswordCode = async (req, res) => {
    const { email, providedCode } = req.body;

    try {
        const { error } = acceptFPCodeSchema.validate({ email, providedCode });
        if (error) {
            return res.status(400).json({ success: false, message: error.details[0].message });
        }

        const existingUser = await User.findOne({ email }).select("+forgotPasswordCode +forgotPasswordCodeValidation");
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        if (!existingUser.forgotPasswordCode || !existingUser.forgotPasswordCodeValidation) {
            return res.status(400).json({ success: false, message: "Invalid code or validation data!" });
        }

        const expirationTime = 10 * 60 * 1000; 
        if (Date.now() - existingUser.forgotPasswordCodeValidation > expirationTime) {
            return res.status(400).json({ success: false, message: "Code expired!" });
        }

        const hashedCodeValue = hmacProcess(providedCode.toString(), process.env.HMAC_VERIFICATION_CODE_SECRET);
        if (hashedCodeValue !== existingUser.forgotPasswordCode) {
            return res.status(400).json({ success: false, message: "Invalid code!" });
        }

        return res.status(200).json({ success: true, message: "Code validated!" });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};
