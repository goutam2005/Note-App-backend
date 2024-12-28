const express = require('express');
const User = require('../moduls/User'); // Adjust the path if needed
const Routes = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const emailotp = require('../utils/email-otp');
const EmailOTP = require('../moduls/Email-OTP');
const generateToken = require('../utils/generateToken');
const { setCookieToken } = require('../utils/setCookieToken');
const refreshTokens = require('../utils/refreshToken');
const setAuthHeader = require('../middleware/setAuthHeaader');
const userRefreshToken = require('../moduls/userRefreshToken');
const transport = require('../Email-verification');
const jwt = require('jsonwebtoken');

Routes.post('/CreateUser', [
    body('name', 'Name must be at least 3 characters').isLength({ min: 3 }),
    body('email', 'Email must be valid').isEmail(),
    body('password', 'Password must be at least 5 characters').isLength({ min: 5 }),
], async (req, res) => {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        // Check if the user already exists
        let user = await User.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).json({ error: "Sorry, a user with this email already exists" });
        }

        // Hash the password before saving
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        // Create new user
        user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword, // Save the hashed password
        });

        // Prepare JWT payload after user creation        
        emailotp(user, req);
        // Generate JWT token


        res.status(201).json({status: true, message: 'User created successfully', user });
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal server error");
    }

});
//login user
Routes.post('/login', [
    body('email', 'Email must be valid').isEmail(),
    body('password', 'Password cannot be blank').exists(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Please enter email and password" });
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: "Please try to login with correct credentials" });
        }

        const passwordCompare = await bcrypt.compare(password, user.password);
        if (!passwordCompare) {
            return res.status(400).json({ error: "Please try to login with correct credentials" });
        }
        if (!user.is_verified) {
            return res.status(400).json({ error: "Please verify your email" });
        }

        const { token, tokenExp, refreshToken, refreshTokenExp } = await generateToken(user)

        await userRefreshToken.findOneAndUpdate(
            { token: refreshToken },
            { $set: { blacklisted: false } },
            { new: true } // Returns the updated document
        );
        setCookieToken(res, token, tokenExp, refreshToken, refreshTokenExp);

        return res.status(201).json({ message: 'User logged in successfully', token, token, tokenExp, refreshToken, refreshTokenExp, user });
    } catch (errors) {
        console.error(errors);
        res.status(500).send("Internal server error");
    }
})

Routes.post('/verify-email', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!email || !otp) {
            return res.status(400).json({ error: "Please fill all the details" });
        }

        if (!user) {
            return res.status(400).json({ error: "Please try to login with correct credentials" });
        }

        if (user.is_verified) {
            return res.status(400).json({ error: "User already verified" });
        }

        const email_verify = await EmailOTP.findOne({ userId: user._id, otp });

        // Check if email_verify is falsy (i.e., null, undefined, etc.)
        if (!email_verify) {

            if (!user.is_verified) {
                await emailotp(user);
                return res.status(400).json({ error: "Invalid OTP, New OTP sent to your email" });
            }
            return res.status(400).json({ error: "Invalid OTP, please enter a valid OTP" });
        }

        const now = new Date();
        const expireotp = new Date(email_verify.createdAt.getTime() + 10 * 60 * 1000);

        if (expireotp < now) {
            await emailotp(user);
            return res.status(400).json({ error: "OTP expired, New OTP sent to your email" });
        }

        user.is_verified = true;
        await user.save();
        await EmailOTP.deleteOne({ userId: user._id });

        return res.status(200).json({ message: "User verified successfully" });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
});

Routes.post('/newtoken', async (req, res) => {
    try {
        const { token, tokenExp, refreshToken, refreshTokenExp } = await refreshTokens(req, res);

        setCookieToken(res, token, tokenExp, refreshToken, refreshTokenExp);

        return res.status(200).json({ message: 'Token refreshed successfully', token, tokenExp, refreshToken, refreshTokenExp });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: 'Internal server error' });
    }
})

Routes.get('/profile', setAuthHeader, passport.authenticate('jwt', { session: false }), async (req, res) => {
    return res.send({ user: req.user });
})

Routes.get('/logout', setAuthHeader, passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        res.clearCookie('token');
        res.clearCookie('RefreshToken');
        res.clearCookie('is_auth');
        const refreshToken = req.cookies.RefreshToken;
        const userRefresh = await userRefreshToken.findOneAndUpdate(
            { token: refreshToken },
            { $set: { blacklisted: true } },
            { new: true } // Returns the updated document
        );
        return res.status(200).json({ message: "User logged out successfully" });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error vvvv" });
    }

})

Routes.post('/change-password', setAuthHeader, passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;

        // Validate inputs
        if (!oldPassword || typeof oldPassword !== "string") {
            return res.status(400).json({ error: "Old password is required and must be a string" });
        }

        if (!newPassword || typeof newPassword !== "string") {
            return res.status(400).json({ error: "New password is required and must be a string" });
        }

        // Find user by ID

        const user = await User.findById(req.user._id);

        // Check if user exists and has a valid password
        if (!user || !user.password || typeof user.password !== "string") {
            return res.status(404).json({ error: "User not found or invalid password stored" });
        }

        // Compare old password
        console.log("Comparing passwords...");
        const passwordCompare = await bcrypt.compare(oldPassword, user.password);

        if (!passwordCompare) {
            return res.status(400).json({ error: "Incorrect old password" });
        }

        // Hash new password and save
        console.log("Hashing new password...");
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        await user.save();

        return res.status(200).json({ message: "Password changed successfully" });
    } catch (error) {
        console.error("Error during password change:", error);
        return res.status(500).json({ error: "Internal server error" });
    }

})

Routes.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        console.log(process.env.JWT_SECRET)
        // Generate reset token
        const resetToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });

        // Send reset token via email
        const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Password Reset",
            html: `
                <p>Hi ${user.name},</p>
                <p>Click the link below to reset your password:</p>
                <p><a href="${resetLink}">Reset Password</a></p>
            `
        };
        // Send the email
        transport.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
            } else {
                ("Email sent:", info.response);
            }
        });

        return res.status(200).json({ message: "Password reset link sent to your email", resetToken });
    } catch (error) {
        console.error("Error during password reset:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
})
Routes.post('/reset-password/:token', async (req, res) => {
    const { newPassword } = req.body;
    const { token } = req.params;

    if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters long" });
    }

    let decoded;
    try {
        // Verify the reset token
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        if (error.name === "TokenExpiredError") {
            return res.status(400).json({ error: "Reset token has expired" });
        } else if (error.name === "JsonWebTokenError") {
            return res.status(400).json({ error: "Invalid reset token" });
        }
        console.error("JWT verification error:", error);
        return res.status(500).json({ error: "Internal server error" });
    }

    try {
        // Find the user by email
        
        const user = await User.findOne({ _id: decoded.userId });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Hash new password and save
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        user.password = hashedPassword;
        await user.save();

        return res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
        console.error("Error during password reset:", error);
        return res.status(500).json({ error: "Internal server error" });
    }
});

module.exports = Routes;
