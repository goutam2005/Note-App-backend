const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const userRefreshToken = require('../moduls/userRefreshToken');
dotenv.config();

const Generate = async (user) => {
    try {
        if (!process.env.JWT_SECRET || !process.env.RefreshTokenSecret) {
            throw new Error("Token secrets are not defined in environment variables.");
        }

        const tokenExpiry = process.env.TOKEN_EXPIRY || '2m';
        const refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '5d';

        const payload = {
            _id: user._id,
            role: user.role,
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: tokenExpiry });
        const refreshToken = jwt.sign(payload, process.env.RefreshTokenSecret, { expiresIn: refreshTokenExpiry });

        await userRefreshToken.findOneAndUpdate(
            { user_id: user._id },
            { token: refreshToken },
            { upsert: true }
        );

        const tokenExp = Math.floor(Date.now() / 1000) + 60 * 2; // 2 minutes
        const refreshTokenExp = Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 5; // 5 days
     
        return {
            token, tokenExp, refreshToken, refreshTokenExp,
        };

    } catch (error) {
        console.error("Error generating tokens:", error.message);
        throw error;
    }
};

module.exports = Generate;
