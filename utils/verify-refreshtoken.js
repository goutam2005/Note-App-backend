const jwt = require('jsonwebtoken');
const userRefreshTokenSchema = require('../moduls/userRefreshToken');
const verifyRefreshToken = async (refreshToken) => {
    try {
        const RefreshTokenSecret = process.env.RefreshTokenSecret;
   
        const userRefreshToken = await userRefreshTokenSchema.findOne({
            token: refreshToken
        });
        
      
        if (!userRefreshToken) {
            throw new Error('Refresh token not found');
        }
        const payload = jwt.verify(refreshToken, RefreshTokenSecret);
        return {
            payload,
            error: false

        }
    } catch (error) {
        throw new Error('Invalid refresh token');

    }

}
module.exports = verifyRefreshToken;