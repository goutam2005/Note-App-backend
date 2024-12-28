const User = require("../moduls/User");
const userRefreshToken = require("../moduls/userRefreshToken");
const Generate = require("./generateToken");
const verifyRefreshToken = require("./verify-refreshtoken");

const refreshToken = async (req, res) => {
    const oldToken = req.cookies.RefreshToken;

    const { payload, error } = await verifyRefreshToken(oldToken)
   
    if (error) {
        return res.status(401).json({ error: "Invalid refresh token" });
    }
    const user = await User.findById(payload._id);
    if (!user) {
        return res.status(401).json({ error: "User not found" });
    }

   

    const RefreshToken = await userRefreshToken.findOne({ user_id: payload._id });

    if (oldToken !== RefreshToken.token || RefreshToken.blacklisted) {
        return res.status(401).json({ error: "Invalid refresh token " });
    }
    
    const { token, tokenExp, refreshToken, refreshTokenExp } = await Generate(user);
    

    return {
        token, tokenExp, refreshToken, refreshTokenExp
    }
}

module.exports = refreshToken