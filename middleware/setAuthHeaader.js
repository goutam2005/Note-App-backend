const isTokenExp = require("../utils/isTikenExp");
const refreshTokens = require("../utils/refreshToken");
const { setCookieToken } = require("../utils/setCookieToken");
const setAuthHeader = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (token || !isTokenExp(token)) {
            req.headers['authorization'] = `Bearer ${token}`
            return next();
        }
      
        if (!token || isTokenExp(accessToken)) {
            // Attempt to get a new access token using the refresh token
            const refreshTokencokie = req.cookies.RefreshToken;
            if (!refreshTokencokie) {
                // If refresh token is also missing, throw an error
                return res.status(401).json('Refresh token is missing');
            }
 
            // Access token is expired, make a refresh token request
            const { token, tokenExp, refreshToken, refreshTokenExp } = await refreshTokens(req, res)

            // set cookies
            setCookieToken(res, token, tokenExp, refreshToken, refreshTokenExp);

            //  Add the access token to the Authorization header
            req.headers['authorization'] = `Bearer ${token}`
        }        
        next();
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
};

module.exports = setAuthHeader;