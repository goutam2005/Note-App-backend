export const setCookieToken = (res,  token, tokenExp, refreshToken, refreshTokenExp) => {
    
    const tokenMaxAge = (tokenExp - Math.floor(Date.now() / 1000)) * 1000; 
    const RefreshTokenMaxAge = (refreshTokenExp - Math.floor(Date.now() / 1000)) * 1000; // 

    if (tokenMaxAge > 0) {
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: tokenMaxAge,
            secure: true,
        });
    } else {
        console.warn("Skipping setting 'token' cookie because maxAge is invalid.");
    }

    if (RefreshTokenMaxAge > 0) {
        res.cookie('RefreshToken', refreshToken, {
            httpOnly: true,
            maxAge: RefreshTokenMaxAge,
            secure: true,
        });

        res.cookie('is_auth', true, {
            httpOnly: false,
            maxAge: RefreshTokenMaxAge,
            secure: true,
        });
    } else {
        console.warn("Skipping setting 'RefreshToken' cookies because maxAge is invalid.");
    }
};
