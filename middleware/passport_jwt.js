const User = require("../moduls/User")
const {Strategy, ExtractJwt} = require("passport-jwt")
const passport = require("passport")
const dotenv = require("dotenv")
dotenv.config()

const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
}

const strategy = new Strategy(options, async (payload, done) => {
    if (!payload._id) {
        return done(null, false, { message: "Invalid token: missing user ID" })
    }

    try {
        const user = await User.findOne({ _id: payload._id }, "-password")
        if (user) {
           
            return done(null, user)
        }
        
        return done(null, false, { message: "User not found" })
    } catch (error) {
        console.error("Error in JWT strategy:", error)
        return done(error, false)
    }
})

passport.use(strategy)


