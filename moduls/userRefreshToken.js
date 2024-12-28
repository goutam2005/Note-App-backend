const mongoose = require('mongoose');

const userRefreshTokenSchema = new mongoose.Schema({
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true

    },
    token: {
        type: String,
        required: true
    },
    blacklisted: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 60 * 60 * 24 * 5 // 5 days
    }
})

module.exports = mongoose.model("UserRefreshToken", userRefreshTokenSchema);