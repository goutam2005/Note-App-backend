const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const EmailOTP = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 600 // 10 minutes
    }
})
module.exports = mongoose.model('EmailOTP', EmailOTP);