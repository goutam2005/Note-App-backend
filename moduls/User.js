const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name:{
        type: String,
        required: true
    },
    email:{
        type: String,
        required: true,
        unique : true
    },
    password:{
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ["user", "admin"],
        default: "user"
    },
    date:{
        type: Date,
        default: Date.now
    },
    is_verified:{
        type: Boolean,
        default: false
    }
})
const User = mongoose.model('User', userSchema);
// User.createIndexes();
module.exports = User;