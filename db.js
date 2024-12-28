const mongoose = require('mongoose');


const connectDB = async (URI) => {
    try {
        await mongoose.connect(URI)
        console.log("Database connected");
    } catch (error) {
        console.log(error);
    }
}
module.exports = connectDB