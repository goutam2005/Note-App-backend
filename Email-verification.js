const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

let transport = nodemailer.createTransport({
    service: 'gmail',
    host: process.env.EMIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

module.exports = transport
