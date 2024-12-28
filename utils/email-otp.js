const EmailOTP = require("../moduls/Email-OTP");
const transport = require("../Email-verification");
const dotenv = require("dotenv");

dotenv.config();

const emailotp = async (user) => {
    try {
        // Generate a 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
         
        // Save OTP to database with expiration
        await EmailOTP.create({
            userId: user._id,
            otp: otp,
            expiresAt: Date.now() + 10 * 60 * 1000 // OTP valid for 10 minutes
        });

        // Generate the verification link
        const otplink = `${process.env.CLIENT_URL}/account/verify-email`;
      
        // Email options
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "Email Verification",
            html: `
                <p>Hi ${user.name},</p>
                <p>Verify your email address by clicking the link below:</p>
                <p><a href="${otplink}">Verify Email</a></p>
                <h3>Your OTP: ${otp}</h3>
                <p>This OTP will expire in 10 minutes.</p>
            `
        };

        // Send the email
        transport.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
            } else {
                ("Email sent:", info.response);
            }
        });

        return { otp };

    } catch (error) {
        console.error("Error in emailotp:", error);
        throw new Error("Failed to send OTP email.");
    }
};

module.exports = emailotp;
