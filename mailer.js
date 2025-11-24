// mailer.js
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendOtpEmail(to, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject: 'Your Jugaad OTP',
    text: `Your Jugaad verification code is ${otp}. It is valid for 5 minutes.`
  };

  await transporter.sendMail(mailOptions);
}

module.exports = sendOtpEmail;
