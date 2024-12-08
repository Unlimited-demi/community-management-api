// utils/passwordUtils.js
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const sendResetPasswordEmail = async (recipient, subject, text) => {
  try {
    const mailOptions = {
      from: 'Techoshere Nigeria', 
      to: recipient, 
      subject: subject,
      text: text, 
    };
    console.log(recipient)
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
      logger: true,    
    //   debug: true,    
    });

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent: %s', info.messageId);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Email sending failed');
  }
};

module.exports = { sendResetPasswordEmail };