const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "MAIL_ADRESIN",
    pass: "GOOGLE_APP_PASSWORD"
  }
});

async function sendResetMail(to, token) {
  const link = `https://senin-site/reset.html?token=${token}`;

  await transporter.sendMail({
    from: '"Tauri App" <MAIL_ADRESIN>',
    to: to,
    subject: "Şifre sıfırlama",
    html: `
      <h2>Şifre sıfırlama</h2>
      <p>Yeni şifre belirlemek için linke tıkla:</p>
      <a href="${link}">${link}</a>
    `
  });
}

module.exports = sendResetMail;