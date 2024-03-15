import nodemailer from 'nodemailer';
import nodemailerConfig from './nodemailerConfig';

interface EmailDescType {
  to: string;
  subject: string;
  html: string;
}

export const sendEmail = async ({ to, subject, html }: EmailDescType) => {
  let testAccount = await nodemailer.createTestAccount();

  const transporter = nodemailer.createTransport(nodemailerConfig);

  return transporter.sendMail({
    from: '"Codding Addict 👻" <coddingaddict@hotmail.com>',
    to,
    subject,
    html,
  });
};
