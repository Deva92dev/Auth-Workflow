import { sendEmail } from './sendEmail';

interface SendResetPasswordEmailType {
  name: string;
  email: string;
  token: string;
  origin: string;
}

export const sendResetPasswordEmail = async ({
  name,
  email,
  token,
  origin,
}: SendResetPasswordEmailType) => {
  const resetURL = `${origin}/user/reset-password?token=${token}&email=${email}`;
  const message = `<p>Please reset password by clicking the following link : <a href="${resetURL}">Reset Password</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h4>Hello, ${name}</h4> ${message}`,
  });
};
