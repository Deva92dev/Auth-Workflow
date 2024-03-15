import { sendEmail } from './sendEmail';

interface VerificationEmailType {
  name: string;
  email: string;
  verificationToken: string;
  origin: string;
}

export const sendVerificationEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}: VerificationEmailType) => {
  // the following route has to be present on the frontend
  const verifyEmail = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  const message = `<p>Please confirm your email by clicking on the following link: <a href="${verifyEmail}">Verify Email</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Confirmation Email',
    html: `<h4>Hello ${name} </h4>
    ${message}
    `,
  });
};
