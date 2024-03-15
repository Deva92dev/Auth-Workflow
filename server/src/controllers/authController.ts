import { Request, Response } from 'express';
import { User } from '../models/userModel';
import { Token } from '../models/tokenModel';
import { StatusCodes } from 'http-status-codes';
import { attachCookiesToResponse } from '../utils/jwtutils';
import { createUserToken } from '../utils/createTokenUser';
import crypto from 'crypto';
import { UserRequest } from '../types';
import { sendVerificationEmail } from '../utils/sendVerificationEmail';
import { sendResetPasswordEmail } from '../utils/sendResetPasswordEmail';
import { hashString } from '../utils/createHash';

export const register = async (req: Request, res: Response) => {
  const { email, name, password } = req.body;
  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    res.status(StatusCodes.BAD_REQUEST).send('Email already exists');
  }

  // first registered user is admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');
  const user = await User.create({
    email,
    name,
    password,
    role,
    verificationToken,
  });

  // add proper url for production one, here
  const origin = 'http://localhost:3000';

  // all these things(up to line 43) can get from req object
  // const newOrigin = req.get('origin');
  // const protocol = req.protocol;
  // const host = req.get('host');
  // console.log(`origin : ${newOrigin}`);
  // console.log(`protocol: ${protocol}`);
  // console.log(`host : ${host}`);
  // const forwardedHost = req.get('x-forwarded-host');
  // const forwardedProtocol = req.get('x-forwarded-proto');
  // console.log(`forwarded Host: ${forwardedHost}`);
  // console.log(`forwarded Protocol : ${forwardedProtocol}`);

  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });

  // send verification token while testing in postman
  res.status(StatusCodes.CREATED).json({
    msg: 'Success ! Please check your email to verify your account',
  });
};

export const verifyEmail = async (req: UserRequest, res: Response) => {
  const { verificationToken, email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(StatusCodes.UNAUTHORIZED).json({ msg: 'Verification Failed' });
  }

  if (user.verificationToken !== verificationToken) {
    res.status(StatusCodes.UNAUTHORIZED).json({ msg: 'Verification Failed' });
  }

  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = '';

  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email Verified' });
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res
      .status(StatusCodes.BAD_REQUEST)
      .send('provide email or password');
  }
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(StatusCodes.UNAUTHORIZED).send('There is no such user');
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    return res.status(StatusCodes.UNAUTHORIZED).send('Invalid credentials');
  }
  if (!user.isVerified) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ msg: 'Please verify your email' });
  }

  const tokenUser = createUserToken(user);
  // after lecture 358,create refresh token, 'let' lets you hint but 'const' not
  let refreshToken = '';
  // check for existing token
  const existingToken = await Token.findOne({ user: user._id });

  if (existingToken) {
    const { isValid } = existingToken;
    if (!isValid) {
      res.status(StatusCodes.UNAUTHORIZED).json({ msg: 'Invalid credentials' });
    }
    refreshToken = existingToken.refreshToken;
    attachCookiesToResponse(res, tokenUser, refreshToken);
    res.status(StatusCodes.OK).json({ user: tokenUser });
    return;
  }

  refreshToken = crypto.randomBytes(40).toString();
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  const userToken = { refreshToken, ip, userAgent, user: user._id };

  await Token.create(userToken);

  attachCookiesToResponse(res, tokenUser, refreshToken);
  res.status(StatusCodes.OK).json({ user: tokenUser });
};

export const logout = async (req: UserRequest, res: Response) => {
  try {
    await Token.findOneAndDelete({ user: req.user.userId });

    // because we have 2 cookies
    res.cookie('accessToken', 'logout', {
      httpOnly: true,
      expires: new Date(Date.now()),
    });

    res.cookie('refreshToken', 'logout', {
      httpOnly: true,
      expires: new Date(Date.now()),
    });
    res.status(StatusCodes.OK).json({ msg: 'User logged out!' });
  } catch (error) {
    console.error('Error during logout:', error);
    res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ error: 'Logout failed' });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    // Sure shot have custom type-safe error messages like just below
    res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: 'Please provide valid Email' });
  }

  const user = await User.findOne({ email });
  if (user) {
    const passwordToken = crypto.randomBytes(70).toString();
    // send email
    const origin = 'http://localhost:3000';
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin,
    });

    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = hashString(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res
    .status(StatusCodes.OK)
    .json({ msg: 'Please check your email for reset password link' });
};

export const resetPassword = async (req: Request, res: Response) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    res
      .status(StatusCodes.BAD_REQUEST)
      .json({ msg: 'Please provide all values' });
  }
  const user = await User.findOne({ email });
  if (user) {
    const currentDate = new Date();
    if (
      user.passwordToken === hashString(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }
  res.send('Reset password');
};
