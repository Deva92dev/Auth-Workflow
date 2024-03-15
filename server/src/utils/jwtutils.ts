import { Response } from 'express';
import jwt from 'jsonwebtoken';
import { UserType } from '../types';

export interface jwtPayload extends UserType {
  refreshToken?: string;
}

// payload is the only thing that will be passed on from controller
export const createJWT = ({ payload }: { payload: jwtPayload }) => {
  const token = jwt.sign(payload, process.env.JWT_SECRET);
  return token;
};

export const isTokenValid = (token: string) => {
  try {
    // Verify the token and handle potential errors
    const decoded = jwt.verify(token, process.env.JWT_SECRET) as jwtPayload;
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token has expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token format');
    } else {
      throw new Error('Authentication failed');
    }
  }
};

// here, res from authController, user is tokenUser
export const attachCookiesToResponse = (
  res: Response,
  user: UserType,
  refreshToken: string = '' // default to empty string if not passed
) => {
  const accessTokenJWT = createJWT({ payload: user });
  const refreshTokenJWT = createJWT({ payload: { ...user, refreshToken } });

  const oneDay = 1000 * 60 * 60 * 24;
  const longerExp = 1000 * 60 * 60 * 24 * 30;

  // storing jwt in cookies so that it can be accessed by only server
  res.cookie('accessToken', accessTokenJWT, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // secured over https
    signed: true,
    expires: new Date(Date.now() + oneDay),
  });

  res.cookie('refreshToken', refreshTokenJWT, {
    httpOnly: true,
    expires: new Date(Date.now() + longerExp),
    secure: process.env.NODE_ENV === 'production', // secured over https
    signed: true,
  });
};

// export const attachSingleCookiesToResponse = (
//   res: Response,
//   user: jwtPayload
// ) => {
//   const token = createJWT({ payload: user });

//   const oneDay = 1000 * 60 * 60 * 24; // number off milliseconds
// storing jwt in cookies so that it can be accessed by only server
//   res.cookie('token', token, {
//     httpOnly: true,
//     expires: new Date(Date.now() + oneDay),
//     secure: process.env.NODE_ENV === 'production', // secured over https
//     signed: true,
//   });
// };
