import { NextFunction, Response } from 'express';
import { attachCookiesToResponse, isTokenValid } from '../utils/jwtutils';
import { StatusCodes } from 'http-status-codes';
import { UserRequest, UserType } from '../types';
import { Token } from '../models/tokenModel';

// signed cookies always be in req.signedCookies
export const authenticateUser = async (
  req: UserRequest,
  res: Response,
  next: NextFunction
) => {
  const { refreshToken, accessToken } = req.signedCookies;

  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken);
      req.user = payload;
      return next();
    }
    const refreshTokenPayload = isTokenValid(refreshToken);
    const existingToken = await Token.findOne({
      user: refreshTokenPayload.userId,
      refreshToken: refreshTokenPayload.refreshToken,
    });

    // solve why after showMe route, while logging out , refreshToken is still there with the help of GenAI
    if (!existingToken || !existingToken?.isValid) {
      res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ msg: 'One of the token is missing' });
    }

    attachCookiesToResponse(res, refreshTokenPayload);

    req.user = refreshTokenPayload;
    next();
  } catch (error) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ msg: 'Authentication Invalid' });
  }
};

export const authorizePermission = (...roles: string[]) => {
  return (req: UserRequest, res: Response, next: NextFunction) => {
    if (!roles.includes(req.user.role)) {
      res
        .status(StatusCodes.UNAUTHORIZED)
        .json({ msg: 'Unauthorized to access this route' });
    }
    next();
  };
};
