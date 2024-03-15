import { Request, Response } from 'express';

export interface UserType {
  name: string;
  userId: string;
  role: string;
  refreshToken?: string;
}

export interface UserResponse extends Response {
  user: UserType;
}

export interface UserRequest extends Request {
  user: UserType;
}
