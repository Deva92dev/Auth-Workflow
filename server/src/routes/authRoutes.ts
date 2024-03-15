import {
  forgotPassword,
  login,
  logout,
  register,
  resetPassword,
  verifyEmail,
} from '../controllers/authController';
import { authenticateUser } from '../middlewares/authentication';
import express, { Router } from 'express';

const router: Router = express.Router();
router.post('/register', register);
router.post('/login', login);
router.delete('/logout', authenticateUser, logout); // on FrontEnd when logout delete authentication
router.post('/verify-email', verifyEmail);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
export default router;
