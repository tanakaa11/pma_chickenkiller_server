import jwt       from 'jsonwebtoken';
import { createHash } from 'crypto';
import { JWT_SECRET } from './env.js';

export const JWT_EXPIRY      = '15m';
export const REFRESH_TTL_MS  = 7 * 24 * 60 * 60 * 1000;

export const hashToken  = (t) => createHash('sha256').update(t).digest('hex');
export const signToken  = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
export const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};
