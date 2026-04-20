import dotenv from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '../.env') });

if (!process.env.CLIENT_URL)
  console.warn('⚠️  CLIENT_URL not set — invite/verification links will use default');
if (!process.env.SMTP_USER || !process.env.SMTP_APP_PASS)
  console.warn('⚠️  SMTP credentials not set — email sending disabled');
if (!process.env.JWT_SECRET)
  console.warn('⚠️  JWT_SECRET is not set — auth tokens will not work correctly');

export const PORT       = process.env.PORT || 5000;
export const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:8080';
export const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
export const SMTP_USER  = process.env.SMTP_USER;
export const SMTP_PASS  = process.env.SMTP_APP_PASS;

// Extra origins injected via env (comma-separated), e.g. all Amplify preview URLs
const _envOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : [];

export const ALLOWED_ORIGINS = [
  'https://staging.d2hsjjwmhjn21g.amplifyapp.com',
  'http://localhost:8080',
  'http://localhost:5173',
  'http://localhost:3000',
  ...(process.env.CLIENT_URL ? [process.env.CLIENT_URL] : []),
  ..._envOrigins,
];

// Pattern: allow any *.amplifyapp.com subdomain automatically
export const AMPLIFY_ORIGIN_REGEX = /^https:\/\/[a-z0-9-]+\.amplifyapp\.com$/i;
