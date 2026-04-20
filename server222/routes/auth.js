import { Router } from 'express';
import { randomUUID } from 'crypto';
import rateLimit from 'express-rate-limit';
import { supabase } from '../supabase.js';
import { hashToken, signToken, verifyToken, REFRESH_TTL_MS } from '../config/jwt.js';
import { hashPassword, verifyPassword } from '../utils/password.js';
import { validate, loginSchema, selfRegisterSchema, setPasswordSchema, updatePasswordSchema } from '../utils/validation.js';
import { USER_SELECT, formatUser, success, err } from '../helpers/format.js';
import { CLIENT_URL } from '../config/env.js';

const router = Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many attempts. Please try again in 15 minutes.' },
});

// GET probes
router.get('/login', (req, res) => res.json({ message: 'Login endpoint is working. Please use POST method to login.' }));

// POST /login
const loginHandler = async (req, res) => {
  const data = validate(loginSchema, req, res);
  if (!data) return;
  const { email, password } = data;
  console.log('[LOGIN] Attempt received');

  if (!supabase) return res.status(503).json(err('Database not configured — contact admin'));

  const { data: userData, error: dbErr } = await supabase
    .from('users').select(USER_SELECT).eq('email', email).eq('is_active', true).maybeSingle();
  if (dbErr) return res.status(500).json(err(`Database error during login: ${dbErr.message}`));

  if (!userData) {
    const { data: unverified } = await supabase.from('users').select('id, is_active').eq('email', email).maybeSingle();
    if (unverified && !unverified.is_active) return res.status(403).json(err('Account not verified. Please check your email for the verification link.'));
    return res.status(401).json(err('Invalid email or password'));
  }

  if (!userData.password) return res.status(401).json(err('Invalid email or password'));
  if (!userData.password.startsWith('$2b$')) {
    console.error(`[SECURITY] User ${userData.id} has unhashed password. Run the migration script.`);
    return res.status(401).json(err('Invalid email or password'));
  }
  if (!await verifyPassword(password, userData.password)) return res.status(401).json(err('Invalid email or password'));

  console.log('[LOGIN] Successful');
  const user           = formatUser(userData);
  const practiceIds    = (userData.user_practices || []).map(p => p.practice_id);
  const isSuperAdmin   = (userData.user_roles    || []).some(r => r.role_id === 'ROLE_SYSADMIN');
  const isSuperSuperAdmin = userData.role === 'super_super_admin';
  const token = signToken({ userId: user.id, role: userData.role, practiceIds, isSuperAdmin, isSuperSuperAdmin });
  const refreshToken = randomUUID();
  await supabase.from('refresh_tokens').insert({
    user_id: user.id, token_hash: hashToken(refreshToken), expires_at: Date.now() + REFRESH_TTL_MS,
  });
  res.json(success({ user, token, refreshToken }, 'Login successful'));
};
router.post('/login', authLimiter, loginHandler);

// POST /logout
const logoutHandler = async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) await supabase.from('refresh_tokens').delete().eq('token_hash', hashToken(refreshToken));
  res.json(success(null, 'Logged out successfully'));
};
router.post('/logout', logoutHandler);

// POST /refresh
const refreshHandler = async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(401).json(err('Refresh token required'));
  const hash = hashToken(refreshToken);
  const { data: tokenRow } = await supabase.from('refresh_tokens').select('*').eq('token_hash', hash).maybeSingle();
  if (!tokenRow || tokenRow.expires_at < Date.now()) {
    if (tokenRow) await supabase.from('refresh_tokens').delete().eq('token_hash', hash);
    return res.status(401).json(err('Refresh token invalid or expired'));
  }
  await supabase.from('refresh_tokens').delete().eq('token_hash', hash);
  const { data: userData } = await supabase.from('users').select(USER_SELECT).eq('id', tokenRow.user_id).maybeSingle();
  if (!userData || !userData.is_active) return res.status(401).json(err('User account not found or inactive'));
  const practiceIds    = (userData.user_practices || []).map(p => p.practice_id);
  const isSuperAdmin   = (userData.user_roles    || []).some(r => r.role_id === 'ROLE_SYSADMIN');
  const isSuperSuperAdmin = userData.role === 'super_super_admin';
  const newAccessToken  = signToken({ userId: userData.id, role: userData.role, practiceIds, isSuperAdmin, isSuperSuperAdmin });
  const newRefreshToken = randomUUID();
  await supabase.from('refresh_tokens').insert({
    user_id: userData.id, token_hash: hashToken(newRefreshToken), expires_at: Date.now() + REFRESH_TTL_MS,
  });
  res.json(success({ token: newAccessToken, refreshToken: newRefreshToken }));
};
router.post('/refresh', authLimiter, refreshHandler);

// GET /me
const meHandler = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json(err('No token provided'));
  const payload = verifyToken(authHeader.replace('Bearer ', ''));
  if (!payload) return res.status(401).json(err('Invalid or expired token'));
  const { data: userData } = await supabase.from('users').select(USER_SELECT).eq('id', payload.userId).single();
  if (!userData) return res.status(404).json(err('User not found'));
  res.json(success(formatUser(userData)));
};
router.get('/me', meHandler);

// Self-registration (public endpoint — creates an inactive account pending email verification)
router.post('/self-register', authLimiter, async (req, res) => {
  const data = validate(selfRegisterSchema, req, res);
  if (!data) return;
  const { email, password, firstName, lastName } = data;
  const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(409).json({ message: 'User already exists' });
  const hashedPassword = await hashPassword(password);
  const newId = randomUUID();
  const { error: uErr } = await supabase.from('users').insert({
    id: newId, email, password: hashedPassword,
    first_name: firstName, last_name: lastName, is_active: false, role: 'unlinked',
  });
  if (uErr) { console.error('Registration error:', uErr); return res.status(500).json({ message: 'Failed to create user' }); }
  const verifyLink = `${CLIENT_URL}/pma/authentication/verify/${newId}`;
  console.log(`[REGISTER] Verify link generated for new user`);
  return res.status(201).json({ message: 'User registered successfully', verifyLink });
});

router.get('/pma/authentication/verify/:userid', async (req, res) => {
  const { userid } = req.params;
  if (!userid) return res.status(400).json({ error: 'UserID is required' });
  const { data: user, error: dbErr } = await supabase.from('users').select('id, is_active').eq('id', userid).maybeSingle();
  if (dbErr || !user) return res.status(404).json({ error: 'User not found' });
  if (user.is_active) return res.status(200).json({ message: 'Account is already verified. Please sign in.' });
  const { error: updErr } = await supabase.from('users').update({ is_active: true }).eq('id', userid);
  if (updErr) return res.status(500).json({ error: 'Failed to verify account' });
  console.log(`✅ [VERIFY] User ${userid} verified successfully`);
  return res.status(200).json({ message: 'Account verified successfully. Please sign in.' });
});

// Invite token verify
router.get('/signup/verify/:token', async (req, res) => {
  const { data: stored, error: tErr } = await supabase.from('invite_tokens').select('*').eq('token', req.params.token).maybeSingle();
  if (tErr || !stored) return res.status(404).json(err('Invalid or expired invite token'));
  if (Date.now() > stored.expires_at) {
    await supabase.from('invite_tokens').delete().eq('token', req.params.token);
    return res.status(410).json(err('Invite link has expired. Please request a new invite.'));
  }
  res.json(success({ firstName: stored.first_name, lastName: stored.last_name, email: stored.email }));
});

// Set password
router.post('/set-password', authLimiter, async (req, res) => {
  const data = validate(setPasswordSchema, req, res);
  if (!data) return;
  const { token, password } = data;
  const { data: stored, error: tErr } = await supabase.from('invite_tokens').select('*').eq('token', token).maybeSingle();
  if (tErr || !stored) return res.status(400).json(err('Invalid or expired invite token'));
  if (Date.now() > stored.expires_at) {
    await supabase.from('invite_tokens').delete().eq('token', token);
    return res.status(410).json(err('Invite link has expired'));
  }
  const hashed = await hashPassword(password);
  await supabase.from('users').update({ password: hashed, is_active: true }).eq('id', stored.user_id);
  await supabase.from('invite_tokens').delete().eq('token', token);
  console.log(`✅ [INVITE] ${stored.email} activated account`);
  res.json(success(null, 'Password set and account activated'));
});

// Update password (authenticated)
router.post('/update-password', authLimiter, async (req, res) => {
  const payload = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!payload) return res.status(401).json(err('Authentication required'));
  const data = validate(updatePasswordSchema, req, res);
  if (!data) return;
  const { email, newPassword } = data;
  const { data: u } = await supabase.from('users').select('id, password').eq('id', payload.userId).eq('email', email).maybeSingle();
  if (!u) return res.status(403).json(err('You can only update your own password'));
  const hashedPassword = await hashPassword(newPassword);
  const { error } = await supabase.from('users').update({ password: hashedPassword }).eq('id', u.id);
  if (error) { console.error('Password update error:', error); return res.status(500).json(err('Failed to update password')); }
  res.json(success(null, 'Password updated successfully'));
});

export default router;
