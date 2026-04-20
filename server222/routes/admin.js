import { Router } from 'express';
import { randomUUID } from 'crypto';
import rateLimit from 'express-rate-limit';
import { supabase } from '../supabase.js';
import { validate, adminRegisterSchema, adminLinkSchema, sendInviteEmailSchema, sendOtpAdminSchema, createAndInviteSchema } from '../utils/validation.js';
import { USER_SELECT, formatUser, success, err } from '../helpers/format.js';
import { ROLE_MAP, ROLE_NAMES, ROLE_UI_MAP } from '../utils/constants.js';
import { hashPassword } from '../utils/password.js';
import { signToken } from '../config/jwt.js';
import { sendMailAsync, emailTransporter } from '../config/email.js';
import { CLIENT_URL } from '../config/env.js';

const router = Router();

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many registration attempts. Please try again later.' },
});

// POST /pma/auth/register  (admin full registration)
const registerHandler = async (req, res) => {
  const data = validate(adminRegisterSchema, req, res);
  if (!data) return;
  const { email, password, firstName, lastName, roleId, practiceIds } = data;
  const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json(err('A user with this email already exists'));
  const roleInfo = ROLE_MAP[roleId];
  if (!roleInfo) return res.status(400).json(err('Invalid role'));
  const hashedPassword = await hashPassword(password);
  const newId = randomUUID();
  const { error: uErr } = await supabase.from('users').insert({
    id: newId, email, first_name: firstName, last_name: lastName,
    is_active: true, role: roleInfo.uiRole, password: hashedPassword,
  });
  if (uErr) return res.status(500).json(err('Failed to create user'));
  if (roleId === 'ROLE_SYSADMIN') {
    await supabase.from('user_roles').insert({ user_id: newId, role_id: roleId, role_name: roleInfo.roleName });
  } else {
    const selectedPracticeIds = practiceIds || [];
    if (selectedPracticeIds.length === 0) {
      await supabase.from('users').delete().eq('id', newId);
      return res.status(400).json(err('At least one practice must be selected for this role'));
    }
    const { data: practiceRows } = await supabase.from('practices').select('id, name').in('id', selectedPracticeIds);
    const practiceMap = Object.fromEntries((practiceRows || []).map(p => [p.id, p.name]));
    await supabase.from('user_roles').insert(
      selectedPracticeIds.map(pid => ({ user_id: newId, role_id: roleId, role_name: roleInfo.roleName, practice_id: pid }))
    );
    const practiceInserts = selectedPracticeIds.filter(pid => practiceMap[pid]).map(pid => ({ user_id: newId, practice_id: pid, practice_name: practiceMap[pid] }));
    if (practiceInserts.length > 0) await supabase.from('user_practices').insert(practiceInserts);
  }
  if (roleId === 'ROLE_PRACTITIONER') {
    await supabase.from('doctors').insert({ id: randomUUID(), user_id: newId, first_name: firstName, last_name: lastName, specialization: 'General Practice', email, phone: '', is_available: true });
  }
  const { data: newUserRow } = await supabase.from('users').select(USER_SELECT).eq('id', newId).single();
  const newUser            = formatUser(newUserRow);
  const regPracticeIds     = (newUserRow?.user_practices || []).map(p => p.practice_id);
  const regIsSuperAdmin    = (newUserRow?.user_roles    || []).some(r => r.role_id === 'ROLE_SYSADMIN');
  const regIsSuperSuperAdmin = newUserRow?.role === 'super_super_admin';
  const token = signToken({ userId: newUser.id, role: newUserRow?.role, practiceIds: regPracticeIds, isSuperAdmin: regIsSuperAdmin, isSuperSuperAdmin: regIsSuperSuperAdmin });
  res.status(201).json(success({ user: newUser, token }, 'Registration successful'));
};
router.post('/register', registerLimiter, registerHandler);

// POST /pma/admin/link-user-to-practice
router.post('/link-user-to-practice', async (req, res) => {
  const data = validate(adminLinkSchema, req, res);
  if (!data) return;
  const { email, practiceId, roleId, firstName, lastName } = data;
  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));
  if (!ROLE_NAMES[roleId]) return res.status(400).json(err('Invalid roleId'));

  let { data: user } = await supabase.from('users').select('id, email, first_name, last_name').eq('email', email).maybeSingle();
  let isNewUser = false;

  if (!user) {
    if (!firstName || !lastName) return res.status(400).json(err('firstName and lastName are required for new users'));
    const newId = randomUUID();
    const { error: createErr } = await supabase.from('users').insert({
      id: newId, email, first_name: firstName, last_name: lastName,
      is_active: true, role: ROLE_UI_MAP[roleId], password: null,
    });
    if (createErr) { console.error('User creation error:', createErr); return res.status(500).json(err('Failed to create user')); }
    const { data: newUser } = await supabase.from('users').select('id, email, first_name, last_name').eq('id', newId).single();
    user = newUser; isNewUser = true;
  }
  if (!user) return res.status(500).json(err('Failed to create or retrieve user'));

  const { data: alreadyLinked } = await supabase.from('user_practices').select('id').eq('user_id', user.id).eq('practice_id', practiceId).maybeSingle();
  if (!alreadyLinked) await supabase.from('user_practices').insert({ user_id: user.id, practice_id: practiceId, practice_name: practice.name });

  const { data: existingRole } = await supabase.from('user_roles').select('id').eq('user_id', user.id).eq('practice_id', practiceId).maybeSingle();
  if (existingRole) {
    await supabase.from('user_roles').update({ role_id: roleId, role_name: ROLE_NAMES[roleId] }).eq('user_id', user.id).eq('practice_id', practiceId);
  } else {
    await supabase.from('user_roles').insert({ user_id: user.id, role_id: roleId, role_name: ROLE_NAMES[roleId], practice_id: practiceId });
  }

  if (roleId === 'ROLE_PRACTITIONER') {
    const { data: existingDoctor } = await supabase.from('doctors').select('id').eq('user_id', user.id).maybeSingle();
    if (!existingDoctor) await supabase.from('doctors').insert({ id: randomUUID(), user_id: user.id, first_name: user.first_name, last_name: user.last_name, specialization: 'General Practice', email: user.email, phone: '', is_available: true });
  }

  let inviteLink = '';
  if (isNewUser) {
    const token = randomUUID();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await supabase.from('invite_tokens').upsert({ token, user_id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, expires_at: expiresAt });
    inviteLink = `${CLIENT_URL}/set-password?token=${token}`;
    sendMailAsync({
      from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `You've been invited to join ${practice.name}`,
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
        <h2 style="color:#2563eb">Welcome to ${practice.name}</h2>
        <p>Hi ${user.first_name},</p>
        <p>Click the button below to set your password and activate your account:</p>
        <p style="text-align:center;margin:32px 0">
          <a href="${inviteLink}" style="background:#2563eb;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">Set Your Password</a>
        </p>
        <p style="color:#999;font-size:12px">This link expires in 7 days.</p>
      </div>`,
    }, 'new-user-invite');
  }

  const { data: updatedUser } = await supabase.from('users').select(USER_SELECT).eq('id', user.id).single();
  res.json(success({ user: formatUser(updatedUser), isNewUser, inviteLink, practice: { id: practice.id, name: practice.name } },
    `User successfully ${isNewUser ? 'created and ' : ''}linked to ${practice.name}`));
});

// POST /pma/admin/send-invite-email
router.post('/send-invite-email', async (req, res) => {
  const data = validate(sendInviteEmailSchema, req, res);
  if (!data) return;
  const { email, inviteLink, practiceName, firstName } = data;
  if (!emailTransporter) return res.status(503).json(err('Email is not configured on the server.'));
  try {
    await emailTransporter.sendMail({
      from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `You've been invited to join ${practiceName || 'a practice'}`,
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
        <p>Hi ${firstName || 'there'}, click below to set your password:</p>
        <p style="text-align:center;margin:32px 0">
          <a href="${inviteLink}" style="background:#2563eb;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">Set Your Password</a>
        </p>
        <p style="color:#999;font-size:12px">This link expires in 7 days.</p>
      </div>`,
    });
    res.json(success(null, `Invite email sent to ${email}`));
  } catch (mailErr) {
    console.error(`❌ [EMAIL] Failed to send invite to ${email}:`, mailErr.message);
    res.status(500).json(err('Failed to send email'));
  }
});

// POST /pma/admin/send-otp
router.post('/send-otp', async (req, res) => {
  const data = validate(sendOtpAdminSchema, req, res);
  if (!data) return;
  const { userId, practiceId } = data;
  const { data: user } = await supabase.from('users').select('id, email, first_name, last_name').eq('id', userId).maybeSingle();
  if (!user) return res.status(404).json(err('User not found'));
  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 300_000).toISOString();
  await supabase.from('otp_tokens').delete().eq('user_id', userId).eq('context', 'practice-link');
  await supabase.from('otp_tokens').insert({ id: randomUUID(), token: otp, user_id: userId, practice_id: practiceId, context: 'practice-link', expires_at: expiresAt });

  sendMailAsync({
    from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
    to: user.email,
    subject: `Your practice link OTP for ${practice.name}`,
    html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
      <p>Hi ${user.first_name}, your OTP is:</p>
      <p style="text-align:center;margin:32px 0">
        <span style="background:#f3f4f6;padding:16px 32px;border-radius:8px;font-size:32px;font-family:monospace;letter-spacing:8px;font-weight:bold;color:#2563eb">${otp}</span>
      </p>
      <p style="color:#666;font-size:13px">It expires in 5 minutes.</p>
    </div>`,
  }, 'admin-send-otp');

  if (!emailTransporter) return res.status(503).json(err('Email service is not configured. Cannot deliver OTP.'));
  res.json(success({ emailed: true }, `OTP sent to ${user.email}`));
});

// POST /pma/admin/create-and-invite
router.post('/create-and-invite', async (req, res) => {
  const data = validate(createAndInviteSchema, req, res);
  if (!data) return;
  const { email, firstName, lastName, roleId, practiceId, tempPassword } = data;
  const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).maybeSingle();
  if (existing) return res.status(409).json(err('A user with this email already exists'));
  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  const newId = randomUUID();
  const hashedPw = await hashPassword(tempPassword || 'TempPass123!');
  const { error: uErr } = await supabase.from('users').insert({
    id: newId, email: email.toLowerCase(), first_name: firstName, last_name: lastName,
    password: hashedPw, role: ROLE_UI_MAP[roleId] || 'reception', is_active: false,
  });
  if (uErr) { console.error('Create invite error:', uErr); return res.status(500).json(err('Failed to create user')); }

  await supabase.from('user_practices').insert({ user_id: newId, practice_id: practiceId, practice_name: practice.name });
  await supabase.from('user_roles').insert({ user_id: newId, role_id: roleId, role_name: ROLE_NAMES[roleId] || roleId, practice_id: practiceId });

  if (roleId === 'ROLE_PRACTITIONER') {
    await supabase.from('doctors').insert({ id: randomUUID(), user_id: newId, first_name: firstName, last_name: lastName, specialization: 'General Practice', email: email.toLowerCase(), phone: '', is_available: true });
  }

  const token = randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  await supabase.from('invite_tokens').insert({ token, user_id: newId, email: email.toLowerCase(), first_name: firstName, last_name: lastName, expires_at: expiresAt });
  const inviteLink = `${CLIENT_URL}/set-password?token=${token}`;
  res.status(201).json(success({ userId: newId, inviteLink, token }, 'User created and invite link generated'));
});

export default router;
