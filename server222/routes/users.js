import { Router } from 'express';
import { randomUUID } from 'crypto';
import { supabase } from '../supabase.js';
import { validate, createUserSchema, updateUserSchema, linkPracticeSchema } from '../utils/validation.js';
import { USER_SELECT, formatUser, success, err, toCamel } from '../helpers/format.js';
import { ROLE_NAMES, ROLE_UI_MAP } from '../utils/constants.js';
import { sendMailAsync } from '../config/email.js';
import { CLIENT_URL } from '../config/env.js';
import { logAudit } from '../utils/audit.js';

const router = Router();

// GET /pma/users
router.get('/', async (req, res) => {
  const { page, pageSize } = req.query;
  const { data: users, error: dbErr } = await supabase.from('users').select(USER_SELECT);
  if (dbErr) return res.status(500).json(err('Failed to fetch users'));
  const formatted = (users || []).map(formatUser);
  if (page && pageSize) {
    const p = parseInt(page), ps = parseInt(pageSize);
    const paginated = formatted.slice((p - 1) * ps, (p - 1) * ps + ps);
    return res.json(success({ data: paginated, total: formatted.length, page: p, pageSize: ps, totalPages: Math.ceil(formatted.length / ps) }));
  }
  res.json(success(formatted));
});

// GET /pma/users/role/:role
router.get('/role/:role', async (req, res) => {
  const { data: users } = await supabase.from('users').select(USER_SELECT).eq('role', req.params.role);
  res.json(success((users || []).map(formatUser)));
});

// GET /pma/users/check-email
router.get('/check-email', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json(err('email is required'));
  const { data: user } = await supabase.from('users').select('id').eq('email', String(email).toLowerCase()).maybeSingle();
  return res.json(success({ exists: !!user }));
});

// GET /pma/users/:id
router.get('/:id', async (req, res) => {
  const { data: u } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  if (!u) return res.status(404).json(err('User not found'));
  res.json(success(formatUser(u)));
});

// POST /pma/users
router.post('/', async (req, res) => {
  const data = validate(createUserSchema, req, res);
  if (!data) return;
  const { email, firstName, lastName, role: uiRole } = data;
  const { data: existing } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json(err('A user with this email already exists'));
  const uiRoleToRoleId   = { super_admin: 'ROLE_SYSADMIN', doctor: 'ROLE_PRACTITIONER', reception: 'ROLE_ADMIN' };
  const uiRoleToRoleName = { super_admin: 'SystemAdministrator', doctor: 'PracticePractitioner', reception: 'PracticeAdministrator' };
  const resolvedRole = uiRole || 'reception';
  const newId = randomUUID();
  const { error: insertErr } = await supabase.from('users').insert({
    id: newId, email, first_name: firstName, last_name: lastName, is_active: true, role: resolvedRole,
  });
  if (insertErr) return res.status(500).json(err('Failed to create user'));
  await supabase.from('user_roles').insert({
    user_id: newId, role_id: uiRoleToRoleId[resolvedRole], role_name: uiRoleToRoleName[resolvedRole],
  });
  const { data: newUserRow } = await supabase.from('users').select(USER_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatUser(newUserRow), 'User created successfully'));
});

// PUT /pma/users/:id
router.put('/:id', async (req, res) => {
  const data = validate(updateUserSchema, req, res);
  if (!data) return;
  const { data: existing } = await supabase.from('users').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  const upd = {};
  if (data.firstName !== undefined) upd.first_name = data.firstName;
  if (data.lastName  !== undefined) upd.last_name  = data.lastName;
  if (data.email     !== undefined) upd.email      = data.email;
  if (data.isActive  !== undefined) upd.is_active  = data.isActive;
  if (data.role      !== undefined) upd.role       = data.role;
  await supabase.from('users').update(upd).eq('id', req.params.id);
  const { data: updated } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success(formatUser(updated), 'User updated successfully'));
});

// DELETE /pma/users/:id
router.delete('/:id', async (req, res) => {
  const { data: existing } = await supabase.from('users').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  logAudit(req, 'DELETE_USER', req.params.id);
  await supabase.from('users').delete().eq('id', req.params.id);
  res.json(success(null, 'User deleted successfully'));
});

// PATCH /pma/users/:id/toggle-active
router.patch('/:id/toggle-active', async (req, res) => {
  const { data: existing } = await supabase.from('users').select('id, is_active').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  logAudit(req, 'TOGGLE_USER_ACTIVE', req.params.id);
  await supabase.from('users').update({ is_active: !existing.is_active }).eq('id', req.params.id);
  const { data: updated } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success(formatUser(updated)));
});

// POST /pma/users/:id/link-practice
router.post('/:id/link-practice', async (req, res) => {
  const data = validate(linkPracticeSchema, req, res);
  if (!data) return;
  const { practiceId, roleId } = data;
  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));
  const { data: user } = await supabase.from('users').select('id, email, first_name, last_name').eq('id', req.params.id).maybeSingle();
  if (!user) return res.status(404).json(err('User not found'));

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 300_000).toISOString();
  await supabase.from('otp_tokens').delete().eq('user_id', req.params.id).eq('context', 'practice-link');
  await supabase.from('otp_tokens').insert({
    id: randomUUID(), token: otp, user_id: req.params.id, practice_id: practiceId,
    context: 'practice-link', expires_at: expiresAt,
  });

  sendMailAsync({
    from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
    to: user.email,
    subject: `Your practice link OTP for ${practice.name}`,
    html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
      <h2 style="color:#2563eb">Practice Link Verification</h2>
      <p>Hi ${user.first_name},</p>
      <p>Use the OTP below to link your account to <strong>${practice.name}</strong>:</p>
      <p style="text-align:center;margin:32px 0">
        <span style="background:#f3f4f6;padding:16px 32px;border-radius:8px;font-size:32px;font-family:monospace;letter-spacing:8px;font-weight:bold;color:#2563eb">${otp}</span>
      </p>
      <p style="color:#666;font-size:13px">Enter this code on your Profile page. It expires in 5 minutes.</p>
    </div>`,
  }, 'practice-link-otp');

  const { data: existingLink } = await supabase.from('user_practices')
    .select('id').eq('user_id', req.params.id).eq('practice_id', practiceId).maybeSingle();
  if (!existingLink) {
    await supabase.from('user_practices').insert({ user_id: req.params.id, practice_id: practiceId, practice_name: practice.name });
  }

  if (roleId) {
    const { data: existingRole } = await supabase.from('user_roles')
      .select('id').eq('user_id', req.params.id).eq('role_id', roleId).eq('practice_id', practiceId).maybeSingle();
    if (!existingRole) {
      await supabase.from('user_roles').insert({ user_id: req.params.id, role_id: roleId, role_name: ROLE_NAMES[roleId] || roleId, practice_id: practiceId });
    }
  }

  const { data: updatedUser } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success({ user: formatUser(updatedUser), emailed: !!process.env.SMTP_USER }, 'Practice linked and OTP sent'));
});

// POST /pma/users/:id/link-practice-direct
router.post('/:id/link-practice-direct', async (req, res) => {
  const data = validate(linkPracticeSchema, req, res);
  if (!data) return;
  const { practiceId, roleId } = data;
  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));
  const { data: user } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).maybeSingle();
  if (!user) return res.status(404).json(err('User not found'));

  const { data: existingLink } = await supabase.from('user_practices')
    .select('id').eq('user_id', req.params.id).eq('practice_id', practiceId).maybeSingle();
  if (!existingLink) {
    await supabase.from('user_practices').insert({ user_id: req.params.id, practice_id: practiceId, practice_name: practice.name });
  }

  if (roleId) {
    const { data: existingRole } = await supabase.from('user_roles')
      .select('id').eq('user_id', req.params.id).eq('practice_id', practiceId).maybeSingle();
    if (existingRole) {
      await supabase.from('user_roles').update({ role_id: roleId, role_name: ROLE_NAMES[roleId] || roleId }).eq('user_id', req.params.id).eq('practice_id', practiceId);
    } else {
      await supabase.from('user_roles').insert({ user_id: req.params.id, role_id: roleId, role_name: ROLE_NAMES[roleId] || roleId, practice_id: practiceId });
    }
    if (user.role === 'unlinked') {
      await supabase.from('users').update({ role: ROLE_UI_MAP[roleId] || 'reception' }).eq('id', req.params.id);
    }
  }

  const { data: updatedUser } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success({ user: formatUser(updatedUser), linked: true }, 'User linked to practice'));
});

// GET /pma/users/:id/my-practice
router.get('/:id/my-practice', async (req, res) => {
  const { data: userPractices } = await supabase
    .from('user_practices').select('practice_id, practice_name').eq('user_id', req.params.id);
  if (!userPractices?.length) return res.json(success(null, 'User is not linked to any practice'));
  const { data: practice } = await supabase
    .from('practices').select('*, practice_practitioners(*)').eq('id', userPractices[0].practice_id).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));
  res.json(success({ ...toCamel(practice), practicePractitioners: (practice.practice_practitioners || []).map(toCamel) }));
});

// GET /pma/users/:id/my-practices
router.get('/:id/my-practices', async (req, res) => {
  const { data: userRow } = await supabase.from('users').select('role').eq('id', req.params.id).maybeSingle();
  if (userRow?.role === 'super_super_admin') {
    const { data: allPractices } = await supabase.from('practices').select('id, name, practice_number');
    return res.json(success((allPractices || []).map(p => ({ id: p.id, name: p.name, practiceNumber: p.practice_number }))));
  }
  const { data: userPractices } = await supabase
    .from('user_practices').select('practice_id, practice_name').eq('user_id', req.params.id);
  if (!userPractices?.length) return res.json(success([], 'User is not linked to any practice'));
  const practiceIds = userPractices.map(p => p.practice_id);
  const { data: practices } = await supabase.from('practices').select('id, name, practice_number').in('id', practiceIds);
  res.json(success((practices || []).map(p => ({ id: p.id, name: p.name, practiceNumber: p.practice_number }))));
});

export default router;
