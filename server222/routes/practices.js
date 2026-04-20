import { Router } from 'express';
import { supabase } from '../supabase.js';
import { validate, verifyPracticeOtpSchema } from '../utils/validation.js';
import { toCamel, success, err, enrichPP } from '../helpers/format.js';
import { sanitizeSearch } from '../utils/constants.js';

const router = Router();

// GET /pma/practices
const practicesHandler = async (req, res) => {
  const { data: practices } = await supabase.from('practices').select('*, practice_practitioners(*), user_practices(*)');
  const formatted = (practices || []).map(p => ({
    ...toCamel(p),
    practitionerCount: (p.practice_practitioners || []).length,
    memberCount: (p.user_practices || []).length,
  }));
  res.json(success(formatted));
};
router.get('/', practicesHandler);

// GET /pma/practices/search
router.get('/search', async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('practices').select('id, name, practice_number');
  if (q) { const sq = sanitizeSearch(q); query = query.or(`name.ilike.%${sq}%,practice_number.ilike.%${sq}%`); }
  const { data: practices } = await query;
  res.json(success((practices || []).map(p => ({ id: p.id, name: p.name, practiceNumber: p.practice_number }))));
});

// GET /pma/practices/:id
router.get('/:id', async (req, res) => {
  const [{ data: practice }, { data: allUsers }, { data: roleRows }, { data: ppRows }] = await Promise.all([
    supabase.from('practices').select('*, practice_practitioners(*)').eq('id', req.params.id).maybeSingle(),
    supabase.from('users').select('id, first_name, last_name, email, is_active, role'),
    supabase.from('user_roles').select('user_id, role_id, role_name').eq('practice_id', req.params.id),
    supabase.from('practice_practitioners').select('user_id').eq('practice_id', req.params.id),
  ]);
  if (!practice) return res.status(404).json(err('Practice not found'));
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  const allLinkedIds = new Set([...(roleRows || []).map(r => r.user_id), ...(ppRows || []).map(p => p.user_id)]);
  const linkedUsers = [...allLinkedIds].map(uid => {
    const u = usersMap[uid] || {};
    const roleRow = (roleRows || []).find(r => r.user_id === uid);
    return {
      id: uid, firstName: u.first_name || '', lastName: u.last_name || '',
      email: u.email || '', role: roleRow?.role_id || 'ROLE_PRACTITIONER', isActive: u.is_active ?? true,
    };
  }).filter(u => u.firstName);
  res.json(success({
    ...toCamel(practice),
    practicePractitioners: (practice.practice_practitioners || []).map(pp => enrichPP(pp, usersMap)),
    linkedUsers,
  }));
});

// GET /pma/practices/:id/doctors
router.get('/:id/doctors', async (req, res) => {
  const { data: practitioners } = await supabase
    .from('practice_practitioners').select('user_id').eq('practice_id', req.params.id);
  if (!practitioners || practitioners.length === 0) return res.json(success([]));

  const userIds = practitioners.map(p => p.user_id);
  const { data: doctors } = await supabase.from('doctors').select('*').in('user_id', userIds);
  if (!doctors || doctors.length === 0) return res.json(success([]));

  const today    = new Date();
  const dateFrom = today.toISOString().split('T')[0];
  const dateTo   = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const { data: schedules } = await supabase.from('schedules').select('*')
    .in('doctor_id', doctors.map(d => d.id)).gte('date', dateFrom).lte('date', dateTo);

  const schedMap = {};
  for (const s of (schedules || [])) {
    if (!schedMap[s.doctor_id]) schedMap[s.doctor_id] = [];
    schedMap[s.doctor_id].push({
      id: s.id, doctorId: s.doctor_id, date: s.date,
      startTime: s.start_time, endTime: s.end_time, status: s.status, notes: s.notes ?? null,
    });
  }

  res.json(success(doctors.map(d => ({
    id: d.id, userId: d.user_id,
    firstName: d.first_name || '', lastName: d.last_name || '',
    specialization: d.specialization || '', email: d.email || '', phone: d.phone || '',
    isAvailable: d.is_available ?? false, schedule: schedMap[d.id] || [],
  }))));
});

// GET /pma/practices/:id/members
router.get('/:id/members', async (req, res) => {
  const [{ data: roleRows }, { data: ppRows }] = await Promise.all([
    supabase.from('user_roles').select('user_id, role_id, role_name').eq('practice_id', req.params.id),
    supabase.from('practice_practitioners').select('user_id, hpcsa_number').eq('practice_id', req.params.id),
  ]);
  const memberMap = {};
  for (const r of (roleRows || [])) {
    if (!memberMap[r.user_id]) memberMap[r.user_id] = { user_id: r.user_id, role_id: r.role_id, role_name: r.role_name };
  }
  for (const pp of (ppRows || [])) {
    if (!memberMap[pp.user_id]) memberMap[pp.user_id] = { user_id: pp.user_id, role_id: 'ROLE_PRACTITIONER', role_name: 'PracticePractitioner' };
  }
  const members = Object.values(memberMap);
  if (members.length === 0) return res.json(success([]));
  const userIds = members.map(r => r.user_id);
  const [{ data: users }, { data: doctors }] = await Promise.all([
    supabase.from('users').select('id, first_name, last_name, email').in('id', userIds),
    supabase.from('doctors').select('user_id, first_name, last_name, email, phone').in('user_id', userIds),
  ]);
  const usersMap   = Object.fromEntries((users   || []).map(u => [u.id,      u]));
  const doctorsMap = Object.fromEntries((doctors || []).map(d => [d.user_id, d]));
  res.json(success(members.map(r => {
    const u = usersMap[r.user_id]   || {};
    const d = doctorsMap[r.user_id] || {};
    return {
      userId: r.user_id, roleId: r.role_id, roleName: r.role_name,
      firstName: u.first_name || d.first_name || '', lastName: u.last_name || d.last_name || '',
      email: u.email || d.email || '', phone: u.phone || d.phone || '',
    };
  })));
});

// POST /pma/practices/verify-otp
router.post('/verify-otp', async (req, res) => {
  const data = validate(verifyPracticeOtpSchema, req, res);
  if (!data) return;
  const { otp, userId } = data;
  const { data: otpRow } = await supabase
    .from('otp_tokens').select('*').eq('token', otp).eq('user_id', userId).eq('context', 'practice-link').maybeSingle();
  if (!otpRow) return res.status(400).json(err('Invalid or expired OTP'));
  if (new Date(otpRow.expires_at) < new Date()) {
    await supabase.from('otp_tokens').delete().eq('id', otpRow.id);
    return res.status(400).json(err('OTP has expired'));
  }
  const { data: user } = await supabase.from('users').select('role').eq('id', userId).maybeSingle();
  if (user?.role === 'unlinked') {
    await supabase.from('users').update({ role: 'reception' }).eq('id', userId);
  }
  await supabase.from('otp_tokens').delete().eq('id', otpRow.id);
  res.json(success({ verified: true }, 'OTP verified successfully'));
});

export default router;
