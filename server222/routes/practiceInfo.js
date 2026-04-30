import { Router } from 'express';
import { supabase } from '../supabase.js';
import { toCamel, success, err, enrichPP } from '../helpers/format.js';
import { validate, createPracticeSchema, updatePracticeSchema } from '../utils/validation.js';

const router = Router();

// GET /pma/practice  — current practice (from X-Practice-Id header / userContext)
router.get('/', async (req, res) => {
  let practiceId = req.userContext?.practiceId;
  if (!practiceId) {
    const { data: firstPractice } = await supabase.from('practices').select('id').limit(1).maybeSingle();
    practiceId = firstPractice?.id;
  }
  if (!practiceId) return res.status(404).json(err('Practice not found'));

  const [{ data: practice }, { data: patients }, { data: allUsers }, { data: roleRows }, { data: ppRows }] = await Promise.all([
    supabase.from('practices').select('*, practice_practitioners(*)').eq('id', practiceId).maybeSingle(),
    supabase.from('patients').select('id, first_name, last_name, gender').eq('practice_id', practiceId),
    supabase.from('users').select('id, first_name, last_name, email, role'),
    supabase.from('user_roles').select('user_id, role_id, role_name').eq('practice_id', practiceId),
    supabase.from('practice_practitioners').select('user_id, hpcsa_number').eq('practice_id', practiceId),
  ]);
  if (!practice) return res.status(404).json(err('Practice not found'));

  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  const memberMap = {};
  for (const r of (roleRows || [])) {
    if (!memberMap[r.user_id]) memberMap[r.user_id] = { userId: r.user_id, roleId: r.role_id, roleName: r.role_name };
  }
  for (const pp of (ppRows || [])) {
    if (!memberMap[pp.user_id]) memberMap[pp.user_id] = { userId: pp.user_id, roleId: 'ROLE_PRACTITIONER', roleName: 'PracticePractitioner' };
  }

  const linkedUsers = Object.values(memberMap).map(m => {
    const u = usersMap[m.userId] || {};
    return { userId: m.userId, roleId: m.roleId, roleName: m.roleName, firstName: u.first_name || '', lastName: u.last_name || '', email: u.email || '' };
  }).filter(u => u.firstName);

  res.json(success({
    ...toCamel(practice),
    practicePractitioners: (practice.practice_practitioners || []).map(pp => enrichPP(pp, usersMap)),
    patients: (patients || []).map(toCamel),
    linkedUsers,
  }));
});

// GET /pma/practice/practitioners
router.get('/practitioners', async (req, res) => {
  const [{ data: pps }, { data: allUsers }] = await Promise.all([
    supabase.from('practice_practitioners').select('*'),
    supabase.from('users').select('id, first_name, last_name, email'),
  ]);
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  res.json(success((pps || []).map(pp => enrichPP(pp, usersMap))));
});

// POST /pma/practice/create
router.post('/create', async (req, res) => {
  const data = validate(createPracticeSchema, req, res);
  if (!data) return;
  const { name, userId, practiceNumber, address, phoneNumber } = data;

  const { data: practice, error } = await supabase
    .from('practices')
    .insert({ name, practice_number: practiceNumber, address, phone_number: phoneNumber })
    .select()
    .single();

  if (error) return res.status(500).json(err(error.message));

  await supabase.from('user_roles').insert({
    user_id: userId, practice_id: practice.id, role_id: 'ROLE_ADMIN', role_name: 'Admin',
  });

  res.status(201).json(success(toCamel(practice)));
});

// PUT /pma/practice/update/:id
router.put('/update/:id', async (req, res) => {
  const data = validate(updatePracticeSchema, req, res);
  if (!data) return;
  const { name, practiceNumber, address, phoneNumber } = data;

  const updates = {};
  if (name !== undefined) updates.name = name;
  if (practiceNumber !== undefined) updates.practice_number = practiceNumber;
  if (address !== undefined) updates.address = address;
  if (phoneNumber !== undefined) updates.phone_number = phoneNumber;

  const { data: practice, error } = await supabase
    .from('practices')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json(err(error.message));
  if (!practice) return res.status(404).json(err('Practice not found'));

  res.json(success(toCamel(practice)));
});

// GET /pma/practice/practitioners/:id
router.get('/practitioners/:id', async (req, res) => {
  const [{ data: pp }, { data: allUsers }] = await Promise.all([
    supabase.from('practice_practitioners').select('*').eq('id', req.params.id).maybeSingle(),
    supabase.from('users').select('id, first_name, last_name, email'),
  ]);
  if (!pp) return res.status(404).json(err('Practitioner not found'));
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  res.json(success(enrichPP(pp, usersMap)));
});

export default router;
