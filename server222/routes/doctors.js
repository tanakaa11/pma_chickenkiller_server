import { Router } from 'express';
import { randomUUID } from 'crypto';
import { supabase } from '../supabase.js';
import { success, err, toCamel } from '../helpers/format.js';

const router = Router();

// GET /pma/doctors
router.get('/', async (req, res) => {
  const { ids } = req.query;
  const { practiceId, isSuperAdmin } = req.userContext || {};

  if (!isSuperAdmin && practiceId) {
    const { data: practitionerIds } = await supabase.from('practice_practitioners').select('user_id').eq('practice_id', practiceId);
    const { data: roleUserIds }     = await supabase.from('user_roles').select('user_id').eq('practice_id', practiceId).eq('role_id', 'ROLE_PRACTITIONER');
    const allUserIds = [...new Set([...(practitionerIds || []).map(p => p.user_id), ...(roleUserIds || []).map(r => r.user_id)])];
    if (allUserIds.length === 0) return res.json(success([]));
    let query = supabase.from('doctors').select('*').in('user_id', allUserIds);
    if (ids) query = query.in('id', ids.split(','));
    const { data: doctors } = await query;
    return res.json(success((doctors || []).map(toCamel)));
  }

  let query = supabase.from('doctors').select('*');
  if (ids) query = query.in('id', ids.split(','));
  const { data: doctors } = await query;
  res.json(success((doctors || []).map(toCamel)));
});

// GET /pma/doctors/available
router.get('/available', async (req, res) => {
  const { date, time } = req.query;
  const { data: doctors } = await supabase.from('doctors').select('*').eq('is_available', true);
  if (!date) return res.json(success((doctors || []).map(toCamel)));
  const availableDoctors = [];
  for (const doc of (doctors || [])) {
    const { data: sched } = await supabase.from('schedules').select('*').eq('doctor_id', doc.id).eq('date', date);
    if (!sched || sched.length === 0) { availableDoctors.push(toCamel(doc)); continue; }
    if (time) { if (sched.some(s => s.status === 'available' && s.start_time <= time && s.end_time > time)) availableDoctors.push(toCamel(doc)); }
    else       { if (sched.some(s => s.status === 'available')) availableDoctors.push(toCamel(doc)); }
  }
  res.json(success(availableDoctors));
});

// GET /pma/doctors/:id
router.get('/:id', async (req, res) => {
  const { data: doctor } = await supabase.from('doctors').select('*').eq('id', req.params.id).single();
  if (!doctor) return res.status(404).json(err('Doctor not found'));
  res.json(success(toCamel(doctor)));
});

// GET /pma/doctors/:id/schedule
router.get('/:id/schedule', async (req, res) => {
  const { dateFrom, dateTo } = req.query;
  let query = supabase.from('schedules').select('*').eq('doctor_id', req.params.id);
  if (dateFrom) query = query.gte('date', dateFrom);
  if (dateTo)   query = query.lte('date', dateTo);
  const { data: schedule } = await query;
  res.json(success((schedule || []).map(toCamel)));
});

// POST /pma/doctors/:id/schedule
router.post('/:id/schedule', async (req, res) => {
  const sd = req.body;
  const { data: existingRow } = await supabase.from('schedules').select('id')
    .eq('doctor_id', req.params.id).eq('date', sd.date).eq('start_time', sd.startTime).maybeSingle();
  let result;
  if (existingRow) {
    const { data } = await supabase.from('schedules').update({ end_time: sd.endTime, status: sd.status || 'available' }).eq('id', existingRow.id).select().single();
    result = data;
  } else {
    const { data } = await supabase.from('schedules').insert({ id: randomUUID(), doctor_id: req.params.id, date: sd.date, start_time: sd.startTime, end_time: sd.endTime, status: sd.status || 'available' }).select().single();
    result = data;
  }
  res.json(success(toCamel(result), 'Schedule updated successfully'));
});

// PATCH /pma/doctors/:id/availability
router.patch('/:id/availability', async (req, res) => {
  const isAvailable = req.body.isAvailable;
  if (typeof isAvailable !== 'boolean') return res.status(400).json(err('isAvailable must be a boolean'));
  const { data: existing } = await supabase.from('doctors').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Doctor not found'));
  const { data: updated } = await supabase.from('doctors').update({ is_available: isAvailable }).eq('id', req.params.id).select().single();
  res.json(success(toCamel(updated)));
});

export default router;
