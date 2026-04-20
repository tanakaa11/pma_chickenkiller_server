import { Router } from 'express';
import { randomUUID } from 'crypto';
import { supabase } from '../supabase.js';
import { validate, createAppointmentSchema, patchAppointmentSchema } from '../utils/validation.js';
import { APPOINTMENT_SELECT, formatAppointment, success, err, toCamel } from '../helpers/format.js';

const router = Router();

const calculateEnd = (s) => {
  const [h, m] = s.split(':').map(Number);
  const em = m + 30;
  return `${String(h + Math.floor(em / 60)).padStart(2, '0')}:${String(em % 60).padStart(2, '0')}`;
};

// GET /pma/appointments
router.get('/', async (req, res) => {
  const { page, pageSize, status, doctorId, patientId, dateFrom, dateTo, lean } = req.query;
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext;

  // Resolve doctor IDs scoped to the current practice
  let filteredDoctorIds = null;
  if (!isSuperSuperAdmin || practiceId) {
    const { data: practitionerIds } = await supabase.from('practice_practitioners').select('user_id').eq('practice_id', practiceId);
    const { data: doctorRows }       = await supabase.from('doctors').select('id').in('user_id', (practitionerIds || []).map(p => p.user_id));
    if (!doctorRows?.length) return res.json(success([]));
    filteredDoctorIds = doctorRows.map(d => d.id);
  }

  // Lightweight stale-detection query (IDs only — does not load full APPOINTMENT_SELECT)
  const today = new Date().toISOString().split('T')[0];
  {
    let staleQ = supabase.from('appointments').select('id').lt('date', today).in('status', ['in_consultation', 'confirmed']);
    if (filteredDoctorIds) staleQ = staleQ.in('doctor_id', filteredDoctorIds);
    const { data: staleRows } = await staleQ;
    if (staleRows?.length > 0) {
      await supabase.from('appointments').update({ status: 'completed', updated_at: new Date().toISOString() }).in('id', staleRows.map(r => r.id));
    }
  }

  // Query builder — reused for both data and count
  const applyFilters = (q) => {
    if (filteredDoctorIds) q = q.in('doctor_id', filteredDoctorIds);
    if (status) { const statuses = Array.isArray(status) ? status : [status]; q = statuses.length === 1 ? q.eq('status', statuses[0]) : q.in('status', statuses); }
    if (doctorId)  q = q.eq('doctor_id',  doctorId);
    if (patientId) q = q.eq('patient_id', patientId);
    if (dateFrom)  q = q.gte('date', dateFrom);
    if (dateTo)    q = q.lte('date', dateTo);
    return q;
  };

  if (page && pageSize) {
    const p = parseInt(page), ps = parseInt(pageSize);
    const from = (p - 1) * ps;
    const dataQ  = applyFilters(supabase.from('appointments').select(lean === 'true' ? '*' : APPOINTMENT_SELECT)).order('date', { ascending: false }).order('start_time', { ascending: false }).range(from, from + ps - 1);
    const countQ = applyFilters(supabase.from('appointments').select('id', { count: 'exact', head: true }));
    const [{ data: appointments, error: dbErr }, { count }] = await Promise.all([dataQ, countQ]);
    if (dbErr) return res.status(500).json(err('Failed to fetch appointments'));
    const total = count ?? 0;
    const formatted = lean === 'true' ? (appointments || []).map(toCamel) : (appointments || []).map(formatAppointment);
    return res.json(success({ data: formatted, total, page: p, pageSize: ps, totalPages: Math.ceil(total / ps) }));
  }

  const { data: appointments, error: dbErr } = await applyFilters(supabase.from('appointments').select(lean === 'true' ? '*' : APPOINTMENT_SELECT)).order('date', { ascending: false }).order('start_time', { ascending: false });
  if (dbErr) return res.status(500).json(err('Failed to fetch appointments'));
  res.json(success(lean === 'true' ? (appointments || []).map(toCamel) : (appointments || []).map(formatAppointment)));
});

// GET /pma/appointments/:id
router.get('/:id', async (req, res) => {
  const { data: apt } = await supabase.from('appointments').select(APPOINTMENT_SELECT).eq('id', req.params.id).single();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  res.json(success(formatAppointment(apt)));
});

// GET /pma/appointments/patient/:patientId
router.get('/patient/:patientId', async (req, res) => {
  const { data: apts } = await supabase.from('appointments').select(APPOINTMENT_SELECT).eq('patient_id', req.params.patientId);
  res.json(success((apts || []).map(formatAppointment)));
});

// GET /pma/appointments/doctor/:doctorId
router.get('/doctor/:doctorId', async (req, res) => {
  const { data: apts } = await supabase.from('appointments').select(APPOINTMENT_SELECT).eq('doctor_id', req.params.doctorId);
  res.json(success((apts || []).map(formatAppointment)));
});

// POST /pma/appointments
router.post('/', async (req, res) => {
  const data = validate(createAppointmentSchema, req, res);
  if (!data) return;
  const { data: conflict } = await supabase.from('appointments').select('id')
    .eq('doctor_id', data.doctorId).eq('date', data.date).eq('start_time', data.startTime)
    .not('status', 'in', '("cancelled","rejected")').maybeSingle();
  if (conflict) return res.status(400).json(err('This time slot is already booked'));
  const { data: patientDayConflict } = await supabase.from('appointments').select('id')
    .eq('patient_id', data.patientId).eq('date', data.date).not('status', 'in', '("cancelled","rejected")').maybeSingle();
  if (patientDayConflict) return res.status(400).json(err('This patient already has an appointment booked for this date.'));
  const newId = randomUUID();
  const now   = new Date().toISOString();
  await supabase.from('appointments').insert({
    id: newId, patient_id: data.patientId, doctor_id: data.doctorId,
    practice_id: data.practiceId, beneficiary_id: data.beneficiaryId || null,
    date: data.date, start_time: data.startTime, end_time: calculateEnd(data.startTime),
    status: 'confirmed', type: 'consultation', notes: data.notes || '', created_at: now, updated_at: now,
  });
  const { data: newApt } = await supabase.from('appointments').select(APPOINTMENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatAppointment(newApt), 'Appointment booked successfully'));
});

// POST /pma/appointments/:id/approve-reception
router.post('/:id/approve-reception', async (req, res) => {
  const { userId } = req.body;
  const { data: apt } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  if (apt.status !== 'pending_reception') return res.status(400).json(err('Appointment is not pending reception approval'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'confirmed', updated_at: new Date().toISOString(), approved_by_reception: { userId, timestamp: new Date().toISOString() } })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment confirmed'));
});

// POST /pma/appointments/:id/approve-doctor
router.post('/:id/approve-doctor', async (req, res) => {
  const { userId } = req.body;
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'confirmed', updated_at: new Date().toISOString(), approved_by_doctor: { userId, timestamp: new Date().toISOString() } })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment confirmed by doctor'));
});

// POST /pma/appointments/:id/reject
router.post('/:id/reject', async (req, res) => {
  const { reason } = req.body;
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'rejected', rejection_reason: reason, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment rejected'));
});

// POST /pma/appointments/:id/cancel
router.post('/:id/cancel', async (req, res) => {
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'cancelled', updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment cancelled'));
});

// PATCH /pma/appointments/:id
router.patch('/:id', async (req, res) => {
  const data = validate(patchAppointmentSchema, req, res);
  if (!data) return;
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const upd = { updated_at: new Date().toISOString() };
  if (data.status    !== undefined) upd.status     = data.status;
  if (data.notes     !== undefined) upd.notes      = data.notes;
  if (data.date      !== undefined) upd.date       = data.date;
  if (data.startTime !== undefined) upd.start_time = data.startTime;
  if (data.endTime   !== undefined) upd.end_time   = data.endTime;
  const { data: updated } = await supabase.from('appointments').update(upd).eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment updated'));
});

// POST /pma/appointments/:id/start-consultation
router.post('/:id/start-consultation', async (req, res) => {
  const { data: apt } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  if (apt.status !== 'confirmed') return res.status(400).json(err('Only confirmed appointments can start consultation'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'in_consultation', updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Consultation started'));
});

export default router;
