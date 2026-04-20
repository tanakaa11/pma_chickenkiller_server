import { Router } from 'express';
import { randomUUID } from 'crypto';
import { supabase } from '../supabase.js';
import { validate, createVisitSchema, updateVisitSchema } from '../utils/validation.js';
import { VISIT_SELECT, INVOICE_SELECT, formatVisit, success, err, snakeKeys } from '../helpers/format.js';
import { enrichVisit, enrichVisitsBatch } from '../helpers/enrichment.js';
import { logAudit } from '../utils/audit.js';

const router = Router();

// GET /pma/visits
router.get('/', async (req, res) => {
  const { patientId, doctorId, dateFrom, dateTo, status } = req.query;
  let query = supabase.from('visits').select(VISIT_SELECT);
  if (patientId) query = query.eq('patient_id', patientId);
  if (doctorId)  query = query.eq('doctor_id',  doctorId);
  if (dateFrom)  query = query.gte('visit_date', dateFrom);
  if (dateTo)    query = query.lte('visit_date', dateTo);
  if (status)    query = query.eq('status', status);
  query = query.order('visit_date', { ascending: false });
  const { data: visits } = await query;
  const enriched = await enrichVisitsBatch((visits || []).map(formatVisit));
  res.json(success(enriched));
});

// GET /pma/visits/patient/:patientId
router.get('/patient/:patientId', async (req, res) => {
  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT).eq('patient_id', req.params.patientId).order('visit_date', { ascending: false });
  logAudit(req, 'VIEW_PATIENT_VISITS', req.params.patientId);
  const enriched = await enrichVisitsBatch((visits || []).map(formatVisit));
  res.json(success(enriched));
});

// GET /pma/visits/doctor/:doctorId
router.get('/doctor/:doctorId', async (req, res) => {
  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT).eq('doctor_id', req.params.doctorId).order('visit_date', { ascending: false });
  const enriched = await enrichVisitsBatch((visits || []).map(formatVisit));
  res.json(success(enriched));
});

// GET /pma/visits/appointment/:appointmentId
router.get('/appointment/:appointmentId', async (req, res) => {
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT).eq('appointment_id', req.params.appointmentId).maybeSingle();
  if (!visit) return res.status(404).json(err('No visit found for this appointment'));
  res.json(success(await enrichVisit(formatVisit(visit))));
});

// GET /pma/visits/:id
router.get('/:id', async (req, res) => {
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).maybeSingle();
  if (!visit) return res.status(404).json(err('Visit not found'));
  logAudit(req, 'VIEW_VISIT', req.params.id);
  res.json(success(await enrichVisit(formatVisit(visit))));
});

// POST /pma/visits
router.post('/', async (req, res) => {
  const data = validate(createVisitSchema, req, res);
  if (!data) return;
  const now = new Date().toISOString();
  const visitId = randomUUID();
  const { error: insertError } = await supabase.from('visits').insert({
    id: visitId, appointment_id: data.appointmentId || null,
    patient_id: data.patientId, doctor_id: data.doctorId,
    practice_practitioner_id: data.practicePractitionerId || null,
    visit_date: now.split('T')[0], reason_for_visit: data.reasonForVisit || '',
    consultation_notes: data.consultationNotes || '', status: 'in_progress',
    created_at: now, updated_at: now,
  });
  if (insertError) { console.error('[POST /pma/visits] Insert error:', insertError.message); return res.status(500).json(err('Failed to create visit')); }
  if (data.vitals)           await supabase.from('visit_vitals').insert({ ...snakeKeys(data.vitals), id: randomUUID(), visit_id: visitId });
  if (data.diagnoses?.length)   await supabase.from('visit_diagnoses').insert(data.diagnoses.map(d => ({ id: randomUUID(), ...snakeKeys(d), visit_id: visitId })));
  if (data.procedures?.length)  await supabase.from('visit_procedures').insert(data.procedures.map(p => ({ id: randomUUID(), ...snakeKeys(p), visit_id: visitId })));
  if (data.prescriptions?.length)     await supabase.from('visit_prescriptions').insert(data.prescriptions.map(p => ({ ...snakeKeys(p), visit_id: visitId })));
  if (data.clinicalDocuments?.length) await supabase.from('visit_clinical_documents').insert(data.clinicalDocuments.map(d => ({ ...snakeKeys(d), visit_id: visitId })));
  if (data.appointmentId) await supabase.from('appointments').update({ status: 'in_consultation', updated_at: now }).eq('id', data.appointmentId);
  const { data: newVisit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', visitId).single();
  if (!newVisit) return res.status(500).json(err('Visit was created but could not be retrieved'));
  logAudit(req, 'CREATE_VISIT', visitId);
  res.status(201).json(success(await enrichVisit(formatVisit(newVisit)), 'Visit created successfully'));
});

// PUT /pma/visits/:id
router.put('/:id', async (req, res) => {
  const body = validate(updateVisitSchema, req, res);
  if (!body) return;
  const { data: existing } = await supabase.from('visits').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Visit not found'));
  const now = new Date().toISOString();
  await supabase.from('visits').update({ reason_for_visit: body.reasonForVisit, consultation_notes: body.consultationNotes, status: body.status, updated_at: now }).eq('id', req.params.id);
  if (body.vitals !== undefined) { await supabase.from('visit_vitals').delete().eq('visit_id', req.params.id); if (body.vitals) await supabase.from('visit_vitals').insert({ ...snakeKeys(body.vitals), visit_id: req.params.id }); }
  if (body.diagnoses !== undefined) { await supabase.from('visit_diagnoses').delete().eq('visit_id', req.params.id); if (body.diagnoses?.length) await supabase.from('visit_diagnoses').insert(body.diagnoses.map(d => ({ ...snakeKeys(d), visit_id: req.params.id }))); }
  if (body.procedures !== undefined) { await supabase.from('visit_procedures').delete().eq('visit_id', req.params.id); if (body.procedures?.length) await supabase.from('visit_procedures').insert(body.procedures.map(p => ({ ...snakeKeys(p), visit_id: req.params.id }))); }
  if (body.prescriptions !== undefined) { await supabase.from('visit_prescriptions').delete().eq('visit_id', req.params.id); if (body.prescriptions?.length) await supabase.from('visit_prescriptions').insert(body.prescriptions.map(p => ({ ...snakeKeys(p), visit_id: req.params.id }))); }
  if (body.clinicalDocuments !== undefined) { await supabase.from('visit_clinical_documents').delete().eq('visit_id', req.params.id); if (body.clinicalDocuments?.length) await supabase.from('visit_clinical_documents').insert(body.clinicalDocuments.map(d => ({ ...snakeKeys(d), visit_id: req.params.id }))); }
  logAudit(req, 'UPDATE_VISIT', req.params.id);
  const { data: updated } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).single();
  res.json(success(await enrichVisit(formatVisit(updated)), 'Visit updated'));
});

// POST /pma/visits/:id/complete
router.post('/:id/complete', async (req, res) => {
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).maybeSingle();
  if (!visit) return res.status(404).json(err('Visit not found'));
  const formatted = formatVisit(visit);
  const now = new Date().toISOString();
  await supabase.from('visits').update({ status: 'completed', updated_at: now }).eq('id', req.params.id);
  const lineItems = (formatted.procedures || []).map(proc => ({ reference_code: proc.code, description: proc.description, amount: proc.tariffAmount || 0 }));
  const totalAmount = lineItems.reduce((sum, li) => sum + li.amount, 0);
  const invId = randomUUID();
  await supabase.from('invoices').insert({ id: invId, visit_id: req.params.id, patient_id: visit.patient_id, total_amount: totalAmount, status: 'issued', created_at: now, paid_at: null });
  if (lineItems.length) await supabase.from('invoice_line_items').insert(lineItems.map(li => ({ ...li, invoice_id: invId })));
  if (visit.appointment_id) await supabase.from('appointments').update({ status: 'completed', updated_at: now }).eq('id', visit.appointment_id);
  logAudit(req, 'COMPLETE_VISIT', req.params.id);
  const { data: updatedVisit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).single();
  res.json(success(await enrichVisit(formatVisit(updatedVisit)), 'Visit completed and invoice generated'));
});

export default router;
