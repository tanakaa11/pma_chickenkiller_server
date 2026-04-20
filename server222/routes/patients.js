import { Router } from 'express';
import { randomUUID } from 'crypto';
import { supabase } from '../supabase.js';
import { validate, createPatientSchema, updatePatientSchema, beneficiarySchema } from '../utils/validation.js';
import { PATIENT_SELECT, formatPatient, success, err } from '../helpers/format.js';
import { sanitizeSearch } from '../utils/constants.js';
import { logAudit } from '../utils/audit.js';

const router = Router();

// GET /pma/patients
router.get('/', async (req, res) => {

  const { page, pageSize, search, idNumber, ids } = req.query;
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  let query = supabase.from('patients').select(PATIENT_SELECT);
  
  if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) {
    query = query.or(`practice_id.eq.${practiceId},practice_id.is.null`);
  }
  if (ids) {
    query = query.in('id', ids.split(',').map(id => id.trim()).filter(Boolean));
    const { data: patients } = await query;
    return res.json(success((patients || []).map(formatPatient)));
  }
  if (idNumber) query = query.eq('id_number', idNumber);
  if (search) { const safe = sanitizeSearch(search); query = query.or(`first_name.ilike.%${safe}%,last_name.ilike.%${safe}%,phone.ilike.%${safe}%,id_number.ilike.%${safe}%`); }
  const { data: patients, error: dbErr } = await query;
  if (dbErr) return res.status(500).json(err('Failed to fetch patients'));
  const formatted = (patients || []).map(formatPatient);
  if (page && pageSize) {
    const p = parseInt(page), ps = Math.min(parseInt(pageSize), 100);
    const from = (p - 1) * ps;
    // Count query runs in parallel with the paginated data fetch
    let countQ = supabase.from('patients').select('id', { count: 'exact', head: true });
    if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) {
      countQ = countQ.or(`practice_id.eq.${practiceId},practice_id.is.null`);
    }
    if (idNumber) countQ = countQ.eq('id_number', idNumber);
    if (search) { const safe = sanitizeSearch(search); countQ = countQ.or(`first_name.ilike.%${safe}%,last_name.ilike.%${safe}%,phone.ilike.%${safe}%,id_number.ilike.%${safe}%`); }
    const [pagedData, { count }] = await Promise.all([
      (async () => {
        let pq = supabase.from('patients').select(PATIENT_SELECT);
        if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) pq = pq.or(`practice_id.eq.${practiceId},practice_id.is.null`);
        if (idNumber) pq = pq.eq('id_number', idNumber);
        if (search) { const safe = sanitizeSearch(search); pq = pq.or(`first_name.ilike.%${safe}%,last_name.ilike.%${safe}%,phone.ilike.%${safe}%,id_number.ilike.%${safe}%`); }
        return pq.range(from, from + ps - 1);
      })(),
      countQ,
    ]);
    if (pagedData.error) return res.status(500).json(err('Failed to fetch patients'));
    const total = count ?? 0;
    return res.json(success({
      data: (pagedData.data || []).map(formatPatient),
      total, page: p, pageSize: ps, totalPages: Math.ceil(total / ps),
    }));
  }
  res.json(success(formatted));
});

// GET /pma/patients/search
router.get('/search', async (req, res) => {

  const { q } = req.query;
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  if (!q) return res.json(success([]));
  const safe = sanitizeSearch(q);
  let query = supabase.from('patients').select(PATIENT_SELECT);
  if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) query = query.eq('practice_id', practiceId);
  query = query.or(`first_name.ilike.%${safe}%,last_name.ilike.%${safe}%,id_number.ilike.%${safe}%,email.ilike.%${safe}%,phone.ilike.%${safe}%`);
  const { data: patients } = await query;
  const results = (patients || []).map(formatPatient);
  results.sort((a, b) => {
    const qL = safe.toLowerCase();
    const aId = (a.idNumber || '').toLowerCase(), bId = (b.idNumber || '').toLowerCase();
    if (aId === qL && bId !== qL) return -1;
    if (bId === qL && aId !== qL) return  1;
    if (aId.startsWith(qL) && !bId.startsWith(qL)) return -1;
    if (bId.startsWith(qL) && !aId.startsWith(qL)) return  1;
    return (a.firstName || '').localeCompare(b.firstName || '');
  });
  res.json(success(results));
});

// GET /pma/patients/id-number/:idNumber
router.get('/id-number/:idNumber', async (req, res) => {
  const { data: patients } = await supabase.from('patients').select(PATIENT_SELECT).eq('id_number', req.params.idNumber);
  if (!patients || patients.length === 0) return res.status(404).json(err('Patient not found'));
  res.json(success(formatPatient(patients[0])));
});

// GET /pma/patients/:id
router.get('/:id', async (req, res) => {
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  const { data: p } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', req.params.id).single();
  if (!p) return res.status(404).json(err('Patient not found'));
  if (!isSuperAdmin && !isSuperSuperAdmin && p.practice_id && practiceId && p.practice_id !== practiceId) {
    return res.status(403).json(err('Access denied'));
  }
  logAudit(req, 'VIEW_PATIENT', req.params.id);
  res.json(success(formatPatient(p)));
});

// POST /pma/patients
router.post('/', async (req, res) => {
  const data = validate(createPatientSchema, req, res);

  if (!data) return;
  if (data.idNumber) {
    const { data: existing } = await supabase.from('patients').select('id').eq('id_number', data.idNumber).maybeSingle();
    if (existing) return res.status(400).json(err('A patient with this ID number already exists'));
  }

  const newId = randomUUID();
  const now   = new Date().toISOString();
  const { error: insertErr } = await supabase.from('patients').insert({
    id: newId, first_name: data.firstName, last_name: data.lastName,
    date_of_birth: data.dateOfBirth, gender: data.gender, id_number: data.idNumber,
    phone: data.phone, email: data.email,
    practice_id: data.practiceId || req.userContext?.practiceId || null,
    allergies: data.allergies || [], created_at: now, updated_at: now,
  });

  if (insertErr) return res.status(500).json(err('Failed to create patient'));
  if (data.address) {
    await supabase.from('patient_addresses').insert({
      patient_id: newId, street: data.address.street, city: data.address.city,
      province: data.address.province, postal_code: data.address.postalCode || data.address.postal_code,
    });
  }

  if (data.emergencyContact) {
    await supabase.from('patient_emergency_contacts').insert({
      patient_id: newId, name: data.emergencyContact.name,
      relationship: data.emergencyContact.relationship, phone: data.emergencyContact.phone,
    });
  }

  if (data.medicalAids) {
    const inserts = [];
    if (data.medicalAids.active) inserts.push({ patient_id: newId, provider_name: data.medicalAids.active.providerName, plan_name: data.medicalAids.active.planName, membership_number: data.medicalAids.active.membershipNumber, is_active: true });
    for (const h of (data.medicalAids.history || [])) inserts.push({ patient_id: newId, provider_name: h.providerName, plan_name: h.planName, membership_number: h.membershipNumber, is_active: false });
    if (inserts.length > 0) await supabase.from('patient_medical_aids').insert(inserts);
  }

  logAudit(req, 'CREATE_PATIENT', newId);
  const { data: newPatient } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatPatient(newPatient), 'Patient created successfully'));

});

// PUT /pma/patients/:id
router.put('/:id', async (req, res) => {
  const data = validate(updatePatientSchema, req, res);
  if (!data) return;

  const { data: existing } = await supabase.from('patients').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Patient not found'));

  const now = new Date().toISOString();

  const upd = { updated_at: now };

  if (data.firstName   !== undefined) upd.first_name    = data.firstName;
  if (data.lastName    !== undefined) upd.last_name     = data.lastName;
  if (data.dateOfBirth !== undefined) upd.date_of_birth = data.dateOfBirth;
  if (data.gender      !== undefined) upd.gender        = data.gender;
  if (data.idNumber    !== undefined) upd.id_number     = data.idNumber;
  if (data.phone       !== undefined) upd.phone         = data.phone;
  if (data.email       !== undefined) upd.email         = data.email;
  if (data.practiceId  !== undefined) upd.practice_id   = data.practiceId;
  if (data.allergies   !== undefined) upd.allergies     = data.allergies;
  await supabase.from('patients').update(upd).eq('id', req.params.id);

  if (data.address) {

    await supabase.from('patient_addresses').delete().eq('patient_id', req.params.id);
    await supabase.from('patient_addresses').insert({ patient_id: req.params.id, street: data.address.street, city: data.address.city, province: data.address.province, postal_code: data.address.postalCode || data.address.postal_code });
  }

  if (data.emergencyContact) {
    await supabase.from('patient_emergency_contacts').delete().eq('patient_id', req.params.id);
    await supabase.from('patient_emergency_contacts').insert({ patient_id: req.params.id, name: data.emergencyContact.name, relationship: data.emergencyContact.relationship, phone: data.emergencyContact.phone });
  }

  if (data.medicalAids) {
    await supabase.from('patient_medical_aids').delete().eq('patient_id', req.params.id);
    const inserts = [];
    if (data.medicalAids.active) inserts.push({ patient_id: req.params.id, provider_name: data.medicalAids.active.providerName, plan_name: data.medicalAids.active.planName, membership_number: data.medicalAids.active.membershipNumber, is_active: true });
    for (const h of (data.medicalAids.history || [])) inserts.push({ patient_id: req.params.id, provider_name: h.providerName, plan_name: h.planName, membership_number: h.membershipNumber, is_active: false });
    if (inserts.length > 0) await supabase.from('patient_medical_aids').insert(inserts);
  }

  logAudit(req, 'UPDATE_PATIENT', req.params.id);
  const { data: updated } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', req.params.id).single();
  res.json(success(formatPatient(updated), 'Patient updated successfully'));

});

// GET /pma/patients/:id/beneficiaries
router.get('/:id/beneficiaries', async (req, res) => {

  const { data: bens } = await supabase.from('beneficiaries').select('patient_id').eq('main_member_id', req.params.id);

  if (!bens || bens.length === 0) return res.json(success([]));
  const { data: patients } = await supabase.from('patients').select(PATIENT_SELECT).in('id', bens.map(b => b.patient_id));
  res.json(success((patients || []).map(formatPatient)));

});

// POST /pma/patients/:id/beneficiaries
router.post('/:id/beneficiaries', async (req, res) => {

  const data = validate(beneficiarySchema, req, res);


  if (!data) return;
  const { relationship, ...bData } = data;
  const newId = randomUUID();
  const now   = new Date().toISOString();
  const { error: patientErr } = await supabase.from('patients').insert({

    id: newId, first_name: bData.firstName, last_name: bData.lastName,
    date_of_birth: bData.dateOfBirth, gender: bData.gender, id_number: bData.idNumber,
    phone: bData.phone, email: bData.email, practice_id: bData.practiceId,
    allergies: bData.allergies || [], created_at: now, updated_at: now,

  });

  if (patientErr) return res.status(500).json(err('Failed to create beneficiary patient record'));

  if (bData.address) {

    const { error: addrErr } = await supabase.from('patient_addresses').insert({
      patient_id: newId, street: bData.address.street, city: bData.address.city,
      province: bData.address.province, postal_code: bData.address.postalCode,

    });

    if (addrErr) console.error('[BENEFICIARY] Address insert failed:', addrErr.message);
  }
  const { error: benErr } = await supabase.from('beneficiaries').insert({

    id: randomUUID(), patient_id: newId, main_member_id: req.params.id, relationship,

  });

  if (benErr) return res.status(500).json(err('Failed to create beneficiary link'));

  logAudit(req, 'CREATE_BENEFICIARY', newId);
  const { data: newPatient } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatPatient(newPatient), 'Beneficiary added successfully'));

});

export default router;
