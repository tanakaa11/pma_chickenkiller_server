import { Router } from 'express';
import { supabase } from '../supabase.js';
import { INVOICE_SELECT, formatInvoice, success, err } from '../helpers/format.js';
import { logAudit } from '../utils/audit.js';

const router = Router();

// GET /pma/invoices
router.get('/', async (req, res) => {
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  let query = supabase.from('invoices').select(INVOICE_SELECT);
  if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) {
    const { data: practicePatients } = await supabase.from('patients').select('id').eq('practice_id', practiceId);
    const patientIds = (practicePatients || []).map(p => p.id);
    if (patientIds.length > 0) { query = query.in('patient_id', patientIds); }
    else { return res.json(success([])); }
  }
  const { data: invoices } = await query;
  res.json(success((invoices || []).map(formatInvoice)));
});

// GET /pma/invoices/visit/:visitId  — must be before /:id to avoid route conflict
router.get('/visit/:visitId', async (req, res) => {
  const { data: invoice } = await supabase.from('invoices').select(INVOICE_SELECT).eq('visit_id', req.params.visitId).maybeSingle();
  if (!invoice) return res.status(404).json(err('Invoice not found for this visit'));
  res.json(success(formatInvoice(invoice)));
});

// GET /pma/invoices/patient/:patientId
router.get('/patient/:patientId', async (req, res) => {
  const { data: invoices } = await supabase.from('invoices').select(INVOICE_SELECT).eq('patient_id', req.params.patientId);
  res.json(success((invoices || []).map(formatInvoice)));
});

// GET /pma/invoices/:id
router.get('/:id', async (req, res) => {
  const { data: invoice } = await supabase.from('invoices').select(INVOICE_SELECT).eq('id', req.params.id).maybeSingle();
  if (!invoice) return res.status(404).json(err('Invoice not found'));
  res.json(success(formatInvoice(invoice)));
});

// POST /pma/invoices/:id/mark-paid
router.post('/:id/mark-paid', async (req, res) => {
  const { data: inv } = await supabase.from('invoices').select('id').eq('id', req.params.id).maybeSingle();
  if (!inv) return res.status(404).json(err('Invoice not found'));
  logAudit(req, 'MARK_INVOICE_PAID', req.params.id);
  const { data: updated } = await supabase.from('invoices')
    .update({ status: 'paid', paid_at: new Date().toISOString() })
    .eq('id', req.params.id).select(INVOICE_SELECT).single();
  res.json(success(formatInvoice(updated), 'Invoice marked as paid'));
});

export default router;
