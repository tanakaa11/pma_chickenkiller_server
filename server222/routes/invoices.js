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

// PUT /pma/invoices/:id  — update line items and/or status (admin only)
router.put('/:id', async (req, res) => {
  const { lineItems, status } = req.body;

  const { data: inv } = await supabase
    .from('invoices').select('id, status').eq('id', req.params.id).maybeSingle();

  if (!inv) return res.status(404).json(err('Invoice not found'));
  if (inv.status === 'paid') return res.status(400).json(err('Paid invoices cannot be edited'));
  if (inv.status === 'cancelled') return res.status(400).json(err('Cancelled invoices cannot be edited'));

  const totalAmount = (lineItems || []).reduce((sum, item) => sum + (Number(item.amount) || 0), 0);

  const { error: updateErr } = await supabase
    .from('invoices')
    .update({ status, total_amount: totalAmount })
    .eq('id', req.params.id);

  if (updateErr) return res.status(500).json(err('Failed to update invoice'));

  // Replace line items: delete existing rows then insert the new set
  await supabase.from('invoice_line_items').delete().eq('invoice_id', req.params.id);

  if (lineItems && lineItems.length > 0) {
    const rows = lineItems.map(item => ({
      invoice_id: req.params.id,
      reference_code: item.referenceCode,
      description: item.description,
      amount: Number(item.amount) || 0,
    }));
    await supabase.from('invoice_line_items').insert(rows);
  }

  logAudit(req, 'UPDATE_INVOICE', req.params.id);

  const { data: updated } = await supabase
    .from('invoices').select(INVOICE_SELECT).eq('id', req.params.id).single();

  res.json(success(formatInvoice(updated), 'Invoice updated'));
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
