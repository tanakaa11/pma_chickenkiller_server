import { Router } from 'express';
import { supabase } from '../supabase.js';
import { INVOICE_SELECT, formatInvoice, success, err } from '../helpers/format.js';
import { logAudit } from '../utils/audit.js';
import { sendMailAsync, emailTransporter } from '../config/email.js';

const router = Router();

// ─── Helpers ─────────────────────────────────────────────────────────────────

const STATUS_COLORS = {
  draft: '#6b7280', issued: '#3b82f6', paid: '#16a34a', cancelled: '#ef4444',
};

const formatDate = (iso) =>
  new Date(iso).toLocaleDateString('en-ZA', { year: 'numeric', month: 'long', day: 'numeric' });

const buildInvoiceEmailHtml = ({ invoice, patient, practiceName, practicePhone }) => {
  const statusColor = STATUS_COLORS[invoice.status] || '#6b7280';
  const statusLabel = invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1);

  const lineItemRows = (invoice.invoice_line_items || []).map(item => `
    <tr>
      <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:13px;color:#374151">${item.reference_code}</td>
      <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#374151">${item.description}</td>
      <td style="padding:12px 16px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:600;font-size:14px;color:#374151">R ${Number(item.amount).toFixed(2)}</td>
    </tr>`).join('');

  const paidRow = invoice.paid_at
    ? `<tr><td colspan="2" style="padding-top:6px;color:#16a34a;font-size:13px">Paid on ${formatDate(invoice.paid_at)}</td></tr>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6">
    <tr><td align="center" style="padding:40px 16px">
      <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 12px rgba(0,0,0,0.08)">

        <!-- Header -->
        <tr>
          <td style="background:#1d4ed8;padding:36px 40px;text-align:center">
            <p style="margin:0;color:#bfdbfe;font-size:13px;text-transform:uppercase;letter-spacing:0.1em;font-weight:600">Tax Invoice</p>
            <h1 style="margin:8px 0 0;color:#ffffff;font-size:26px;font-weight:700">${practiceName}</h1>
            ${practicePhone ? `<p style="margin:8px 0 0;color:#bfdbfe;font-size:13px">Tel: ${practicePhone}</p>` : ''}
          </td>
        </tr>

        <!-- Invoice Meta -->
        <tr>
          <td style="padding:32px 40px 24px">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="vertical-align:top;width:50%">
                  <p style="margin:0 0 4px;color:#9ca3af;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;font-weight:600">Billed To</p>
                  <p style="margin:0;font-weight:700;font-size:16px;color:#111827">${patient.first_name} ${patient.last_name}</p>
                  ${patient.id_number ? `<p style="margin:4px 0 0;color:#6b7280;font-size:13px">ID: ${patient.id_number}</p>` : ''}
                </td>
                <td style="vertical-align:top;text-align:right;width:50%">
                  <p style="margin:0 0 4px;color:#9ca3af;font-size:11px;text-transform:uppercase;letter-spacing:0.08em;font-weight:600">Invoice Date</p>
                  <p style="margin:0;font-weight:700;font-size:16px;color:#111827">${formatDate(invoice.created_at)}</p>
                  <span style="display:inline-block;margin-top:8px;background:${statusColor};color:#fff;padding:3px 12px;border-radius:999px;font-size:12px;font-weight:600">${statusLabel}</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Divider -->
        <tr><td style="padding:0 40px"><hr style="border:none;border-top:1px solid #e5e7eb;margin:0"></td></tr>

        <!-- Line Items -->
        <tr>
          <td style="padding:24px 40px">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">
              <thead>
                <tr style="background:#f9fafb">
                  <th style="padding:10px 16px;text-align:left;font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:0.08em;border-bottom:1px solid #e5e7eb">Code</th>
                  <th style="padding:10px 16px;text-align:left;font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:0.08em;border-bottom:1px solid #e5e7eb">Description</th>
                  <th style="padding:10px 16px;text-align:right;font-size:11px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:0.08em;border-bottom:1px solid #e5e7eb">Amount</th>
                </tr>
              </thead>
              <tbody>${lineItemRows}</tbody>
            </table>
          </td>
        </tr>

        <!-- Total -->
        <tr>
          <td style="padding:0 40px 32px">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:18px 20px">
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="font-size:15px;font-weight:600;color:#1f2937">Total Amount</td>
                      <td style="text-align:right;font-size:26px;font-weight:700;color:#16a34a">R ${Number(invoice.total_amount).toFixed(2)}</td>
                    </tr>
                    ${paidRow}
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:24px 40px;background:#f9fafb;border-top:1px solid #e5e7eb;text-align:center">
            <p style="margin:0;color:#6b7280;font-size:13px;font-weight:500">${practiceName}</p>
            <p style="margin:8px 0 0;color:#9ca3af;font-size:11px">This is a computer-generated invoice. No signature required.</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
};

// ─── Routes ──────────────────────────────────────────────────────────────────

// GET /pma/invoices
router.get('/', async (req, res) => {
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  let query = supabase.from('invoices').select(INVOICE_SELECT).order('created_at', { ascending: true });
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
  const { data: invoices } = await supabase
    .from('invoices').select(INVOICE_SELECT).eq('patient_id', req.params.patientId).order('created_at', { ascending: true });
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

// POST /pma/invoices/:id/email  — send invoice to patient's email
router.post('/:id/email', async (req, res) => {
  if (!emailTransporter) return res.status(503).json(err('Email is not configured on the server.'));

  const { data: inv } = await supabase
    .from('invoices').select(INVOICE_SELECT).eq('id', req.params.id).maybeSingle();
  if (!inv) return res.status(404).json(err('Invoice not found'));

  const { data: patient } = await supabase
    .from('patients').select('id, first_name, last_name, email, id_number')
    .eq('id', inv.patient_id).maybeSingle();
  if (!patient?.email) return res.status(400).json(err('Patient does not have an email address on file'));

  const { practiceId } = req.userContext || {};
  let practiceName = 'PMA Health Hub';
  let practicePhone = '';
  if (practiceId) {
    const { data: practice } = await supabase
      .from('practices').select('name, phone').eq('id', practiceId).maybeSingle();
    if (practice) { practiceName = practice.name; practicePhone = practice.phone || ''; }
  }

  const html = buildInvoiceEmailHtml({ invoice: inv, patient, practiceName, practicePhone });

  try {
    await emailTransporter.sendMail({
      from: `"${practiceName}" <${process.env.SMTP_USER}>`,
      to: patient.email,
      subject: `Invoice from ${practiceName}`,
      html,
    });
    logAudit(req, 'EMAIL_INVOICE', req.params.id);
    res.json(success(null, `Invoice emailed to ${patient.email}`));
  } catch (mailErr) {
    console.error('❌ [EMAIL] Invoice email failed:', mailErr.message);
    res.status(500).json(err('Failed to send invoice email'));
  }
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
