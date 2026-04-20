import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { supabase } from '../supabase.js';
import { validate, otpSendSchema, otpVerifySchema } from '../utils/validation.js';
import { success, err } from '../helpers/format.js';
import { emailTransporter } from '../config/email.js';

const router = Router();

const otpSendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many OTP requests. Please try again in 1 hour.' },
});

const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many verification attempts. Please try again in 15 minutes.' },
});

// In-memory OTP store (module-scoped)
const otpStore = new Map();

// POST /pma/otp/send
router.post('/send', otpSendLimiter, async (req, res) => {
  const data = validate(otpSendSchema, req, res);
  if (!data) return;
  const { phone, email: emailFromBody, appointmentData } = data;
  if (!emailTransporter) return res.status(500).json(err('Email service is not configured on the server.'));

  let email = emailFromBody || '';
  if (!email && appointmentData?.patientId) {
    const { data: patientRow } = await supabase.from('patients').select('email').eq('id', appointmentData.patientId).maybeSingle();
    email = patientRow?.email || '';
  }
  if (!email) return res.status(400).json(err('No email address found for this patient.'));

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const otpEntry = { code, expiresAt: Date.now() + 300000, appointmentData, resolvedEmail: email };
  otpStore.set(email, otpEntry);
  if (phone) otpStore.set(phone, otpEntry);

  try {
    await emailTransporter.sendMail({
      from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Your Appointment Booking Verification Code',
      html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;color:#1e293b">
        <h2>Appointment Booking Verification</h2>
        <p>Use the code below to confirm your booking. It expires in <strong>5 minutes</strong>.</p>
        <div style="background:#f1f5f9;border-radius:10px;padding:24px 0;text-align:center;margin:24px 0">
          <span style="font-size:36px;font-family:monospace;letter-spacing:10px;font-weight:bold;color:#2563eb">${code}</span>
        </div>
        <p style="font-size:13px;color:#94a3b8">Do not share this code with anyone.</p>
      </div>`,
    });
    res.json(success({ sent: true, email }, `Verification code sent to ${email}`));
  } catch (mailErr) {
    console.error(`❌ [EMAIL] Failed to send OTP to ${email}:`, mailErr.message);
    res.status(500).json(err('Failed to send verification email. Please try again.'));
  }
});

// POST /pma/otp/verify
router.post('/verify', otpVerifyLimiter, async (req, res) => {
  const data = validate(otpVerifySchema, req, res);
  if (!data) return;
  const { phone, email, code } = data;

  let key = null, stored = null;
  if (email) { const entry = otpStore.get(email); if (entry) { key = email; stored = entry; } }
  if (!stored && phone) { const entry = otpStore.get(phone); if (entry) { key = phone; stored = entry; } }
  if (!stored) {
    for (const [k, v] of otpStore.entries()) {
      if ((email && v.resolvedEmail === email) || (phone && k === phone)) { key = k; stored = v; break; }
    }
  }

  if (!stored) return res.status(400).json(err('No OTP was sent to this address. Please request a new code.'));

  if (Date.now() > stored.expiresAt) {
    otpStore.delete(key);
    if (stored.resolvedEmail) otpStore.delete(stored.resolvedEmail);
    if (phone) otpStore.delete(phone);
    return res.status(400).json(err('OTP has expired'));
  }

  if (stored.code === code) {
    const { appointmentData } = stored;
    otpStore.delete(key);
    if (stored.resolvedEmail) otpStore.delete(stored.resolvedEmail);
    if (phone) otpStore.delete(phone);

    if (appointmentData) {
      try {
        const d = appointmentData;
        const { data: conflict } = await supabase.from('appointments').select('id')
          .eq('doctor_id', d.doctorId).eq('date', d.date).eq('start_time', d.startTime)
          .not('status', 'in', '("cancelled","rejected")').maybeSingle();
        if (conflict) return res.status(400).json(err('This time slot is already booked'));

        const { data: patientDayConflict } = await supabase.from('appointments').select('id')
          .eq('patient_id', d.patientId).eq('date', d.date)
          .not('status', 'in', '("cancelled","rejected")').maybeSingle();
        if (patientDayConflict) return res.status(400).json(err('This patient already has an appointment booked for this date.'));

        const calculateEnd = (s) => {
          const [h, m] = s.split(':').map(Number);
          const em = m + 30;
          return `${String(h + Math.floor(em / 60)).padStart(2, '0')}:${String(em % 60).padStart(2, '0')}`;
        };
        const { randomUUID } = await import('crypto');
        const newId = randomUUID();
        const now = new Date().toISOString();
        await supabase.from('appointments').insert({
          id: newId, patient_id: d.patientId, doctor_id: d.doctorId,
          practice_id: d.practiceId || null, beneficiary_id: d.beneficiaryId || null,
          date: d.date, start_time: d.startTime, end_time: calculateEnd(d.startTime),
          status: 'confirmed', type: 'consultation', notes: d.notes || '', created_at: now, updated_at: now,
        });
        return res.json(success({ verified: true }, 'OTP verified and appointment booked'));
      } catch (dbErr) {
        console.error('Appointment creation error after OTP verify:', dbErr);
        return res.status(500).json(err('OTP verified but appointment creation failed'));
      }
    }
    return res.json(success({ verified: true }, 'OTP verified'));
  }

  return res.status(400).json(err('Invalid OTP'));
});

export default router;
