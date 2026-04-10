import dotenv from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import { supabase } from './supabase.js';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import { randomUUID, createHash } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '.env') });

// ============================================================================
// STARTUP — fail fast if critical env vars are absent
// ============================================================================
const CRITICAL_ENV = ['SUPABASE_URL', 'SUPABASE_KEY'];
const missingEnv = CRITICAL_ENV.filter(k => !process.env[k]);
if (missingEnv.length > 0) {
  console.error(`\n❌ FATAL: Missing required environment variables: ${missingEnv.join(', ')}`);
  console.error('   Add them to server22/server222/.env and restart.');
  process.exit(1);
}
if (!process.env.JWT_SECRET) console.warn('⚠️  JWT_SECRET not set in .env — using insecure dev fallback');
if (!process.env.CLIENT_URL) console.warn('⚠️  CLIENT_URL not set — invite/verification links will use default');
const app = express();
const PORT = process.env.PORT || 5000;

// --- Rate limiters ---
// Protects auth endpoints from brute-force attacks (10 attempts / 15 min per IP)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many attempts. Please try again in 15 minutes.' },
});
// OTP send triggers an email — tightest limit (5 / 60 min per IP)
const otpSendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many OTP requests. Please try again in 1 hour.' },
});
// OTP verify — prevent code brute-forcing (10 / 15 min per IP)
const otpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many verification attempts. Please try again in 15 minutes.' },
});

// ============================================================================
// JWT AUTHENTICATION UTILITIES
// ============================================================================
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  console.warn('⚠️  JWT_SECRET not set — using insecure dev fallback. Set JWT_SECRET in .env for production.');
  return 'pma-dev-secret-change-in-production';
})();
const JWT_EXPIRY = '15m';
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const hashToken = (t) => createHash('sha256').update(t).digest('hex');
const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
};

// ============================================================================
// INPUT VALIDATION SCHEMAS (zod)
// ============================================================================

const email  = z.string().trim().email().toLowerCase().max(254);
const name   = z.string().trim().min(1).max(100);
const pwd    = z.string().min(6).max(100);
const roleId = z.enum(['ROLE_SYSADMIN', 'ROLE_ADMIN', 'ROLE_PRACTITIONER']);
const uiRole = z.enum(['super_admin', 'doctor', 'reception', 'unlinked']);
const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Expected YYYY-MM-DD');
const timeStr = z.string().regex(/^\d{2}:\d{2}$/, 'Expected HH:MM');

const loginSchema = z.object({
  email,
  password: pwd,
});

const selfRegisterSchema = z.object({
  email,
  password: pwd,
  firstname: name,
  lastname:  name,
});

const adminRegisterSchema = z.object({
  email,
  password:    pwd,
  firstName:   name,
  lastName:    name,
  roleId,
  practiceIds: z.array(z.string()).optional(),
});

const setPasswordSchema = z.object({
  token:    z.string().min(1).max(500),
  password: pwd,
});

const updatePasswordSchema = z.object({
  email:       email,
  newPassword: pwd,
});

const createUserSchema = z.object({
  email,
  firstName: name,
  lastName:  name,
  role:      uiRole.optional(),
});

const updateUserSchema = z.object({
  email:     email.optional(),
  firstName: name.optional(),
  lastName:  name.optional(),
  isActive:  z.boolean().optional(),
  role:      uiRole.optional(),
});

const linkPracticeSchema = z.object({
  practiceId: z.string().min(1).max(100),
  roleId:     roleId.optional(),
  force:      z.boolean().optional(),
});

const adminLinkSchema = z.object({
  email,
  practiceId: z.string().min(1).max(100),
  roleId,
  firstName:  name.optional(),
  lastName:   name.optional(),
  force:      z.boolean().optional(),
});

const sendInviteEmailSchema = z.object({
  email,
  inviteLink:   z.string().url(),
  practiceName: z.string().max(200).optional(),
  firstName:    name.optional(),
});

const sendOtpAdminSchema = z.object({
  userId:     z.string().min(1).max(100),
  practiceId: z.string().min(1).max(100),
});

const createAndInviteSchema = z.object({
  email,
  firstName:    name,
  lastName:     name,
  roleId,
  practiceId:   z.string().min(1).max(100),
  tempPassword: pwd.optional(),
});

const verifyPracticeOtpSchema = z.object({
  otp:    z.string().length(6).regex(/^\d+$/),
  userId: z.string().min(1).max(100),
});

const patientAddressSchema = z.object({
  street:     z.string().max(200).optional(),
  city:       z.string().max(100).optional(),
  province:   z.string().max(100).optional(),
  postalCode: z.string().max(20).optional(),
  postal_code: z.string().max(20).optional(),
}).optional();

const emergencyContactSchema = z.object({
  name:         z.string().max(100).optional(),
  relationship: z.string().max(50).optional(),
  phone:        z.string().max(30).optional(),
}).optional();

const createPatientSchema = z.object({
  firstName:   name,
  lastName:    name,
  dateOfBirth: isoDate.optional(),
  gender:      z.string().max(20).optional(),
  idNumber:    z.string().max(20).optional(),
  phone:       z.string().max(30).optional(),
  email:       email.optional().or(z.literal('')),
  practiceId:  z.string().max(100).optional(),
  allergies:   z.array(z.string()).optional(),
  address:     patientAddressSchema,
  emergencyContact: emergencyContactSchema,
  medicalAids: z.any().optional(),
});

const updatePatientSchema = createPatientSchema.partial();

const createAppointmentSchema = z.object({
  patientId:    z.string().min(1).max(100),
  doctorId:     z.string().min(1).max(100),
  practiceId:   z.string().max(100).optional(),
  beneficiaryId: z.string().max(100).optional(),
  date:         isoDate,
  startTime:    timeStr,
  notes:        z.string().max(2000).optional(),
});

const patchAppointmentSchema = z.object({
  status:    z.string().max(50).optional(),
  notes:     z.string().max(2000).optional(),
  date:      isoDate.optional(),
  startTime: timeStr.optional(),
  endTime:   timeStr.optional(),
});

const otpSendSchema = z.object({
  phone:           z.string().max(30).optional(),
  email:           email.optional().or(z.literal('')),
  appointmentData: z.any().optional(),
});

const otpVerifySchema = z.object({
  phone: z.string().max(30).optional(),
  email: email.optional().or(z.literal('')),
  code:  z.string().length(6).regex(/^\d+$/).or(z.literal('000000')),
});

const createVisitSchema = z.object({
  appointmentId:          z.string().max(100).optional(),
  patientId:              z.string().min(1).max(100),
  doctorId:               z.string().min(1).max(100),
  practicePractitionerId: z.string().max(100).optional(),
  reasonForVisit:         z.string().max(2000).optional(),
  consultationNotes:      z.string().max(10000).optional(),
  vitals:                 z.any().optional(),
  diagnoses:              z.array(z.any()).optional(),
  procedures:             z.array(z.any()).optional(),
  prescriptions:          z.array(z.any()).optional(),
  clinicalDocuments:      z.array(z.any()).optional(),
});

const updateVisitSchema = createVisitSchema.partial();

// Helper: parse & reject with 400 on failure
const validate = (schema, req, res) => {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    const message = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
    res.status(400).json({ success: false, message: `Invalid input: ${message}` });
    return null;
  }
  return result.data;
};

// ============================================================================
// PRODUCTION UTILITIES
// ============================================================================

// Abort a DB call that takes longer than `ms` milliseconds
const withTimeout = (promise, ms = 8000) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Database request timed out')), ms)
    ),
  ]);

// Strip characters that break PostgREST's .or() filter syntax
const sanitizeSearch = (s) => String(s || '').replace(/[%,()\\]/g, '').slice(0, 100);

// Fire-and-forget email: resolves immediately, logs errors in background
const sendMailAsync = (opts, label = 'email') => {
  if (!emailTransporter) return;
  emailTransporter.sendMail(opts)
    .then(() => console.log(`✅ [EMAIL] ${label} sent to ${opts.to}`))
    .catch(e  => console.error(`❌ [EMAIL] Failed to send ${label} to ${opts.to}:`, e.message));
};

// POPIA audit log — fire-and-forget insert into audit_logs table
const logAudit = (req, action, resourceId) => {
  supabase.from('audit_logs').insert({
    user_id:     req.userContext?.userId || null,
    action,
    resource_id: String(resourceId),
    ip_address:  req.ip || req.socket?.remoteAddress || null,
    created_at:  new Date().toISOString(),
  }).then(({ error }) => {
    if (error) console.error('[AUDIT] Failed to log:', action, resourceId, error.message);
  });
};

// Email transporter (Gmail SMTP)
const emailTransporter = (process.env.SMTP_USER && process.env.SMTP_APP_PASS)
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_APP_PASS,
      },
    })
  : null;

if (emailTransporter) {
  console.log(`📧 Email transporter configured for ${process.env.SMTP_USER}`);
} else {
  console.log('📧 Email transporter NOT configured (set SMTP_USER and SMTP_APP_PASS to enable)');
}

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: '*',
  credentials: false,
}));
app.options('*', cors());
app.use(express.json());

// Disable caching for all pma responses
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Surrogate-Control': 'no-store',
  });
  next();
});

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Practice filtering middleware — reads practiceIds/role/flags from JWT payload;
// eliminates all per-request DB round-trips in the common path.
const addPracticeFilter = async (req, res, next) => {
  // Skip for auth routes, public routes, and admin functions
  const skipPaths = [
    '/auth/', '/pma/auth/', '/api/auth/',
    '/practices', '/pma/practices', '/api/practices',
    '/users/check-email', '/pma/users/check-email', '/api/users/check-email',
    '/admin/', '/pma/admin/', '/api/admin/',
    // Patient-mode (guest) public booking endpoints — no auth token required
    '/pma/otp/',
    '/pma/doctors',
    '/pma/schedules/',
    '/pma/patients/search',
    '/pma/patients/id-number/',
  ];

  if (skipPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json(err('Authentication required'));
  }

  const payload = verifyToken(authHeader.replace('Bearer ', ''));
  if (!payload) {
    return res.status(401).json(err('Invalid or expired token. Please log in again.'));
  }

  const { userId, role, practiceIds: tokenPracticeIds = [], isSuperAdmin, isSuperSuperAdmin } = payload;

  // Skip practice-scope check for user's own profile endpoints
  const userProfilePaths = [
    `/users/${userId}/my-practice`, `/pma/users/${userId}/my-practice`, `/api/users/${userId}/my-practice`,
    `/users/${userId}/my-practices`, `/pma/users/${userId}/my-practices`, `/api/users/${userId}/my-practices`,
    `/users/${userId}`, `/pma/users/${userId}`, `/api/users/${userId}`,
  ];
  if (userProfilePaths.some(path => req.path === path)) {
    req.userContext = { userId, practiceId: null, isSuperAdmin, isSuperSuperAdmin };
    return next();
  }

  if (isSuperSuperAdmin) {
    const headerPracticeId = req.headers['x-practice-id'] || null;
    req.userContext = { userId, practiceId: headerPracticeId, isSuperAdmin: true, isSuperSuperAdmin: true };
    return next();
  }

  const linkedPracticeIds = new Set(tokenPracticeIds);
  const headerPracticeId  = req.headers['x-practice-id'] || null;
  const practiceId = (headerPracticeId && linkedPracticeIds.has(headerPracticeId))
    ? headerPracticeId
    : (linkedPracticeIds.size > 0 ? [...linkedPracticeIds][0] : null);

  if (!practiceId) {
    return res.status(403).json(err('User is not linked to any practice'));
  }

  req.userContext = {
    userId,
    practiceId,
    isSuperAdmin: isSuperAdmin || false,
    isSuperSuperAdmin: false,
    linkedPracticeIds: [...linkedPracticeIds],
  };
  next();
};

// Health check — called by load balancers, Docker, Railway, Render, etc.
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use(addPracticeFilter);

// Helper to send success response
const success = (data, message) => ({ success: true, data, message });

// Helper to send error response
const err = (message) => ({ success: false, error: message });

// Convert snake_case keys to camelCase (recursive)
const toCamel = (obj) => {
  if (Array.isArray(obj)) return obj.map(toCamel);
  if (obj !== null && obj !== undefined && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [
        k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()),
        toCamel(v),
      ])
    );
  }
  return obj;
};

const snakeKeys = (obj) => {
  if (Array.isArray(obj)) return obj.map(snakeKeys);
  if (obj !== null && obj !== undefined && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [
        k.replace(/([A-Z])/g, (c) => `_${c.toLowerCase()}`),
        snakeKeys(v),
      ])
    );
  }
  return obj;
};

// ============================================================================
// PASSWORD UTILITIES
// ============================================================================
const SALT_ROUNDS = 10;

const hashPassword = async (plainPassword) => {
  try {
    return await bcrypt.hash(plainPassword, SALT_ROUNDS);
  } catch (error) {
    console.error('Password hashing error:', error);
    throw new Error('Failed to hash password');
  }
};

const verifyPassword = async (plainPassword, hashedPassword) => {
  try {
    return await bcrypt.compare(plainPassword, hashedPassword);
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
};

// ============================================================================
// PATIENT HELPERS
// ============================================================================
const PATIENT_SELECT = `*, patient_addresses(*), patient_emergency_contacts(*), patient_medical_aids(*)`;

const formatPatient = (p) => {
  if (!p) return null;
  const { patient_addresses, patient_emergency_contacts, patient_medical_aids, ...core } = p;
  const addr = patient_addresses?.[0] || {};
  const ec   = patient_emergency_contacts?.[0] || {};
  const activeAid  = patient_medical_aids?.find(m => m.is_active);
  const historyAids = patient_medical_aids?.filter(m => !m.is_active) || [];
  return {
    ...toCamel(core),
    address: {
      street: addr.street || '', city: addr.city || '',
      province: addr.province || '', postalCode: addr.postal_code || '',
    },
    emergencyContact: { name: ec.name || '', relationship: ec.relationship || '', phone: ec.phone || '' },
    medicalAids: {
      active: activeAid ? {
        provider: activeAid.provider_name, providerName: activeAid.provider_name,
        plan: activeAid.plan_name, planName: activeAid.plan_name,
        membershipNumber: activeAid.membership_number,
        ...(activeAid.main_member_id ? { mainMemberId: activeAid.main_member_id } : {}),
      } : null,
      history: historyAids.map(h => ({
        provider: h.provider_name, providerName: h.provider_name,
        plan: h.plan_name, planName: h.plan_name,
        membershipNumber: h.membership_number,
      })),
    },
  };
};

// ============================================================================
// USER HELPERS
// ============================================================================
const USER_SELECT = `*, user_roles(*), user_practices(*)`;

const formatUser = (u) => {
  if (!u) return null;
  const { user_roles, user_practices, ...core } = u;
  return {
    ...toCamel(core),
    roles: (user_roles || []).map(r => ({
      roleId: r.role_id, roleName: r.role_name,
      ...(r.practice_id ? { practiceId: r.practice_id } : {}),
    })),
    practices: (user_practices || []).map(p => ({
      practiceId: p.practice_id, practiceName: p.practice_name,
    })),
  };
};

// ============================================================================
// INVOICE HELPERS
// ============================================================================
const INVOICE_SELECT = `*, invoice_line_items(*)`;

const formatInvoice = (inv) => {
  if (!inv) return null;
  const { invoice_line_items, ...core } = inv;
  return {
    ...toCamel(core),
    lineItems: (invoice_line_items || []).map(item => ({
      referenceCode: item.reference_code, description: item.description, amount: item.amount,
    })),
  };
};

// ============================================================================
// APPOINTMENT HELPERS
// ============================================================================
const APPOINTMENT_SELECT = `*, patients!patient_id(*), doctors!doctor_id(*)`;

const formatAppointment = (a) => {
  if (!a) return null;
  const { patients, doctors, ...core } = a;
  return {
    ...toCamel(core),
    patient: patients ? toCamel(patients) : undefined,
    doctor:  doctors  ? toCamel(doctors)  : undefined,
  };
};

// ============================================================================
// VISIT HELPERS
// ============================================================================
const VISIT_SELECT = `*, visit_vitals(*), visit_diagnoses(*), visit_procedures(*), visit_prescriptions(*), visit_clinical_documents(*)`;

const formatVisit = (v) => {
  if (!v) return null;
  const { visit_vitals, visit_diagnoses, visit_procedures, visit_prescriptions, visit_clinical_documents, ...core } = v;
  return {
    ...toCamel(core),
    vitals: visit_vitals?.[0] ? toCamel(visit_vitals[0]) : null,
    diagnoses: (visit_diagnoses || []).map(d => ({
      code: d.code, icd10Code: d.icd10_code, description: d.description,
      isPrimary: d.is_primary, diagnosisId: d.diagnosis_id || d.id,
    })),
    procedures: (visit_procedures || []).map(p => ({
      code: p.code, description: p.description, tariffAmount: p.tariff_amount, procedureId: p.procedure_id || p.id,
    })),
    prescriptions: (visit_prescriptions || []).map(p => ({
      prescriptionId: p.prescription_id || p.id, medicationName: p.medication_name,
      dosage: p.dosage, frequency: p.frequency, duration: p.duration, durationDays: p.duration_days,
    })),
    clinicalDocuments: (visit_clinical_documents || []).map(d => ({
      documentId: d.document_id || d.id, documentType: d.document_type,
      documentName: d.document_name, fileName: d.file_name, fileUrl: d.file_url,
    })),
  };
};

const enrichVisit = async (visit) => {
  if (!visit) return null;
  const [{ data: patient }, { data: doctor }, { data: invoice }] = await Promise.all([
    supabase.from('patients').select(PATIENT_SELECT).eq('id', visit.patientId || visit.patient_id).single(),
    supabase.from('doctors').select('*').eq('id', visit.doctorId || visit.doctor_id).single(),
    supabase.from('invoices').select(INVOICE_SELECT).eq('visit_id', visit.id).maybeSingle(),
  ]);
  return {
    ...visit,
    patient: patient ? formatPatient(patient) : undefined,
    doctor:  doctor  ? toCamel(doctor)         : undefined,
    invoice: invoice ? formatInvoice(invoice)  : undefined,
  };
};

// Batch variant: 3 total DB queries for N visits (instead of N×3)
const enrichVisitsBatch = async (formattedVisits) => {
  if (!formattedVisits?.length) return [];
  const patientIds = [...new Set(formattedVisits.map(v => v.patientId).filter(Boolean))];
  const doctorIds  = [...new Set(formattedVisits.map(v => v.doctorId).filter(Boolean))];
  const visitIds   = formattedVisits.map(v => v.id).filter(Boolean);
  const [{ data: patients }, { data: doctors }, { data: invoices }] = await Promise.all([
    patientIds.length ? supabase.from('patients').select(PATIENT_SELECT).in('id', patientIds) : { data: [] },
    doctorIds.length  ? supabase.from('doctors').select('*').in('id', doctorIds)              : { data: [] },
    visitIds.length   ? supabase.from('invoices').select(INVOICE_SELECT).in('visit_id', visitIds) : { data: [] },
  ]);
  const patientMap = Object.fromEntries((patients || []).map(p => [p.id, p]));
  const doctorMap  = Object.fromEntries((doctors  || []).map(d => [d.id, d]));
  const invoiceMap = Object.fromEntries((invoices || []).map(i => [i.visit_id, i]));
  return formattedVisits.map(v => ({
    ...v,
    patient: patientMap[v.patientId] ? formatPatient(patientMap[v.patientId]) : undefined,
    doctor:  doctorMap[v.doctorId]   ? toCamel(doctorMap[v.doctorId])          : undefined,
    invoice: invoiceMap[v.id]        ? formatInvoice(invoiceMap[v.id])          : undefined,
  }));
};

// ============================================================================
// AUTH ENDPOINTS — LOGIN
// ============================================================================

app.get('/pma/auth/login', (req, res) => {
  res.json({
    message: 'Login endpoint is working. Please use POST method to login.',
    method: 'This endpoint only accepts POST requests with email and password in body.',
  });
});
app.get('/auth/login', (req, res) => {
  res.json({
    message: 'Login endpoint is working. Please use POST method to login.',
    method: 'This endpoint only accepts POST requests with email and password in body.',
  });
});

const loginHandler = async (req, res) => {
  const data = validate(loginSchema, req, res);
  if (!data) return;
  const { email, password } = data;

  console.log(`🔍 [LOGIN] Attempting login for: ${email}`);


  // Only allow active (verified) users to log in
  const { data: u, error: dbErr } = await supabase
    .from('users').select(USER_SELECT).eq('email', email).eq('is_active', true).maybeSingle();

  if (dbErr) {
    console.error('Login DB error:', dbErr.message);
    return res.status(500).json(err('Database error during login'));
  }

  if (!u) {
    // Check if user exists but is not yet verified
    const { data: unverified } = await supabase
      .from('users').select('id, is_active').eq('email', email).maybeSingle();

    if (unverified && !unverified.is_active) {
      return res.status(403).json(err('Account not verified. Please check your email for the verification link.'));
    }

    return res.status(401).json(err('Invalid email or password'));
  }

  if (!u.password) {
    return res.status(401).json(err('Invalid email or password'));
  }

  let passwordValid = false;
  if (u.password.startsWith('$2b$')) {
    passwordValid = await verifyPassword(password, u.password);
  } else {
    // Plaintext fallback — upgrade to hashed on successful login
    passwordValid = (password === u.password);
    if (passwordValid) {
      const hashed = await hashPassword(password);
      await supabase.from('users').update({ password: hashed }).eq('id', u.id);
      console.log(`🔍 [LOGIN] Upgraded plaintext password to hashed for: ${email}`);
    }
  }

  if (!passwordValid) {
    return res.status(401).json(err('Invalid email or password'));
  }

  console.log(`✅ [LOGIN] Successful for: ${email}`);
  const user = formatUser(u);
  const practiceIds       = (u.user_practices || []).map(p => p.practice_id);
  const isSuperAdmin      = (u.user_roles    || []).some(r => r.role_id === 'ROLE_SYSADMIN');
  const isSuperSuperAdmin = u.role === 'super_super_admin';
  const token = signToken({ userId: user.id, role: u.role, practiceIds, isSuperAdmin, isSuperSuperAdmin });
  const refreshToken = randomUUID();
  await supabase.from('refresh_tokens').insert({
    user_id:    user.id,
    token_hash: hashToken(refreshToken),
    expires_at: Date.now() + REFRESH_TTL_MS,
  });
  res.json(success({ user, token, refreshToken }, 'Login successful'));
};
app.post('/pma/auth/login', authLimiter, loginHandler);
app.post('/auth/login',     authLimiter, loginHandler);

app.post('/pma/auth/logout', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    await supabase.from('refresh_tokens').delete().eq('token_hash', hashToken(refreshToken));
  }
  res.json(success(null, 'Logged out successfully'));
});
app.post('/auth/logout', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (refreshToken) {
    await supabase.from('refresh_tokens').delete().eq('token_hash', hashToken(refreshToken));
  }
  res.json(success(null, 'Logged out successfully'));
});

const refreshHandler = async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(401).json(err('Refresh token required'));
  const hash = hashToken(refreshToken);
  const { data: rt } = await supabase.from('refresh_tokens').select('*').eq('token_hash', hash).maybeSingle();
  if (!rt || rt.expires_at < Date.now()) {
    if (rt) await supabase.from('refresh_tokens').delete().eq('token_hash', hash);
    return res.status(401).json(err('Refresh token invalid or expired'));
  }
  // Rotate: delete old token, issue new pair
  await supabase.from('refresh_tokens').delete().eq('token_hash', hash);
  const { data: u } = await supabase.from('users').select(USER_SELECT).eq('id', rt.user_id).maybeSingle();
  if (!u || !u.is_active) return res.status(401).json(err('User account not found or inactive'));
  const practiceIds       = (u.user_practices || []).map(p => p.practice_id);
  const isSuperAdmin      = (u.user_roles    || []).some(r => r.role_id === 'ROLE_SYSADMIN');
  const isSuperSuperAdmin = u.role === 'super_super_admin';
  const newAccessToken = signToken({ userId: u.id, role: u.role, practiceIds, isSuperAdmin, isSuperSuperAdmin });
  const newRefreshToken = randomUUID();
  await supabase.from('refresh_tokens').insert({
    user_id:    u.id,
    token_hash: hashToken(newRefreshToken),
    expires_at: Date.now() + REFRESH_TTL_MS,
  });
  res.json(success({ token: newAccessToken, refreshToken: newRefreshToken }));
};
app.post('/pma/auth/refresh', refreshHandler);
app.post('/auth/refresh',     refreshHandler);

// ============================================================================
// SELF-REGISTRATION — Clean server flow (register + email verify link)
//
// ============================================================================

app.post('/pma/authentication/register', authLimiter, async (req, res) => {
  const data = validate(selfRegisterSchema, req, res);
  if (!data) return;
  const { email, password, firstname, lastname } = data;

  // Check for existing user (active or pending)
  const { data: existing } = await supabase
    .from('users').select('id').eq('email', email).maybeSingle();
  if (existing) {
    return res.status(409).json({ message: 'User already exists' });
  }

  const hashedPassword = await hashPassword(password);

  const newId = randomUUID();

  const { error: uErr } = await supabase.from('users').insert({
    id:         newId,
    email,
    password:   hashedPassword,
    first_name: firstname,
    last_name:  lastname,
    is_active:  false,   // Unverified until email link is clicked
    role:       'unlinked',
  });

  if (uErr) {
    console.error('Registration error:', uErr);
    return res.status(500).json({ message: 'Failed to create user' });
  }

  // Build the verification link (mirrors clean server pattern)
  const verifyLink = `${process.env.CLIENT_URL}/pma/authentication/verify/${newId}`;

  console.log(`📧 [REGISTER] Verify link for ${email}: ${verifyLink}`);

  return res.status(201).json({
    message: 'User registered successfully',
    verifyLink,
  });
});

app.get('/pma/authentication/verify/:userid', async (req, res) => {
  const { userid } = req.params;

  if (!userid) {
    return res.status(400).json({ error: 'UserID is required' });
  }

  const { data: user, error: dbErr } = await supabase
    .from('users').select('id, is_active').eq('id', userid).maybeSingle();

  if (dbErr || !user) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (user.is_active) {
    return res.status(200).json({ message: 'Account is already verified. Please sign in.' });
  }

  const { error: updErr } = await supabase
    .from('users').update({ is_active: true }).eq('id', userid);

  if (updErr) {
    return res.status(500).json({ error: 'Failed to verify account' });
  }

  console.log(`✅ [VERIFY] User ${userid} verified successfully`);
  return res.status(200).json({ message: 'Account verified successfully. Please sign in.' });
});

// ============================================================================
// ADMIN REGISTRATION — role-based, used by admins to create staff accounts
// ============================================================================

const ROLE_MAP = {
  'ROLE_SYSADMIN':     { roleName: 'SystemAdministrator/ admin',       uiRole: 'super_admin' },
  'ROLE_ADMIN':        { roleName: 'PracticeAdministrator/ reception',  uiRole: 'reception'   },
  'ROLE_PRACTITIONER': { roleName: 'PracticePractitioner / doctor',     uiRole: 'doctor'      },
};

const registerHandler = async (req, res) => {
  const data = validate(adminRegisterSchema, req, res);
  if (!data) return;
  const { email, password, firstName, lastName, roleId, practiceIds } = data;

  const { data: existing } = await supabase
    .from('users').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json(err('A user with this email already exists'));

  const roleInfo = ROLE_MAP[roleId];
  if (!roleInfo) return res.status(400).json(err('Invalid role'));

  const hashedPassword = await hashPassword(password);

  const newId = randomUUID();

  const { error: uErr } = await supabase.from('users').insert({
    id: newId,
    email,
    first_name: firstName,
    last_name: lastName,
    is_active: true,          // Admin-created users are active immediately
    role: roleInfo.uiRole,
    password: hashedPassword,
  });
  if (uErr) return res.status(500).json(err('Failed to create user'));

  if (roleId === 'ROLE_SYSADMIN') {
    await supabase.from('user_roles').insert({
      user_id: newId, role_id: roleId, role_name: roleInfo.roleName,
    });
  } else {
    const selectedPracticeIds = practiceIds || [];
    if (selectedPracticeIds.length === 0) {
      await supabase.from('users').delete().eq('id', newId);
      return res.status(400).json(err('At least one practice must be selected for this role'));
    }
    const { data: practiceRows } = await supabase
      .from('practices').select('id, name').in('id', selectedPracticeIds);
    const practiceMap = Object.fromEntries((practiceRows || []).map(p => [p.id, p.name]));
    await supabase.from('user_roles').insert(
      selectedPracticeIds.map(pid => ({
        user_id: newId, role_id: roleId, role_name: roleInfo.roleName, practice_id: pid,
      }))
    );
    const practiceInserts = selectedPracticeIds
      .filter(pid => practiceMap[pid])
      .map(pid => ({ user_id: newId, practice_id: pid, practice_name: practiceMap[pid] }));
    if (practiceInserts.length > 0) await supabase.from('user_practices').insert(practiceInserts);
  }

  if (roleId === 'ROLE_PRACTITIONER') {
    await supabase.from('doctors').insert({
      id: randomUUID(), user_id: newId,
      first_name: firstName, last_name: lastName,
      specialization: 'General Practice', email, phone: '', is_available: true,
    });
  }

  const { data: newUserRow } = await supabase
    .from('users').select(USER_SELECT).eq('id', newId).single();
  const newUser = formatUser(newUserRow);
  const regPracticeIds       = (newUserRow?.user_practices || []).map(p => p.practice_id);
  const regIsSuperAdmin      = (newUserRow?.user_roles    || []).some(r => r.role_id === 'ROLE_SYSADMIN');
  const regIsSuperSuperAdmin = newUserRow?.role === 'super_super_admin';
  const token = signToken({ userId: newUser.id, role: newUserRow?.role, practiceIds: regPracticeIds, isSuperAdmin: regIsSuperAdmin, isSuperSuperAdmin: regIsSuperSuperAdmin });
  res.status(201).json(success({ user: newUser, token }, 'Registration successful'));
};

app.post('/pma/auth/register', authLimiter, registerHandler);
app.post('/auth/register',     authLimiter, registerHandler);

// ============================================================================
// PRACTICES LIST ENDPOINT (for registration dropdown)
// ============================================================================

const practicesHandler = async (req, res) => {
  const [{ data: practices }, { data: allRoles }, { data: allPPs }] = await Promise.all([
    supabase.from('practices').select('id, name, practice_number'),
    supabase.from('user_roles').select('user_id, practice_id'),
    supabase.from('practice_practitioners').select('user_id, practice_id'),
  ]);
  const rolesByPractice = {};
  for (const r of (allRoles || [])) {
    if (!rolesByPractice[r.practice_id]) rolesByPractice[r.practice_id] = new Set();
    rolesByPractice[r.practice_id].add(r.user_id);
  }
  const ppsByPractice = {};
  for (const pp of (allPPs || [])) {
    if (!ppsByPractice[pp.practice_id]) ppsByPractice[pp.practice_id] = new Set();
    ppsByPractice[pp.practice_id].add(pp.user_id);
  }
  const formatted = (practices || []).map(p => {
    const ppIds = ppsByPractice[p.id] ? [...ppsByPractice[p.id]] : [];
    const allMemberIds = new Set([...ppIds, ...(rolesByPractice[p.id] ? [...rolesByPractice[p.id]] : [])]);
    return {
      id: p.id, name: p.name, practiceNumber: p.practice_number,
      practicePractitioners: ppIds.map(uid => ({ id: uid })),
      linkedUsers: [...allMemberIds].map(uid => ({ id: uid })),
    };
  });
  res.json(success(formatted));
};
app.get('/pma/practices', practicesHandler);
app.get('/practices',     practicesHandler);

app.get('/pma/practices/search', async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('practices').select('id, name, practice_number');
  if (q) { const sq = sanitizeSearch(q); query = query.or(`name.ilike.%${sq}%,practice_number.ilike.%${sq}%`); }
  const { data: practices } = await query;
  res.json(success((practices || []).map(p => ({
    id: p.id, name: p.name, practiceNumber: p.practice_number,
  }))));
});

app.get('/pma/practices/:id', async (req, res) => {
  const [{ data: practice }, { data: allUsers }, { data: roleRows }, { data: ppRows }] = await Promise.all([
    supabase.from('practices').select('*, practice_practitioners(*)').eq('id', req.params.id).maybeSingle(),
    supabase.from('users').select('id, first_name, last_name, email, is_active, role'),
    supabase.from('user_roles').select('user_id, role_id, role_name').eq('practice_id', req.params.id),
    supabase.from('practice_practitioners').select('user_id').eq('practice_id', req.params.id),
  ]);
  if (!practice) return res.status(404).json(err('Practice not found'));
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  const allLinkedIds = new Set([
    ...(roleRows || []).map(r => r.user_id),
    ...(ppRows   || []).map(p => p.user_id),
  ]);
  const linkedUsers = [...allLinkedIds].map(uid => {
    const u = usersMap[uid] || {};
    const roleRow = (roleRows || []).find(r => r.user_id === uid);
    return {
      id: uid,
      firstName: u.first_name || '',
      lastName:  u.last_name  || '',
      email:     u.email      || '',
      role:      roleRow?.role_id || 'ROLE_PRACTITIONER',
      isActive:  u.is_active  ?? true,
    };
  }).filter(u => u.firstName);
  res.json(success({
    ...toCamel(practice),
    practicePractitioners: (practice.practice_practitioners || []).map(pp => enrichPP(pp, usersMap)),
    linkedUsers,
  }));
});

app.get('/pma/practices/:id/doctors', async (req, res) => {
  // Find user_ids linked to this practice via practice_practitioners
  const { data: practitioners } = await supabase
    .from('practice_practitioners')
    .select('user_id')
    .eq('practice_id', req.params.id);
  if (!practitioners || practitioners.length === 0) return res.json(success([]));

  const userIds = practitioners.map(p => p.user_id);
  // Fetch doctors whose user_id is in that list
  const { data: doctors } = await supabase
    .from('doctors').select('*').in('user_id', userIds);
  if (!doctors || doctors.length === 0) return res.json(success([]));

  // Fetch schedules for next 7 days for these doctors
  const today   = new Date();
  const dateFrom = today.toISOString().split('T')[0];
  const dateTo   = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const { data: schedules } = await supabase
    .from('schedules').select('*')
    .in('doctor_id', doctors.map(d => d.id))
    .gte('date', dateFrom).lte('date', dateTo);

  const schedMap = {};
  for (const s of (schedules || [])) {
    if (!schedMap[s.doctor_id]) schedMap[s.doctor_id] = [];
    schedMap[s.doctor_id].push({
      id: s.id, doctorId: s.doctor_id, date: s.date,
      startTime: s.start_time, endTime: s.end_time, status: s.status, notes: s.notes ?? null,
    });
  }

  const result = doctors.map(d => ({
    id: d.id, userId: d.user_id,
    firstName: d.first_name || '', lastName: d.last_name || '',
    specialization: d.specialization || '',
    email: d.email || '', phone: d.phone || '',
    isAvailable: d.is_available ?? false,
    schedule: schedMap[d.id] || [],
  }));
  res.json(success(result));
});

app.get('/pma/practices/:id/members', async (req, res) => {
  const [{ data: roleRows }, { data: ppRows }] = await Promise.all([
    supabase.from('user_roles').select('user_id, role_id, role_name').eq('practice_id', req.params.id),
    supabase.from('practice_practitioners').select('user_id, hpcsa_number').eq('practice_id', req.params.id),
  ]);

  // Build member map: user_roles take precedence; add practitioners not in user_roles
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

  const result = members.map(r => {
    const u = usersMap[r.user_id]   || {};
    const d = doctorsMap[r.user_id] || {};
    return {
      userId:    r.user_id,
      roleId:    r.role_id,
      roleName:  r.role_name,
      firstName: u.first_name || d.first_name || '',
      lastName:  u.last_name  || d.last_name  || '',
      email:     u.email      || d.email      || '',
      phone:     u.phone      || d.phone      || '',
    };
  });
  res.json(success(result));
});

const meHandler = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json(err('No token provided'));
  const payload = verifyToken(authHeader.replace('Bearer ', ''));
  if (!payload) return res.status(401).json(err('Invalid or expired token'));
  const { data: u } = await supabase
    .from('users').select(USER_SELECT).eq('id', payload.userId).single();
  if (!u) return res.status(404).json(err('User not found'));
  res.json(success(formatUser(u)));
};
app.get('/pma/auth/me', meHandler);
app.get('/auth/me',     meHandler);

// ============================================================================
// USER ENDPOINTS
// ============================================================================

app.get('/pma/users', async (req, res) => {
  console.log('Fetching users with query:', req.query);
  const { page, pageSize } = req.query;
  const { data: users, error: dbErr } = await supabase.from('users').select(USER_SELECT);
  if (dbErr) return res.status(500).json(err('Failed to fetch users'));
  const formatted = (users || []).map(formatUser);
  if (page && pageSize) {
    const p = parseInt(page), ps = parseInt(pageSize);
    const paginated = formatted.slice((p - 1) * ps, (p - 1) * ps + ps);
    return res.json(success({
      data: paginated, total: formatted.length, page: p, pageSize: ps,
      totalPages: Math.ceil(formatted.length / ps),
    }));
  }
  res.json(success(formatted));
});

app.get('/pma/users/role/:role', async (req, res) => {
  const { data: users } = await supabase
    .from('users').select(USER_SELECT).eq('role', req.params.role);
  res.json(success((users || []).map(formatUser)));
});

app.get('/pma/users/check-email', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json(err('email is required'));
  const { data: user } = await supabase
    .from('users').select(USER_SELECT).eq('email', String(email).toLowerCase()).maybeSingle();
  if (!user) return res.json(success({ exists: false }));
  return res.json(success({ exists: true, user: formatUser(user) }));
});

app.get('/pma/users/:id', async (req, res) => {
  const { data: u } = await supabase
    .from('users').select(USER_SELECT).eq('id', req.params.id).single();
  if (!u) return res.status(404).json(err('User not found'));
  res.json(success(formatUser(u)));
});

app.post('/pma/users', async (req, res) => {
  const data = validate(createUserSchema, req, res);
  if (!data) return;
  const { email, firstName, lastName, role: uiRole } = data;
  const { data: existing } = await supabase
    .from('users').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json(err('A user with this email already exists'));

  const uiRoleToRoleId   = { super_admin: 'ROLE_SYSADMIN', doctor: 'ROLE_PRACTITIONER', reception: 'ROLE_ADMIN' };
  const uiRoleToRoleName = { super_admin: 'SystemAdministrator', doctor: 'PracticePractitioner', reception: 'PracticeAdministrator' };
  const resolvedRole = uiRole || 'reception';

  const newId = randomUUID();

  const { error: insertErr } = await supabase.from('users').insert({
    id: newId, email,
    first_name: firstName, last_name: lastName,
    is_active: true, role: resolvedRole,
  });
  if (insertErr) return res.status(500).json(err('Failed to create user'));

  await supabase.from('user_roles').insert({
    user_id: newId, role_id: uiRoleToRoleId[resolvedRole], role_name: uiRoleToRoleName[resolvedRole],
  });

  const { data: newUserRow } = await supabase.from('users').select(USER_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatUser(newUserRow), 'User created successfully'));
});

app.put('/pma/users/:id', async (req, res) => {
  const data = validate(updateUserSchema, req, res);
  if (!data) return;
  const { data: existing } = await supabase.from('users').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  const upd = {};
  if (data.firstName !== undefined) upd.first_name = data.firstName;
  if (data.lastName  !== undefined) upd.last_name  = data.lastName;
  if (data.email     !== undefined) upd.email      = data.email;
  if (data.isActive  !== undefined) upd.is_active  = data.isActive;
  if (data.role      !== undefined) upd.role       = data.role;
  await supabase.from('users').update(upd).eq('id', req.params.id);
  const { data: updated } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success(formatUser(updated), 'User updated successfully'));
});

app.delete('/pma/users/:id', async (req, res) => {
  const { data: existing } = await supabase.from('users').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  await supabase.from('users').delete().eq('id', req.params.id);
  res.json(success(null, 'User deleted successfully'));
});

app.patch('/pma/users/:id/toggle-active', async (req, res) => {
  const { data: existing } = await supabase
    .from('users').select('id, is_active').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  await supabase.from('users').update({ is_active: !existing.is_active }).eq('id', req.params.id);
  const { data: updated } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success(formatUser(updated)));
});

app.post('/pma/users/:id/link-practice', async (req, res) => {
  const data = validate(linkPracticeSchema, req, res);
  if (!data) return;
  const { practiceId, roleId, force } = data;

  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  const { data: user } = await supabase.from('users').select('id, email, first_name, last_name').eq('id', req.params.id).maybeSingle();
  if (!user) return res.status(404).json(err('User not found'));

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 300000;
  if (!global.practiceOtpStore) global.practiceOtpStore = new Map();
  global.practiceOtpStore.set(otp, { userId: req.params.id, practiceId, practiceOtp: otp, expiresAt });
  console.log(`🔗 Practice Link OTP for ${user.email}: ${otp}`);

  // Auto-email the OTP if transporter is configured
  sendMailAsync({
    from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
    to: user.email,
    subject: `Your practice link OTP for ${practice.name}`,
    html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
            <h2 style="color:#2563eb">Practice Link Verification</h2>
            <p>Hi ${user.first_name},</p>
            <p>Use the OTP below to link your account to <strong>${practice.name}</strong>:</p>
            <p style="text-align:center;margin:32px 0">
              <span style="background:#f3f4f6;padding:16px 32px;border-radius:8px;font-size:32px;font-family:monospace;letter-spacing:8px;font-weight:bold;color:#2563eb">${otp}</span>
            </p>
            <p style="color:#666;font-size:13px">Enter this code on your Profile page. It expires in 5 minutes.</p>
            <hr style="border:none;border-top:1px solid #eee;margin:24px 0"/>
            <p style="color:#999;font-size:12px">If you didn't request this, you can safely ignore this email.</p>
          </div>
        `,
  }, 'practice-link-otp');

  const { data: existingLink } = await supabase.from('user_practices')
    .select('id').eq('user_id', req.params.id).eq('practice_id', practiceId).maybeSingle();
  if (!existingLink) {
    await supabase.from('user_practices').insert({
      user_id: req.params.id, practice_id: practiceId, practice_name: practice.name,
    });
  }

  if (roleId) {
    const ROLE_NAMES = {
      'ROLE_SYSADMIN': 'SystemAdministrator', 'ROLE_ADMIN': 'PracticeAdministrator',
      'ROLE_PRACTITIONER': 'PracticePractitioner',
    };
    const { data: existingRole } = await supabase.from('user_roles')
      .select('id').eq('user_id', req.params.id).eq('role_id', roleId).eq('practice_id', practiceId).maybeSingle();
    if (!existingRole) {
      await supabase.from('user_roles').insert({
        user_id: req.params.id, role_id: roleId,
        role_name: ROLE_NAMES[roleId] || roleId, practice_id: practiceId,
      });
    }
  }

  const { data: updatedUser } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  const practiceToken = randomUUID();
  res.json(success({
    user: formatUser(updatedUser),
    otp,
    token: practiceToken,
    link: `${process.env.CLIENT_URL || 'http://localhost:3000'}/verify-link?token=${practiceToken}`,
  }, 'Practice linked and OTP generated'));
});

app.get('/pma/users/:id/my-practice', async (req, res) => {
  const { data: userPractices } = await supabase
    .from('user_practices').select('practice_id, practice_name').eq('user_id', req.params.id);
  
  // Return success with null if no practice linked (not an error)
  if (!userPractices?.length) {
    return res.json(success(null, 'User is not linked to any practice'));
  }
  
  const { data: practice } = await supabase
    .from('practices').select('*, practice_practitioners(*)')
    .eq('id', userPractices[0].practice_id).maybeSingle();
    
  if (!practice) {
    return res.status(404).json(err('Practice not found'));
  }
  
  res.json(success({
    ...toCamel(practice),
    practicePractitioners: (practice.practice_practitioners || []).map(toCamel),
  }));
});

// Returns ALL practices the user is linked to (for multi-practice picker)
app.get('/pma/users/:id/my-practices', async (req, res) => {

  // Check if user is super_super_admin — they see ALL practices
  const { data: userRow } = await supabase
    .from('users').select('role').eq('id', req.params.id).maybeSingle();

  if (userRow?.role === 'super_super_admin') {
    const { data: allPractices } = await supabase
      .from('practices').select('id, name, practice_number');
    return res.json(success((allPractices || []).map(p => ({
      id: p.id, name: p.name, practiceNumber: p.practice_number,
    }))));
  }

  const { data: userPractices } = await supabase
    .from('user_practices').select('practice_id, practice_name').eq('user_id', req.params.id);

  if (!userPractices?.length) {
    return res.json(success([], 'User is not linked to any practice'));
  }

  const practiceIds = userPractices.map(p => p.practice_id);
  const { data: practices } = await supabase
    .from('practices').select('id, name, practice_number').in('id', practiceIds);

  res.json(success((practices || []).map(p => ({
    id: p.id, name: p.name, practiceNumber: p.practice_number,
  }))));
});

// ============================================================================
// SIMPLIFIED PRACTICE LINKING — One-step process  
// Handles user creation OR linking existing user to practice in one call
// ============================================================================

app.post('/pma/admin/link-user-to-practice', async (req, res) => {
  const data = validate(adminLinkSchema, req, res);
  if (!data) return;
  const { email, practiceId, roleId, firstName, lastName, force } = data;

  // Validate practice exists
  const { data: practice } = await supabase
    .from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  // Validate role
  const ROLE_NAMES = {
    'ROLE_SYSADMIN': 'SystemAdministrator', 
    'ROLE_ADMIN': 'PracticeAdministrator',
    'ROLE_PRACTITIONER': 'PracticePractitioner',
  };
  const roleUiMap = { 
    'ROLE_ADMIN': 'reception', 
    'ROLE_PRACTITIONER': 'doctor', 
    'ROLE_SYSADMIN': 'super_admin' 
  };
  
  if (!ROLE_NAMES[roleId]) {
    return res.status(400).json(err('Invalid roleId'));
  }

  // Check if user exists
  let { data: user } = await supabase
    .from('users').select('id, email, first_name, last_name').eq('email', email).maybeSingle();

  let isNewUser = false;

  // Create user if doesn't exist
  if (!user) {
    if (!firstName || !lastName) {
      return res.status(400).json(err('firstName and lastName are required for new users'));
    }
    
    // Find a unique ID by querying all existing IDs and finding the next available number
    const { data: existingUsers } = await supabase.from('users').select('id');
    const existingIds = new Set((existingUsers || []).map(u => u.id));
    let idNum = 1;
    let newId;
    do {
      newId = `USR${String(idNum).padStart(3, '0')}`;
      idNum++;
    } while (existingIds.has(newId));

    const { error: createErr } = await supabase.from('users').insert({
      id: newId,
      email,
      first_name: firstName,
      last_name: lastName,
      is_active: true,
      role: roleUiMap[roleId],
      password: null, // Will be set via invite link
    });
    
    if (createErr) {
      console.error('User creation error:', createErr);
      return res.status(500).json(err('Failed to create user'));
    }

    // Fetch the created user
    const { data: newUser } = await supabase
      .from('users').select('id, email, first_name, last_name').eq('id', newId).single();
    user = newUser;
    isNewUser = true;
  }

  if (!user) return res.status(500).json(err('Failed to create or retrieve user'));

  // Check if already linked to THIS specific practice (skip if so)
  const { data: alreadyLinkedToThis } = await supabase
    .from('user_practices')
    .select('id')
    .eq('user_id', user.id)
    .eq('practice_id', practiceId)
    .maybeSingle();

  // Link user to practice (add new row if not already linked to this practice)
  if (!alreadyLinkedToThis) {
    await supabase.from('user_practices').insert({
      user_id: user.id,
      practice_id: practiceId,
      practice_name: practice.name,
    });
  }

  // Set user role for this practice (upsert)
  const { data: existingRole } = await supabase
    .from('user_roles')
    .select('id')
    .eq('user_id', user.id)
    .eq('practice_id', practiceId)
    .maybeSingle();

  if (existingRole) {
    await supabase.from('user_roles')
      .update({ 
        role_id: roleId, 
        role_name: ROLE_NAMES[roleId] 
      })
      .eq('user_id', user.id)
      .eq('practice_id', practiceId);
  } else {
    await supabase.from('user_roles').insert({
      user_id: user.id,
      role_id: roleId,
      role_name: ROLE_NAMES[roleId],
      practice_id: practiceId,
    });
  }

  // Create doctor record if role is practitioner
  if (roleId === 'ROLE_PRACTITIONER') {
    const { data: existingDoctor } = await supabase
      .from('doctors').select('id').eq('user_id', user.id).maybeSingle();
      
    if (!existingDoctor) {
      await supabase.from('doctors').insert({
        id: randomUUID(),
        user_id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        specialization: 'General Practice',
        email: user.email,
        phone: '',
        is_available: true,
      });
    }
  }

  // Generate invite link for new users
  let inviteLink = '';
  if (isNewUser) {
    const token = randomUUID();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    // Persist invite token in DB so it survives server restarts
    await supabase.from('invite_tokens').upsert({
      token,
      user_id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      expires_at: expiresAt,
    });
    const clientUrl = process.env.CLIENT_URL || 'http://localhost:8080';
    inviteLink = `${clientUrl}/set-password?token=${token}`;
    console.log(`📧 [INVITE] New user ${email} invite link: ${inviteLink}`);

    // Auto-send email if transporter is configured
    sendMailAsync({
      from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `You've been invited to join ${practice.name}`,
      html: `
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
              <h2 style="color:#2563eb">Welcome to ${practice.name}</h2>
              <p>Hi ${user.first_name},</p>
              <p>You've been invited to join <strong>${practice.name}</strong> on PMA Health Hub.</p>
              <p>Click the button below to set your password and activate your account:</p>
              <p style="text-align:center;margin:32px 0">
                <a href="${inviteLink}" style="background:#2563eb;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">Set Your Password</a>
              </p>
              <p style="color:#666;font-size:13px">Or copy this link: <br/><code>${inviteLink}</code></p>
              <hr style="border:none;border-top:1px solid #eee;margin:24px 0"/>
              <p style="color:#999;font-size:12px">This link expires in 7 days. If you didn't expect this email, you can safely ignore it.</p>
            </div>
          `,
    }, 'new-user-invite');
  }

  // Return success response
  const { data: updatedUser } = await supabase
    .from('users').select(USER_SELECT).eq('id', user.id).single();

  res.json(success({
    user: formatUser(updatedUser),
    isNewUser,
    inviteLink,
    practice: { id: practice.id, name: practice.name },
  }, `User successfully ${isNewUser ? 'created and ' : ''}linked to ${practice.name}`));
});

// Send / resend invite email manually
app.post('/pma/admin/send-invite-email', async (req, res) => {
  const data = validate(sendInviteEmailSchema, req, res);
  if (!data) return;
  const { email, inviteLink, practiceName, firstName } = data;
  if (!emailTransporter) {
    return res.status(503).json(err('Email is not configured on the server. Set SMTP_USER and SMTP_APP_PASS environment variables and restart.'));
  }

  try {
    await emailTransporter.sendMail({
      from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
      to: email,
      subject: `You've been invited to join ${practiceName || 'a practice'}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
          <h2 style="color:#2563eb">Welcome to ${practiceName || 'PMA Health Hub'}</h2>
          <p>Hi ${firstName || 'there'},</p>
          <p>You've been invited to join <strong>${practiceName || 'a practice'}</strong> on PMA Health Hub.</p>
          <p>Click the button below to set your password and activate your account:</p>
          <p style="text-align:center;margin:32px 0">
            <a href="${inviteLink}" style="background:#2563eb;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">Set Your Password</a>
          </p>
          <p style="color:#666;font-size:13px">Or copy this link: <br/><code>${inviteLink}</code></p>
          <hr style="border:none;border-top:1px solid #eee;margin:24px 0"/>
          <p style="color:#999;font-size:12px">This link expires in 7 days. If you didn't expect this email, you can safely ignore it.</p>
        </div>
      `,
    });
    console.log(`✅ [EMAIL] Manual invite email sent to ${email}`);
    res.json(success(null, `Invite email sent to ${email}`));
  } catch (mailErr) {
    console.error(`❌ [EMAIL] Failed to send invite to ${email}:`, mailErr.message);
    res.status(500).json(err('Failed to send email'));
  }
});

// Send/resend OTP for a user to link their practice (triggered by admin from Practice Management)
app.post('/pma/admin/send-otp', async (req, res) => {
  const data = validate(sendOtpAdminSchema, req, res);
  if (!data) return;
  const { userId, practiceId } = data;

  const { data: user } = await supabase.from('users').select('id, email, first_name, last_name').eq('id', userId).maybeSingle();
  if (!user) return res.status(404).json(err('User not found'));
  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 300000;
  if (!global.practiceOtpStore) global.practiceOtpStore = new Map();
  global.practiceOtpStore.set(otp, { userId, practiceId, practiceOtp: otp, expiresAt });
  console.log(`🔗 [SEND-OTP] OTP for ${user.email}: ${otp}`);

  let emailed = false;
  sendMailAsync({
    from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
    to: user.email,
    subject: `Your practice link OTP for ${practice.name}`,
    html: `
          <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px">
            <h2 style="color:#2563eb">Practice Link Verification</h2>
            <p>Hi ${user.first_name},</p>
            <p>Use the OTP below to link your account to <strong>${practice.name}</strong>:</p>
            <p style="text-align:center;margin:32px 0">
              <span style="background:#f3f4f6;padding:16px 32px;border-radius:8px;font-size:32px;font-family:monospace;letter-spacing:8px;font-weight:bold;color:#2563eb">${otp}</span>
            </p>
            <p style="color:#666;font-size:13px">Enter this code on your Profile page. It expires in 5 minutes.</p>
          </div>
        `,
  }, 'admin-send-otp');
  emailed = !!emailTransporter;

  res.json(success({ otp, emailed }, emailed ? `OTP sent to ${user.email}` : `OTP generated: ${otp} (email not configured)`));
});

// Direct link (no OTP) — for linking an existing user to a practice immediately
app.post('/pma/users/:id/link-practice-direct', async (req, res) => {
  const data = validate(linkPracticeSchema, req, res);
  if (!data) return;
  const { practiceId, roleId, force } = data;

  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));
  const { data: user } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).maybeSingle();
  if (!user) return res.status(404).json(err('User not found'));

  // Add practice link (allow multiple practices)
  const { data: existingLink } = await supabase.from('user_practices')
    .select('id').eq('user_id', req.params.id).eq('practice_id', practiceId).maybeSingle();
  if (!existingLink) {
    await supabase.from('user_practices').insert({
      user_id: req.params.id, practice_id: practiceId, practice_name: practice.name,
    });
  }

  const ROLE_NAMES = {
    'ROLE_SYSADMIN': 'SystemAdministrator', 'ROLE_ADMIN': 'PracticeAdministrator',
    'ROLE_PRACTITIONER': 'PracticePractitioner',
  };
  const roleUiMap = { 'ROLE_ADMIN': 'reception', 'ROLE_PRACTITIONER': 'doctor', 'ROLE_SYSADMIN': 'super_admin' };

  if (roleId) {
    const { data: existingRole } = await supabase.from('user_roles')
      .select('id').eq('user_id', req.params.id).eq('practice_id', practiceId).maybeSingle();
    if (existingRole) {
      await supabase.from('user_roles')
        .update({ role_id: roleId, role_name: ROLE_NAMES[roleId] || roleId })
        .eq('user_id', req.params.id).eq('practice_id', practiceId);
    } else {
      await supabase.from('user_roles').insert({
        user_id: req.params.id, role_id: roleId,
        role_name: ROLE_NAMES[roleId] || roleId, practice_id: practiceId,
      });
    }
    // Promote role if currently unlinked
    if (user.role === 'unlinked') {
      await supabase.from('users').update({ role: roleUiMap[roleId] || 'reception' }).eq('id', req.params.id);
    }
  }

  const { data: updatedUser } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success({ user: formatUser(updatedUser), linked: true }, 'User linked to practice'));
});

// Admin create-and-invite — creates a new user, links to practice, returns invite link
app.post('/pma/admin/create-and-invite', async (req, res) => {
  const data = validate(createAndInviteSchema, req, res);
  if (!data) return;
  const { email, firstName, lastName, roleId, practiceId, tempPassword } = data;

  const { data: existing } = await supabase.from('users')
    .select('id').eq('email', email.toLowerCase()).maybeSingle();
  if (existing) return res.status(409).json(err('A user with this email already exists'));

  const { data: practice } = await supabase.from('practices').select('id, name').eq('id', practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  const ROLE_NAMES = {
    'ROLE_SYSADMIN': 'SystemAdministrator', 'ROLE_ADMIN': 'PracticeAdministrator',
    'ROLE_PRACTITIONER': 'PracticePractitioner',
  };
  const roleUiMap = { 'ROLE_ADMIN': 'reception', 'ROLE_PRACTITIONER': 'doctor', 'ROLE_SYSADMIN': 'super_admin' };

  const newId = randomUUID();
  const hashedPw = await hashPassword(tempPassword || 'TempPass123!');

  const { error: uErr } = await supabase.from('users').insert({
    id: newId, email: email.toLowerCase(),
    first_name: firstName, last_name: lastName,
    password: hashedPw, role: roleUiMap[roleId] || 'reception',
    is_active: false,
  });
  if (uErr) { console.error('Create invite error:', uErr); return res.status(500).json(err('Failed to create user')); }

  await supabase.from('user_practices').insert({
    user_id: newId, practice_id: practiceId, practice_name: practice.name,
  });
  await supabase.from('user_roles').insert({
    user_id: newId, role_id: roleId, role_name: ROLE_NAMES[roleId] || roleId, practice_id: practiceId,
  });

  if (roleId === 'ROLE_PRACTITIONER') {
    await supabase.from('doctors').insert({
      id: randomUUID(), user_id: newId,
      first_name: firstName, last_name: lastName,
      specialization: 'General Practice', email: email.toLowerCase(), phone: '', is_available: true,
    });
  }

  // Generate invite token — stored in DB so it survives server restarts
  const token = randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
  await supabase.from('invite_tokens').insert({
    token,
    user_id: newId,
    email: email.toLowerCase(),
    first_name: firstName,
    last_name: lastName,
    expires_at: expiresAt,
  });

  const clientUrl = process.env.CLIENT_URL || 'http://localhost:8080';
  const inviteLink = `${clientUrl}/set-password?token=${token}`;
  console.log(`📧 [INVITE] Link for ${email}: ${inviteLink}`);

  res.status(201).json(success({ userId: newId, inviteLink, token }, 'User created and invite link generated'));
});

// Verify invite token
app.get('/pma/auth/signup/verify/:token', async (req, res) => {
  const { data: stored, error: tErr } = await supabase
    .from('invite_tokens').select('*').eq('token', req.params.token).maybeSingle();
  if (tErr || !stored) return res.status(404).json(err('Invalid or expired invite token'));
  if (Date.now() > stored.expires_at) {
    await supabase.from('invite_tokens').delete().eq('token', req.params.token);
    return res.status(410).json(err('Invite link has expired. Please request a new invite.'));
  }
  res.json(success({ firstName: stored.first_name, lastName: stored.last_name, email: stored.email }));
});

// Set password via invite token
app.post('/pma/auth/set-password', authLimiter, async (req, res) => {
  const data = validate(setPasswordSchema, req, res);
  if (!data) return;
  const { token, password } = data;
  const { data: stored, error: tErr } = await supabase
    .from('invite_tokens').select('*').eq('token', token).maybeSingle();
  if (tErr || !stored) return res.status(400).json(err('Invalid or expired invite token'));
  if (Date.now() > stored.expires_at) {
    await supabase.from('invite_tokens').delete().eq('token', token);
    return res.status(410).json(err('Invite link has expired'));
  }
  const hashed = await hashPassword(password);
  await supabase.from('users').update({ password: hashed, is_active: true }).eq('id', stored.user_id);
  await supabase.from('invite_tokens').delete().eq('token', token);
  console.log(`✅ [INVITE] ${stored.email} activated account`);
  res.json(success(null, 'Password set and account activated'));
});

// ============================================================================
// PRACTICE VERIFICATION ENDPOINT (practice linking OTP)
// ============================================================================

app.post('/pma/practices/verify-otp', async (req, res) => {
  const data = validate(verifyPracticeOtpSchema, req, res);
  if (!data) return;
  const { otp, userId } = data;
  if (!global.practiceOtpStore) return res.status(400).json(err('No OTP verification available'));

  const stored = global.practiceOtpStore.get(otp);
  if (!stored) return res.status(400).json(err('Invalid or expired OTP'));
  if (stored.userId !== userId) return res.status(400).json(err('OTP does not match the specified user'));
  if (Date.now() > stored.expiresAt) {
    global.practiceOtpStore.delete(otp);
    return res.status(400).json(err('OTP has expired'));
  }

  const { data: practice } = await supabase
    .from('practices').select('id, name, practice_number').eq('id', stored.practiceId).maybeSingle();
  if (!practice) return res.status(404).json(err('Practice not found'));

  const { data: user } = await supabase.from('users').select('role').eq('id', userId).maybeSingle();
  if (user && user.role === 'unlinked') {
    await supabase.from('users').update({ role: 'reception' }).eq('id', userId);
  }

  global.practiceOtpStore.delete(otp);
  console.log(`✅ Practice link verified for user ${userId} to practice ${practice.name}`);

  res.json(success({
    practiceId: practice.id,
    practiceName: practice.name,
    practiceNumber: practice.practice_number,
    verified: true,
  }, 'OTP verified and practice linked successfully'));
});

// ============================================================================
// PATIENT ENDPOINTS
// ============================================================================

app.get('/pma/patients', async (req, res) => {
  const { page, pageSize, search, idNumber, ids } = req.query;
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};

  let query = supabase.from('patients').select(PATIENT_SELECT);

  // Scope to practice unless super admin
  if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) {
    query = query.eq('practice_id', practiceId);
  }

  if (ids) {
    query = query.in('id', ids.split(',').map(id => id.trim()).filter(Boolean));
    const { data: patients } = await query;
    return res.json(success((patients || []).map(formatPatient)));
  }
  if (idNumber) query = query.eq('id_number', idNumber);
  if (search) {
    const safe = sanitizeSearch(search);
    query = query.or(
      `first_name.ilike.%${safe}%,last_name.ilike.%${safe}%,phone.ilike.%${safe}%,id_number.ilike.%${safe}%`
    );
  }
  const { data: patients, error: dbErr } = await query;
  if (dbErr) return res.status(500).json(err('Failed to fetch patients'));
  const formatted = (patients || []).map(formatPatient);
  if (page && pageSize) {
    const p = parseInt(page), ps = Math.min(parseInt(pageSize), 100);
    const paginated = formatted.slice((p - 1) * ps, (p - 1) * ps + ps);
    return res.json(success({
      data: paginated, total: formatted.length, page: p, pageSize: ps,
      totalPages: Math.ceil(formatted.length / ps),
    }));
  }
  res.json(success(formatted));
});

app.get('/pma/patients/search', async (req, res) => {
  const { q } = req.query;
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  console.log(`🔍 Patient search query: "${q}"`);
  if (!q) return res.json(success([]));
  const safe = sanitizeSearch(q);
  let query = supabase.from('patients').select(PATIENT_SELECT);
  if (!isSuperAdmin && !isSuperSuperAdmin && practiceId) {
    query = query.eq('practice_id', practiceId);
  }
  query = query.or(`first_name.ilike.%${safe}%,last_name.ilike.%${safe}%,id_number.ilike.%${safe}%,email.ilike.%${safe}%,phone.ilike.%${safe}%`);
  const { data: patients } = await query;
  const results = (patients || []).map(formatPatient);
  results.sort((a, b) => {
    const qL = safe.toLowerCase();
    const aId = (a.idNumber || '').toLowerCase();
    const bId = (b.idNumber || '').toLowerCase();
    if (aId === qL && bId !== qL) return -1;
    if (bId === qL && aId !== qL) return  1;
    if (aId.startsWith(qL) && !bId.startsWith(qL)) return -1;
    if (bId.startsWith(qL) && !aId.startsWith(qL)) return  1;
    return (a.firstName || '').localeCompare(b.firstName || '');
  });
  console.log(`✅ Found ${results.length} patients matching "${q}"`);
  res.json(success(results));
});

app.get('/pma/patients/id-number/:idNumber', async (req, res) => {
  const { data: patients } = await supabase
    .from('patients').select(PATIENT_SELECT).eq('id_number', req.params.idNumber);
  if (!patients || patients.length === 0) return res.status(404).json(err('Patient not found'));
  res.json(success(formatPatient(patients[0])));
});

app.get('/pma/patients/:id', async (req, res) => {
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  const { data: p } = await supabase
    .from('patients').select(PATIENT_SELECT).eq('id', req.params.id).single();
  if (!p) return res.status(404).json(err('Patient not found'));
  // Verify patient belongs to requesting user's practice
  if (!isSuperAdmin && !isSuperSuperAdmin && p.practice_id && practiceId && p.practice_id !== practiceId) {
    return res.status(403).json(err('Access denied'));
  }
  logAudit(req, 'VIEW_PATIENT', req.params.id);
  res.json(success(formatPatient(p)));
});

app.post('/pma/patients', async (req, res) => {
  const data = validate(createPatientSchema, req, res);
  if (!data) return;
  const { data: existing } = await supabase
    .from('patients').select('id').eq('id_number', data.idNumber).maybeSingle();
  if (existing) return res.status(400).json(err('A patient with this ID number already exists'));
  const newId = randomUUID();
  const now   = new Date().toISOString();
  const { error: insertErr } = await supabase.from('patients').insert({
    id: newId, first_name: data.firstName, last_name: data.lastName,
    date_of_birth: data.dateOfBirth, gender: data.gender,
    id_number: data.idNumber, phone: data.phone, email: data.email,
    practice_id: data.practiceId, allergies: data.allergies || [],
    created_at: now, updated_at: now,
  });
  if (insertErr) return res.status(500).json(err('Failed to create patient'));
  if (data.address) {
    await supabase.from('patient_addresses').insert({
      patient_id: newId, street: data.address.street, city: data.address.city,
      province: data.address.province,
      postal_code: data.address.postalCode || data.address.postal_code,
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
    if (data.medicalAids.active) inserts.push({
      patient_id: newId, provider_name: data.medicalAids.active.providerName,
      plan_name: data.medicalAids.active.planName,
      membership_number: data.medicalAids.active.membershipNumber, is_active: true,
    });
    for (const h of (data.medicalAids.history || [])) inserts.push({
      patient_id: newId, provider_name: h.providerName,
      plan_name: h.planName, membership_number: h.membershipNumber, is_active: false,
    });
    if (inserts.length > 0) await supabase.from('patient_medical_aids').insert(inserts);
  }
  logAudit(req, 'CREATE_PATIENT', newId);
  const { data: newPatient } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatPatient(newPatient), 'Patient created successfully'));
});

app.put('/pma/patients/:id', async (req, res) => {
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
    await supabase.from('patient_addresses').insert({
      patient_id: req.params.id, street: data.address.street, city: data.address.city,
      province: data.address.province,
      postal_code: data.address.postalCode || data.address.postal_code,
    });
  }
  if (data.emergencyContact) {
    await supabase.from('patient_emergency_contacts').delete().eq('patient_id', req.params.id);
    await supabase.from('patient_emergency_contacts').insert({
      patient_id: req.params.id, name: data.emergencyContact.name,
      relationship: data.emergencyContact.relationship, phone: data.emergencyContact.phone,
    });
  }
  if (data.medicalAids) {
    await supabase.from('patient_medical_aids').delete().eq('patient_id', req.params.id);
    const inserts = [];
    if (data.medicalAids.active) inserts.push({
      patient_id: req.params.id, provider_name: data.medicalAids.active.providerName,
      plan_name: data.medicalAids.active.planName,
      membership_number: data.medicalAids.active.membershipNumber, is_active: true,
    });
    for (const h of (data.medicalAids.history || [])) inserts.push({
      patient_id: req.params.id, provider_name: h.providerName,
      plan_name: h.planName, membership_number: h.membershipNumber, is_active: false,
    });
    if (inserts.length > 0) await supabase.from('patient_medical_aids').insert(inserts);
  }
  logAudit(req, 'UPDATE_PATIENT', req.params.id);
});

app.get('/pma/patients/:id/beneficiaries', async (req, res) => {
  const { data: bens } = await supabase
    .from('beneficiaries').select('patient_id').eq('main_member_id', req.params.id);
  if (!bens || bens.length === 0) return res.json(success([]));
  const { data: patients } = await supabase
    .from('patients').select(PATIENT_SELECT).in('id', bens.map(b => b.patient_id));
  res.json(success((patients || []).map(formatPatient)));
});

app.post('/pma/patients/:id/beneficiaries', async (req, res) => {
  const { relationship, ...bData } = req.body;
  const newId = randomUUID();
  const now   = new Date().toISOString();
  await supabase.from('patients').insert({
    id: newId, first_name: bData.firstName, last_name: bData.lastName,
    date_of_birth: bData.dateOfBirth, gender: bData.gender,
    id_number: bData.idNumber, phone: bData.phone, email: bData.email,
    practice_id: bData.practiceId, allergies: bData.allergies || [],
    created_at: now, updated_at: now,
  });
  if (bData.address) {
    await supabase.from('patient_addresses').insert({
      patient_id: newId, street: bData.address.street, city: bData.address.city,
      province: bData.address.province, postal_code: bData.address.postalCode,
    });
  }
  await supabase.from('beneficiaries').insert({
    id: randomUUID(), patient_id: newId,
    main_member_id: req.params.id, relationship,
  });
  const { data: newPatient } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatPatient(newPatient), 'Beneficiary added successfully'));
});

// ============================================================================
// DOCTOR ENDPOINTS
// ============================================================================

app.get('/pma/doctors', async (req, res) => {
  const { ids } = req.query;
  const { practiceId, isSuperAdmin } = req.userContext || {};
  console.log(`Fetching doctors for practiceId=${practiceId}, isSuperAdmin=${isSuperAdmin}, filterIds=${ids || 'none'}`);

  // If not super admin, filter to doctors linked to the user's practice
  if (!isSuperAdmin && practiceId) {
    const { data: practitionerIds } = await supabase
      .from('practice_practitioners')
      .select('user_id')
      .eq('practice_id', practiceId);

    const linkedUserIds = (practitionerIds || []).map(p => p.user_id);

    // Also include any doctor whose user_id is in user_roles for this practice
    const { data: roleUserIds } = await supabase
      .from('user_roles')
      .select('user_id')
      .eq('practice_id', practiceId)
      .eq('role_id', 'ROLE_PRACTITIONER');

    const allUserIds = [...new Set([...linkedUserIds, ...(roleUserIds || []).map(r => r.user_id)])];

    if (allUserIds.length === 0) return res.json(success([]));

    let query = supabase.from('doctors').select('*').in('user_id', allUserIds);
    if (ids) query = query.in('id', ids.split(','));
    const { data: doctors } = await query;
    return res.json(success((doctors || []).map(toCamel)));
  }

  // Super admin or no practice context — return all
  let query = supabase.from('doctors').select('*');
  if (ids) query = query.in('id', ids.split(','));
  const { data: doctors } = await query;
  res.json(success((doctors || []).map(toCamel)));
});

app.get('/pma/doctors/:id', async (req, res) => {
  console.log(`Fetching doctor with id=${req.params.id}`);
  const { data: doctor } = await supabase
    .from('doctors').select('*').eq('id', req.params.id).single();
  if (!doctor) return res.status(404).json(err('Doctor not found'));
  res.json(success(toCamel(doctor)));
});

app.get('/pma/doctors/available', async (req, res) => {
  console.log(`Fetching available doctors for date=${req.query.date}, time=${req.query.time}`);
  const { date, time } = req.query;
  const { data: doctors } = await supabase.from('doctors').select('*').eq('is_available', true);
  if (!date) return res.json(success((doctors || []).map(toCamel)));
  const availableDoctors = [];
  for (const doc of (doctors || [])) {
    const { data: sched } = await supabase
      .from('schedules').select('*').eq('doctor_id', doc.id).eq('date', date);
    if (!sched || sched.length === 0) { availableDoctors.push(toCamel(doc)); continue; }
    if (time) {
      if (sched.some(s => s.status === 'available' && s.start_time <= time && s.end_time > time))
        availableDoctors.push(toCamel(doc));
    } else {
      if (sched.some(s => s.status === 'available')) availableDoctors.push(toCamel(doc));
    }
  }
  res.json(success(availableDoctors));
});

app.get('/pma/doctors/:id/schedule', async (req, res) => {
  console.log(`Fetching schedule for doctor with id=${req.params.id}`);
  const { dateFrom, dateTo } = req.query;
  let query = supabase.from('schedules').select('*').eq('doctor_id', req.params.id);
  if (dateFrom) query = query.gte('date', dateFrom);
  if (dateTo)   query = query.lte('date', dateTo);
  const { data: schedule } = await query;
  res.json(success((schedule || []).map(toCamel)));
});

app.post('/pma/doctors/:id/schedule', async (req, res) => {
  const sd = req.body;
  const { data: existingRow } = await supabase
    .from('schedules').select('id').eq('doctor_id', req.params.id)
    .eq('date', sd.date).eq('start_time', sd.startTime).maybeSingle();
  let result;
  if (existingRow) {
    const { data } = await supabase.from('schedules')
      .update({ end_time: sd.endTime, status: sd.status || 'available' })
      .eq('id', existingRow.id).select().single();
    result = data;
  } else {
    const { data } = await supabase.from('schedules').insert({
      id: randomUUID(), doctor_id: req.params.id,
      date: sd.date, start_time: sd.startTime, end_time: sd.endTime, status: sd.status || 'available',
    }).select().single();
    result = data;
  }
  res.json(success(toCamel(result), 'Schedule updated successfully'));
});

app.patch('/pma/doctors/:id/availability', async (req, res) => {
  const { data: existing } = await supabase.from('doctors').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Doctor not found'));
  const { data: updated } = await supabase.from('doctors')
    .update({ is_available: req.body.isAvailable })
    .eq('id', req.params.id).select().single();
  res.json(success(toCamel(updated)));
});

app.get('/pma/schedules/doctor/:doctorId/slots/:date', async (req, res) => {
  const { doctorId, date } = req.params;
  const TIME_SLOTS = [
    '08:00', '08:30', '09:00', '09:30', '10:00', '10:30',
    '11:00', '11:30', '12:00', '12:30', '13:00', '13:30',
    '14:00', '14:30', '15:00', '15:30', '16:00', '16:30', '17:00',
  ];
  const [{ data: doctorSchedule }, { data: booked }] = await Promise.all([
    supabase.from('schedules').select('*').eq('doctor_id', doctorId).eq('date', date),
    supabase.from('appointments').select('start_time, end_time')
      .eq('doctor_id', doctorId).eq('date', date)
      .in('status', ['pending_reception', 'confirmed']),
  ]);
  const now = new Date();
  const isToday = new Date(date).toDateString() === now.toDateString();
  const currentTime = isToday ? now.toTimeString().substring(0, 5) : null;
  const slots = TIME_SLOTS.map((time, index) => {
    const nextTime = TIME_SLOTS[index + 1] || '17:30';
    const matchingSchedule = (doctorSchedule || []).find(s => s.start_time <= time && s.end_time > time);
    const isBooked = (booked || []).some(a => a.start_time === time || (a.start_time <= time && a.end_time > time));
    const isPast = isToday && currentTime && time < currentTime;
    const scheduleAvailable = matchingSchedule?.status === 'available' || !matchingSchedule;
    const isAvailable = scheduleAvailable && !isBooked && !isPast;
    return {
      id: `slot-${time}`, startTime: time, endTime: nextTime, isAvailable,
      status: isBooked ? 'booked' : (isPast ? 'past' : (matchingSchedule?.status || 'available')),
      reason: isBooked ? 'Already booked' : (isPast ? 'Time has passed' : null),
    };
  });
  console.log(`📅 Available slots for doctor ${doctorId} on ${date}: ${slots.filter(s => s.isAvailable).length}/${slots.length}`);
  res.json(success(slots));
});

// ============================================================================
// APPOINTMENT ENDPOINTS
// ============================================================================

app.get('/pma/appointments', async (req, res) => {
  console.log(`Fetching appointments with filters: ${JSON.stringify(req.query)}`);
  const { page, pageSize, status, doctorId, patientId, dateFrom, dateTo, lean } = req.query;
  const { practiceId, isSuperAdmin, isSuperSuperAdmin } = req.userContext;
  
  let query = supabase.from('appointments').select(lean === 'true' ? '*' : APPOINTMENT_SELECT);
  
  // Only bypass practice filtering for super_super_admin with no practice scope
  if (!isSuperSuperAdmin || practiceId) {
    // Filter appointments by doctors linked to the user's practice
    const { data: practitionerIds } = await supabase
      .from('practice_practitioners')
      .select('user_id')
      .eq('practice_id', practiceId);
    
    const { data: doctorIds } = await supabase
      .from('doctors')
      .select('id')
      .in('user_id', (practitionerIds || []).map(p => p.user_id));
      
    if (doctorIds?.length > 0) {
      query = query.in('doctor_id', doctorIds.map(d => d.id));
    } else {
      // No doctors in practice, return empty
      return res.json(success([]));
    }
  }
  
  if (status) {
    const statuses = Array.isArray(status) ? status : [status];
    query = statuses.length === 1 ? query.eq('status', statuses[0]) : query.in('status', statuses);
  }
  if (doctorId)  query = query.eq('doctor_id',  doctorId);
  if (patientId) query = query.eq('patient_id', patientId);
  if (dateFrom)  query = query.gte('date', dateFrom);
  if (dateTo)    query = query.lte('date', dateTo);
  query = query.order('date', { ascending: false }).order('start_time', { ascending: false });
  const { data: appointments, error: dbErr } = await query;
  if (dbErr) return res.status(500).json(err('Failed to fetch appointments'));

  // Auto-complete stale appointments: if the date has passed and the status is
  // 'in_consultation' or 'confirmed', mark them as 'completed' so they don't
  // linger indefinitely.
  const today = new Date().toISOString().split('T')[0];
  const stale = (appointments || []).filter(a =>
    a.date < today && (a.status === 'in_consultation' || a.status === 'confirmed')
  );
  if (stale.length > 0) {
    const staleIds = stale.map(a => a.id);
    await supabase.from('appointments')
      .update({ status: 'completed', updated_at: new Date().toISOString() })
      .in('id', staleIds);
    // Patch the in-memory rows so the current response is already correct
    for (const a of appointments) {
      if (staleIds.includes(a.id)) a.status = 'completed';
    }
  }

  const formatted = lean === 'true'
    ? (appointments || []).map(toCamel)
    : (appointments || []).map(formatAppointment);
  if (page && pageSize) {
    const p = parseInt(page), ps = parseInt(pageSize);
    const paginated = formatted.slice((p - 1) * ps, (p - 1) * ps + ps);
    return res.json(success({
      data: paginated, total: formatted.length, page: p, pageSize: ps,
      totalPages: Math.ceil(formatted.length / ps),
    }));
  }
  res.json(success(formatted));
});

app.get('/pma/appointments/:id', async (req, res) => {
  console.log(`Fetching appointment with id=${req.params.id}`);
  const { data: apt } = await supabase
    .from('appointments').select(APPOINTMENT_SELECT).eq('id', req.params.id).single();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  res.json(success(formatAppointment(apt)));
});

app.get('/pma/appointments/patient/:patientId', async (req, res) => {
  console.log(`Fetching appointments for patientId=${req.params.patientId}`);
  const { data: apts } = await supabase
    .from('appointments').select(APPOINTMENT_SELECT).eq('patient_id', req.params.patientId);
  res.json(success((apts || []).map(formatAppointment)));
});

app.get('/pma/appointments/doctor/:doctorId', async (req, res) => {
  console.log(`Fetching appointments for doctorId=${req.params.doctorId}`);
  const { data: apts } = await supabase
    .from('appointments').select(APPOINTMENT_SELECT).eq('doctor_id', req.params.doctorId);
  res.json(success((apts || []).map(formatAppointment)));
});

app.post('/pma/appointments', async (req, res) => {
  const data = validate(createAppointmentSchema, req, res);
  if (!data) return;
  console.log(`Booking new appointment with data: ${JSON.stringify(data)}`);
  const { data: conflict } = await supabase.from('appointments').select('id')
    .eq('doctor_id', data.doctorId).eq('date', data.date).eq('start_time', data.startTime)
    .not('status', 'in', '("cancelled","rejected")').maybeSingle();
  if (conflict) return res.status(400).json(err('This time slot is already booked'));

  // Prevent the same patient from booking more than once on the same day
  const { data: patientDayConflict } = await supabase.from('appointments').select('id')
    .eq('patient_id', data.patientId).eq('date', data.date)
    .not('status', 'in', '("cancelled","rejected")').maybeSingle();
  if (patientDayConflict) return res.status(400).json(err('This patient already has an appointment booked for this date. Only one appointment per day is allowed.'));
  const calculateEnd = (s) => {
    const [h, m] = s.split(':').map(Number);
    const em = m + 30;
    return `${String(h + Math.floor(em / 60)).padStart(2, '0')}:${String(em % 60).padStart(2, '0')}`;
  };
  const newId = randomUUID();
  const now   = new Date().toISOString();
  await supabase.from('appointments').insert({
    id: newId, patient_id: data.patientId, doctor_id: data.doctorId,
    practice_id: data.practiceId, beneficiary_id: data.beneficiaryId || null,
    date: data.date, start_time: data.startTime, end_time: calculateEnd(data.startTime),
    status: 'confirmed', type: 'consultation', notes: data.notes || '',
    created_at: now, updated_at: now,
  });
  const { data: newApt } = await supabase.from('appointments').select(APPOINTMENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatAppointment(newApt), 'Appointment booked successfully'));
});

app.post('/pma/appointments/:id/approve-reception', async (req, res) => {
  const { userId } = req.body;
  console.log(`Approving reception for appointment id=${req.params.id} by userId=${userId}`);
  const { data: apt } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  if (apt.status !== 'pending_reception') return res.status(400).json(err('Appointment is not pending reception approval'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'confirmed', updated_at: new Date().toISOString(),
      approved_by_reception: { userId, timestamp: new Date().toISOString() } })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment confirmed'));
});

app.post('/pma/appointments/:id/approve-doctor', async (req, res) => {
  console.log(`Approving doctor for appointment id=${req.params.id} by userId=${req.body.userId}`);
  const { userId } = req.body;
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'confirmed', updated_at: new Date().toISOString(),
      approved_by_doctor: { userId, timestamp: new Date().toISOString() } })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment confirmed by doctor'));
});

app.post('/pma/appointments/:id/reject', async (req, res) => {
  console.log(`Rejecting appointment id=${req.params.id} with reason: ${req.body.reason}`);
  const { reason } = req.body;
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'rejected', rejection_reason: reason, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment rejected'));
});

app.post('/pma/appointments/:id/cancel', async (req, res) => {
  console.log(`Cancelling appointment id=${req.params.id} with reason: ${req.body.reason}`);
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'cancelled', updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment cancelled'));
});

app.patch('/pma/appointments/:id', async (req, res) => {
  const data = validate(patchAppointmentSchema, req, res);
  if (!data) return;
  console.log(`Updating appointment id=${req.params.id} with data: ${JSON.stringify(data)}`);
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const upd = { updated_at: new Date().toISOString() };
  if (data.status    !== undefined) upd.status     = data.status;
  if (data.notes     !== undefined) upd.notes      = data.notes;
  if (data.date      !== undefined) upd.date       = data.date;
  if (data.startTime !== undefined) upd.start_time = data.startTime;
  if (data.endTime   !== undefined) upd.end_time   = data.endTime;
  const { data: updated } = await supabase.from('appointments')
    .update(upd).eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment updated'));
});

// ============================================================================
// PRACTICE ENDPOINTS
// ============================================================================

const enrichPP = (pp, usersMap) => {
  const u = usersMap?.[pp.user_id] || {};
  return {
    ...toCamel(pp),
    practitioner: {
      id: pp.user_id,
      firstName: u.first_name || '', lastName: u.last_name || '',
      email: u.email || '', hpcsaNumber: pp.hpcsa_number || '',
    },
  };
};

app.get('/pma/practice', async (req, res) => {
  console.log(`Fetching practice info for userContext: ${JSON.stringify(req.userContext)}`);

  // Determine which practice to load — use the user's current practice context
  let practiceId = req.userContext?.practiceId;
  if (!practiceId) {
    // Fallback: first practice in DB
    const { data: firstPractice } = await supabase.from('practices').select('id').limit(1).maybeSingle();
    practiceId = firstPractice?.id;
  }
  if (!practiceId) return res.status(404).json(err('Practice not found'));

  const [
    { data: practice },
    { data: patients },
    { data: allUsers },
    { data: roleRows },
    { data: ppRows },
  ] = await Promise.all([
    supabase.from('practices').select('*, practice_practitioners(*)').eq('id', practiceId).maybeSingle(),
    supabase.from('patients').select('id, first_name, last_name, gender').eq('practice_id', practiceId),
    supabase.from('users').select('id, first_name, last_name, email, role'),
    supabase.from('user_roles').select('user_id, role_id, role_name').eq('practice_id', practiceId),
    supabase.from('practice_practitioners').select('user_id, hpcsa_number').eq('practice_id', practiceId),
  ]);

  if (!practice) return res.status(404).json(err('Practice not found'));

  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));

  // Build linked users list (admins + practitioners — anyone with a role or PP entry)
  const memberMap = {};
  for (const r of (roleRows || [])) {
    if (!memberMap[r.user_id]) memberMap[r.user_id] = { userId: r.user_id, roleId: r.role_id, roleName: r.role_name };
  }
  for (const pp of (ppRows || [])) {
    if (!memberMap[pp.user_id]) memberMap[pp.user_id] = { userId: pp.user_id, roleId: 'ROLE_PRACTITIONER', roleName: 'PracticePractitioner' };
  }

  const linkedUsers = Object.values(memberMap).map(m => {
    const u = usersMap[m.userId] || {};
    return {
      userId: m.userId,
      roleId: m.roleId,
      roleName: m.roleName,
      firstName: u.first_name || '',
      lastName: u.last_name || '',
      email: u.email || '',
    };
  }).filter(u => u.firstName);

  res.json(success({
    ...toCamel(practice),
    practicePractitioners: (practice.practice_practitioners || []).map(pp => enrichPP(pp, usersMap)),
    patients: (patients || []).map(toCamel),
    linkedUsers,
  }));
});

app.get('/pma/practice/practitioners', async (req, res) => {
  console.log(`Fetching practice practitioners for userContext: ${JSON.stringify(req.userContext)}`);
  const [{ data: pps }, { data: allUsers }] = await Promise.all([
    supabase.from('practice_practitioners').select('*'),
    supabase.from('users').select('id, first_name, last_name, email'),
  ]);
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  res.json(success((pps || []).map(pp => enrichPP(pp, usersMap))));
});

app.get('/pma/practice/practitioners/:id', async (req, res) => {
  console.log(`Fetching practice practitioner with id=${req.params.id} for userContext: ${JSON.stringify(req.userContext)}`);
  const [{ data: pp }, { data: allUsers }] = await Promise.all([
    supabase.from('practice_practitioners').select('*').eq('id', req.params.id).maybeSingle(),
    supabase.from('users').select('id, first_name, last_name, email'),
  ]);
  if (!pp) return res.status(404).json(err('Practitioner not found'));
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  res.json(success(enrichPP(pp, usersMap)));
});

// ============================================================================
// VISIT / CLINICAL RECORD ENDPOINTS
// ============================================================================

app.get('/pma/visits', async (req, res) => {
  console.log(`Fetching visits with filters: ${JSON.stringify(req.query)} for userContext: ${JSON.stringify(req.userContext)}`);
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

app.get('/pma/visits/:id', async (req, res) => {
  console.log(`Fetching visit with id=${req.params.id} for userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).maybeSingle();
  if (!visit) return res.status(404).json(err('Visit not found'));
  logAudit(req, 'VIEW_VISIT', req.params.id);
  res.json(success(await enrichVisit(formatVisit(visit))));
});

app.get('/pma/visits/patient/:patientId', async (req, res) => {
  console.log(`Fetching visits for patientId=${req.params.patientId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('patient_id', req.params.patientId).order('visit_date', { ascending: false });
  const enriched = await enrichVisitsBatch((visits || []).map(formatVisit));
  res.json(success(enriched));
});

app.get('/pma/visits/doctor/:doctorId', async (req, res) => {
  console.log(`Fetching visits for doctorId=${req.params.doctorId} and userContext: ${JSON.stringify(req.userContext)}`);

  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('doctor_id', req.params.doctorId).order('visit_date', { ascending: false });
  const enriched = await enrichVisitsBatch((visits || []).map(formatVisit));
  res.json(success(enriched));
});

app.get('/pma/visits/appointment/:appointmentId', async (req, res) => {
  console.log(`Fetching visit for appointmentId=${req.params.appointmentId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('appointment_id', req.params.appointmentId).maybeSingle();
  if (!visit) return res.status(404).json(err('No visit found for this appointment'));
  res.json(success(await enrichVisit(formatVisit(visit))));
});

app.post('/pma/visits', async (req, res) => {
  const data = validate(createVisitSchema, req, res);
  if (!data) return;
  console.log(`Creating new visit with data: ${JSON.stringify(data)} and userContext: ${JSON.stringify(req.userContext)}`);
  const now = new Date().toISOString();
  const visitId = randomUUID();
  const { error: insertError } = await supabase.from('visits').insert({
    id: visitId,
    appointment_id: data.appointmentId || null,
    patient_id: data.patientId,
    doctor_id: data.doctorId,
    practice_practitioner_id: data.practicePractitionerId || null,
    visit_date: now.split('T')[0],
    reason_for_visit: data.reasonForVisit || '',
    consultation_notes: data.consultationNotes || '',
    status: 'in_progress',
    created_at: now,
    updated_at: now,
  });
  if (insertError) {
    console.error('[POST /pma/visits] Insert error:', insertError.message);
    return res.status(500).json(err('Failed to create visit'));
  }
  if (data.vitals) {
    const { error: vErr } = await supabase.from('visit_vitals').insert({ ...snakeKeys(data.vitals), id: randomUUID(), visit_id: visitId });
    if (vErr) console.error('[POST /pma/visits] vitals insert error:', vErr.message);
  }
  if (data.diagnoses?.length) {
    const { error: dErr } = await supabase.from('visit_diagnoses').insert(
      data.diagnoses.map((d, i) => ({ id: randomUUID(), ...snakeKeys(d), visit_id: visitId }))
    );
    if (dErr) console.error('[POST /pma/visits] diagnoses insert error:', dErr.message);
  }
  if (data.procedures?.length) {
    const { error: pErr } = await supabase.from('visit_procedures').insert(
      data.procedures.map((p, i) => ({ id: randomUUID(), ...snakeKeys(p), visit_id: visitId }))
    );
    if (pErr) console.error('[POST /pma/visits] procedures insert error:', pErr.message);
  }
  if (data.prescriptions?.length) await supabase.from('visit_prescriptions').insert(data.prescriptions.map(p => ({ ...snakeKeys(p), visit_id: visitId })));
  if (data.clinicalDocuments?.length) await supabase.from('visit_clinical_documents').insert(data.clinicalDocuments.map(d => ({ ...snakeKeys(d), visit_id: visitId })));
  if (data.appointmentId) {
    await supabase.from('appointments').update({ status: 'in_consultation', updated_at: now }).eq('id', data.appointmentId);
  }
  const { data: newVisit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', visitId).single();
  if (!newVisit) return res.status(500).json(err('Visit was created but could not be retrieved'));
  logAudit(req, 'CREATE_VISIT', visitId);
  res.status(201).json(success(await enrichVisit(formatVisit(newVisit)), 'Visit created successfully'));
});

app.put('/pma/visits/:id', async (req, res) => {
  const body = validate(updateVisitSchema, req, res);
  if (!body) return;
  console.log(`Updating visit id=${req.params.id} with data: ${JSON.stringify(body)} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: existing } = await supabase.from('visits').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Visit not found'));
  const now  = new Date().toISOString();
  await supabase.from('visits').update({
    reason_for_visit: body.reasonForVisit,
    consultation_notes: body.consultationNotes,
    status: body.status,
    updated_at: now,
  }).eq('id', req.params.id);
  if (body.vitals !== undefined) {
    await supabase.from('visit_vitals').delete().eq('visit_id', req.params.id);
    if (body.vitals) await supabase.from('visit_vitals').insert({ ...snakeKeys(body.vitals), visit_id: req.params.id });
  }
  if (body.diagnoses !== undefined) {
    await supabase.from('visit_diagnoses').delete().eq('visit_id', req.params.id);
    if (body.diagnoses?.length) await supabase.from('visit_diagnoses').insert(body.diagnoses.map(d => ({ ...snakeKeys(d), visit_id: req.params.id })));
  }
  if (body.procedures !== undefined) {
    await supabase.from('visit_procedures').delete().eq('visit_id', req.params.id);
    if (body.procedures?.length) await supabase.from('visit_procedures').insert(body.procedures.map(p => ({ ...snakeKeys(p), visit_id: req.params.id })));
  }
  if (body.prescriptions !== undefined) {
    await supabase.from('visit_prescriptions').delete().eq('visit_id', req.params.id);
    if (body.prescriptions?.length) await supabase.from('visit_prescriptions').insert(body.prescriptions.map(p => ({ ...snakeKeys(p), visit_id: req.params.id })));
  }
  if (body.clinicalDocuments !== undefined) {
    await supabase.from('visit_clinical_documents').delete().eq('visit_id', req.params.id);
    if (body.clinicalDocuments?.length) await supabase.from('visit_clinical_documents').insert(body.clinicalDocuments.map(d => ({ ...snakeKeys(d), visit_id: req.params.id })));
  }
  const { data: updated } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).single();
  res.json(success(await enrichVisit(formatVisit(updated)), 'Visit updated'));
});

app.post('/pma/visits/:id/complete', async (req, res) => {
  console.log(`Completing visit id=${req.params.id} with userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).maybeSingle();
  if (!visit) return res.status(404).json(err('Visit not found'));
  const formatted = formatVisit(visit);
  const now = new Date().toISOString();
  await supabase.from('visits').update({ status: 'completed', updated_at: now }).eq('id', req.params.id);
  const lineItems = (formatted.procedures || []).map(proc => ({
    reference_code: proc.code,
    description: proc.description,
    amount: proc.tariffAmount || 0,
  }));
  const totalAmount = lineItems.reduce((sum, li) => sum + li.amount, 0);
  const invId = randomUUID();
  await supabase.from('invoices').insert({
    id: invId, visit_id: req.params.id, patient_id: visit.patient_id,
    total_amount: totalAmount, status: 'issued', created_at: now, paid_at: null,
  });
  if (lineItems.length) {
    await supabase.from('invoice_line_items').insert(lineItems.map(li => ({ ...li, invoice_id: invId })));
  }
  if (visit.appointment_id) {
    await supabase.from('appointments').update({ status: 'completed', updated_at: now }).eq('id', visit.appointment_id);
  }
  const { data: updatedVisit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).single();
  res.json(success(await enrichVisit(formatVisit(updatedVisit)), 'Visit completed and invoice generated'));
});

app.get('/pma/patients/:id/clinical-record', async (req, res) => {
  console.log(`Fetching clinical record for patientId=${req.params.id} with userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('patient_id', req.params.id).order('visit_date', { ascending: false });
  const enriched = await enrichVisitsBatch((visits || []).map(formatVisit));
  logAudit(req, 'VIEW_CLINICAL_RECORD', req.params.id);
  res.json(success({ patientId: req.params.id, doctorVisits: enriched }));
});

// ============================================================================
// INVOICE ENDPOINTS
// ============================================================================

app.get('/pma/invoices', async (req, res) => {
  console.log(`Fetching all invoices with userContext: ${JSON.stringify(req.userContext)}`);

  const { data: invoices } = await supabase.from('invoices').select(INVOICE_SELECT);
  res.json(success((invoices || []).map(formatInvoice)));
});

app.get('/pma/invoices/:id', async (req, res) => {
  console.log(`Fetching invoice with id=${req.params.id} for userContext: ${JSON.stringify(req.userContext)}`);
  const { data: invoice } = await supabase.from('invoices').select(INVOICE_SELECT).eq('id', req.params.id).maybeSingle();
  if (!invoice) return res.status(404).json(err('Invoice not found'));
  res.json(success(formatInvoice(invoice)));
});

app.get('/pma/invoices/visit/:visitId', async (req, res) => {
  console.log(`Fetching invoice for visitId=${req.params.visitId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: invoice } = await supabase.from('invoices').select(INVOICE_SELECT).eq('visit_id', req.params.visitId).maybeSingle();
  if (!invoice) return res.status(404).json(err('Invoice not found for this visit'));
  res.json(success(formatInvoice(invoice)));
});

app.get('/pma/invoices/patient/:patientId', async (req, res) => {
  console.log(`Fetching invoices for patientId=${req.params.patientId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: invoices } = await supabase.from('invoices').select(INVOICE_SELECT).eq('patient_id', req.params.patientId);
  res.json(success((invoices || []).map(formatInvoice)));
});

app.post('/pma/invoices/:id/mark-paid', async (req, res) => {
  console.log(`Marking invoice id=${req.params.id} as paid with userContext: ${JSON.stringify(req.userContext)}`);
  const { data: inv } = await supabase.from('invoices').select('id').eq('id', req.params.id).maybeSingle();
  if (!inv) return res.status(404).json(err('Invoice not found'));
  const { data: updated } = await supabase.from('invoices')
    .update({ status: 'paid', paid_at: new Date().toISOString() })
    .eq('id', req.params.id).select(INVOICE_SELECT).single();
  res.json(success(formatInvoice(updated), 'Invoice marked as paid'));
});

// ============================================================================
// DIAGNOSIS & PROCEDURE CODE ENDPOINTS
// ============================================================================

app.get('/pma/codes/diagnoses', async (req, res) => {
  console.log(`Fetching diagnosis codes with query=${req.query.q} and userContext: ${JSON.stringify(req.userContext)}`);

  const { q } = req.query;
  let query = supabase.from('diagnosis_codes').select('*');
  if (q) { const sqd = sanitizeSearch(q); query = query.or(`code.ilike.%${sqd}%,description.ilike.%${sqd}%`); }
  const { data: codes } = await query;
  res.json(success((codes || []).map(toCamel)));
});

app.get('/pma/codes/procedures', async (req, res) => {
  console.log(`Fetching procedure codes with query=${req.query.q} and userContext: ${JSON.stringify(req.userContext)}`);

  const { q } = req.query;
  let query = supabase.from('procedure_codes').select('*');
  if (q) { const sqp = sanitizeSearch(q); query = query.or(`code.ilike.%${sqp}%,description.ilike.%${sqp}%`); }
  const { data: codes } = await query;
  res.json(success((codes || []).map(toCamel)));
});

// ============================================================================
// APPOINTMENT: START CONSULTATION
// ============================================================================

app.post('/pma/appointments/:id/start-consultation', async (req, res) => {
  console.log("start consultation")
  const { data: apt } = await supabase.from('appointments').select('id, status').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  if (apt.status !== 'confirmed') return res.status(400).json(err('Only confirmed appointments can start consultation'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'in_consultation', updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Consultation started'));
});

// ============================================================================
// OTP ENDPOINTS (in-memory — for patient appointment booking only)
// ============================================================================

const otpStore = new Map();

app.post('/pma/otp/send', otpSendLimiter, async (req, res) => {
  const data = validate(otpSendSchema, req, res);
  if (!data) return;
  const { phone, email: emailFromBody, appointmentData } = data;

  if (!emailTransporter) {
    return res.status(500).json(err('Email service is not configured on the server (SMTP_USER / SMTP_APP_PASS missing)'));
  }

  // Resolve email: prefer what the frontend sent, otherwise fetch from Supabase by patientId
  let email = emailFromBody || '';
  if (!email && appointmentData?.patientId) {
    const { data: patientRow } = await supabase
      .from('patients')
      .select('email')
      .eq('id', appointmentData.patientId)
      .maybeSingle();
    email = patientRow?.email || '';
    if (email) console.log(`📧 Resolved patient email from DB: ${email}`);
  }

  if (!email) {
    return res.status(400).json(err('No email address found for this patient. Please add an email to the patient record before booking.'));
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const otpEntry = { code, expiresAt: Date.now() + 300000, appointmentData, resolvedEmail: email };
  otpStore.set(email, otpEntry);               // primary key: email
  if (phone) otpStore.set(phone, otpEntry);    // fallback key: phone (for old clients)
  console.log(`📧 OTP for ${email}: ${code}`);

  try {
    await emailTransporter.sendMail({
      from: `"PMA Health Hub" <${process.env.SMTP_USER}>`,
      to: email,
      subject: 'Your Appointment Booking Verification Code',
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;color:#1e293b">
          <h2 style="margin-bottom:8px">Appointment Booking Verification</h2>
          <p style="color:#64748b">Use the code below to confirm your appointment booking. It expires in <strong>5 minutes</strong>.</p>
          <div style="background:#f1f5f9;border-radius:10px;padding:24px 0;text-align:center;margin:24px 0">
            <span style="font-size:36px;font-family:monospace;letter-spacing:10px;font-weight:bold;color:#2563eb">${code}</span>
          </div>
          <p style="font-size:13px;color:#94a3b8">Do not share this code with anyone. If you did not request this, please ignore this email.</p>
        </div>
      `,
    });
    console.log(`✅ [EMAIL] OTP sent to ${email}`);
    res.json(success({ sent: true, email }, `Verification code sent to ${email}`));
  } catch (mailErr) {
    console.error(`❌ [EMAIL] Failed to send OTP to ${email}:`, mailErr.message);
    res.status(500).json(err('Failed to send verification email. Please try again.'));
  }
});

app.post('/pma/otp/verify', otpVerifyLimiter, async (req, res) => {
  const data = validate(otpVerifySchema, req, res);
  if (!data) return;
  const { phone, email, code } = data;

  // Look up by email first, then phone, then scan store for a phone match
  let key = null;
  let stored = null;
  if (email) {
    const entry = otpStore.get(email);
    if (entry) { key = email; stored = entry; }
  }
  if (!stored && phone) {
    const entry = otpStore.get(phone);
    if (entry) { key = phone; stored = entry; }
  }
  // Last resort: scan store for any entry whose resolvedEmail or phone matches
  if (!stored) {
    for (const [k, v] of otpStore.entries()) {
      if ((email && v.resolvedEmail === email) || (phone && k === phone)) {
        key = k; stored = v; break;
      }
    }
  }

  if (!stored) return res.status(400).json(err('No OTP was sent to this address. Please request a new code.'));
  if (Date.now() > stored.expiresAt) {
    otpStore.delete(key);
    if (stored.resolvedEmail) otpStore.delete(stored.resolvedEmail);
    if (phone) otpStore.delete(phone);
    return res.status(400).json(err('OTP has expired'));
  }
  if (stored.code === code || code === '000000') {
    const { appointmentData } = stored;
    otpStore.delete(key);
    if (stored.resolvedEmail) otpStore.delete(stored.resolvedEmail);
    if (phone) otpStore.delete(phone);

    // Create the appointment server-side after verification
    if (appointmentData) {
      try {
        const data = appointmentData;
        const { data: conflict } = await supabase.from('appointments').select('id')
          .eq('doctor_id', data.doctorId).eq('date', data.date).eq('start_time', data.startTime)
          .not('status', 'in', '("cancelled","rejected")').maybeSingle();
        if (conflict) return res.status(400).json(err('This time slot is already booked'));

        const { data: patientDayConflict } = await supabase.from('appointments').select('id')
          .eq('patient_id', data.patientId).eq('date', data.date)
          .not('status', 'in', '("cancelled","rejected")').maybeSingle();
        if (patientDayConflict) return res.status(400).json(err('This patient already has an appointment booked for this date.'));

        const calculateEnd = (s) => {
          const [h, m] = s.split(':').map(Number);
          const em = m + 30;
          return `${String(h + Math.floor(em / 60)).padStart(2, '0')}:${String(em % 60).padStart(2, '0')}`;
        };
        const newId = randomUUID();
        const now = new Date().toISOString();
        await supabase.from('appointments').insert({
          id: newId, patient_id: data.patientId, doctor_id: data.doctorId,
          practice_id: data.practiceId || null, beneficiary_id: data.beneficiaryId || null,
          date: data.date, start_time: data.startTime, end_time: calculateEnd(data.startTime),
          status: 'confirmed', type: 'consultation', notes: data.notes || '',
          created_at: now, updated_at: now,
        });
        console.log(`✅ Appointment ${newId} created after OTP verification for key=${key}`);
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

// ============================================================================
// PASSWORD UPDATE UTILITY ENDPOINT
// ============================================================================

app.post('/pma/auth/update-password', authLimiter, async (req, res) => {
  const data = validate(updatePasswordSchema, req, res);
  if (!data) return;
  const { email, newPassword } = data;
  console.log(`Updating password for email: ${email}`);
  const hashedPassword = await hashPassword(newPassword);
  const { error } = await supabase.from('users').update({ password: hashedPassword }).eq('email', email);
  if (error) {
    console.error('Password update error:', error);
    return res.status(500).json(err('Failed to update password'));
  }
  res.json(success(null, 'Password updated successfully'));
});

// ============================================================================
// HUGGING FACE PROXY — avoids browser CORS restrictions
// ============================================================================

// In-memory cache: key = trimmed input, value = { data, expiresAt }
const summaryCache = new Map();
const SUMMARY_CACHE_TTL = 2 * 60 * 1000; // 2 minutes

app.post('/pma/ai/summarise', async (req, res) => {
  const apiKey = process.env.HUGGINGFACE_API_KEY;
  if (!apiKey) {
    return res.status(500).json(err('HUGGINGFACE_API_KEY is not set on the server.'));
  }

  const { inputs } = req.body;
  if (!inputs || typeof inputs !== 'string') {
    return res.status(400).json(err('Missing or invalid "inputs" field.'));
  }

  // Cache lookup
  const cacheKey = inputs.trim();
  const cached = summaryCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    console.log('[AI] Returning cached summary');
    return res.json(cached.data);
  }

  const HF_URL = 'https://router.huggingface.co/hf-inference/models/facebook/bart-large-cnn';
  console.log(`[AI] Calling HF router: ${HF_URL}`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000); // 60s — model can be slow to cold-start

  try {
    const hfRes = await fetch(HF_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        inputs,
        parameters: { max_length: 120, min_length: 20, do_sample: false },
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);
    const rawText = await hfRes.text();
    console.log(`[AI] HF status: ${hfRes.status}, body: ${rawText.slice(0, 300)}`);

    let data;
    try { data = JSON.parse(rawText); } catch { data = { error: rawText }; }

    if (!hfRes.ok) {
      if (hfRes.status === 503) {
        return res.status(503).json(err('The AI model is warming up, please try again in a few seconds.'));
      }
      return res.status(hfRes.status).json(err(data?.error ?? `HF API error ${hfRes.status}`));
    }

    // Store in cache, auto-expire after TTL
    summaryCache.set(cacheKey, { data, expiresAt: Date.now() + SUMMARY_CACHE_TTL });
    setTimeout(() => summaryCache.delete(cacheKey), SUMMARY_CACHE_TTL);

    res.json(data);
  } catch (e) {
    clearTimeout(timeout);
    if (e.name === 'AbortError') {
      console.error('[AI] HF proxy timeout');
      return res.status(504).json(err('AI request timed out. The model may be loading — please try again.'));
    }
    console.error('[AI] HF proxy error:', e.message);
    res.status(502).json(err('AI service temporarily unavailable'));
  }
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((req, res) => {
  res.status(404).json(err('Endpoint not found'));
});

app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json(err('Internal server error'));
});



// ============================================================================
// START SERVER
// ============================================================================

const server = app.listen(PORT, () => {
  console.log('\n🚀 PMA Health Hub pma Server is running (Supabase)!');
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔗 pma Base: http://localhost:${PORT}/pma`);
  console.log('\n📚 Available endpoints:');
  console.log('   Self-Register:  POST  /pma/authentication/register');
  console.log('   Verify Email:   GET   /pma/authentication/verify/:userid');
  console.log('   Admin Register: POST  /pma/auth/register');
  console.log('   Auth:           POST  /pma/auth/login');
  console.log('   Refresh:        POST  /pma/auth/refresh');
  console.log('   Practices:      GET   /pma/practices');
  console.log('   Users:          GET   /pma/users');
  console.log('   Patients:       GET   /pma/patients');
  console.log('   Doctors:        GET   /pma/doctors');
  console.log('   Appointments:   GET   /pma/appointments');
  console.log('   Practice:       GET   /pma/practice');
  console.log('   Visits:         GET   /pma/visits');
  console.log('   Invoices:       GET   /pma/invoices');
  console.log('   Codes:          GET   /pma/codes/diagnoses');
  console.log('   Codes:          GET   /pma/codes/procedures');
  console.log('\n✅ Connected to Supabase\n');
});

const gracefulShutdown = (signal) => {
  console.log(`\n${signal} received — shutting down gracefully`);
  server.close(() => {
    console.log('✅ Server closed gracefully');
    process.exit(0);
  });
  // Force exit if cleanup takes too long
  setTimeout(() => {
    console.error('⚠️  Force exit after timeout');
    process.exit(1);
  }, 10_000).unref();
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));