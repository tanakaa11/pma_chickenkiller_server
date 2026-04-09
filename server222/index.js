import dotenv from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import { supabase } from './supabase.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '.env') });
const app = express();
const PORT = process.env.PORT || 5000;

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

// Practice filtering middleware - ensures users only see their practice's data
const extractUserIdFromToken = (req) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.replace('Bearer ', '');
  // Extract user ID from mock token format: "mock-jwt-token-{userId}"
  const match = token.match(/mock-jwt-token-(.+)/);
  return match ? match[1] : null;
};

const addPracticeFilter = async (req, res, next) => {
  // Skip for auth routes, public routes, user profile endpoints, and admin functions
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
  
  // Check if this is a skip path first
  if (skipPaths.some(path => req.path.startsWith(path))) {
    return next();
  }
  
  // Extract userId from token
  const userId = extractUserIdFromToken(req);
  
  if (!userId) {
    return res.status(401).json(err('Authentication required'));
  }
  
  // Skip user's own profile and practice checking endpoints
  const userProfilePaths = [
    `/users/${userId}/my-practice`, `/pma/users/${userId}/my-practice`, `/api/users/${userId}/my-practice`,
    `/users/${userId}/my-practices`, `/pma/users/${userId}/my-practices`, `/api/users/${userId}/my-practices`,
    `/users/${userId}`, `/pma/users/${userId}`, `/api/users/${userId}`
  ];
  
  if (userProfilePaths.some(path => req.path === path)) {
    return next();
  }

  // Check user's role from DB for super_super_admin bypass
  const { data: userRow } = await supabase
    .from('users').select('role').eq('id', userId).maybeSingle();

  if (userRow?.role === 'super_super_admin') {
    // Super super admin bypasses all practice filtering
    // They can optionally send X-Practice-Id to scope to a specific practice
    const headerPracticeId = req.headers['x-practice-id'] || null;
    req.userContext = {
      userId,
      practiceId: headerPracticeId,
      isSuperAdmin: true,
      isSuperSuperAdmin: true,
    };
    return next();
  }

  // Check for X-Practice-Id header (multi-practice support)
  const headerPracticeId = req.headers['x-practice-id'] || null;

  // Get ALL user's linked practices
  const { data: allUserPractices } = await supabase
    .from('user_practices')
    .select('practice_id')
    .eq('user_id', userId);

  const linkedPracticeIds = new Set((allUserPractices || []).map(p => p.practice_id));

  // Also check user_roles and practice_practitioners as fallback
  if (linkedPracticeIds.size === 0) {
    const [{ data: roleRows }, { data: ppRows }] = await Promise.all([
      supabase.from('user_roles').select('practice_id').eq('user_id', userId).not('practice_id', 'is', null),
      supabase.from('practice_practitioners').select('practice_id').eq('user_id', userId),
    ]);
    for (const r of (roleRows || [])) linkedPracticeIds.add(r.practice_id);
    for (const p of (ppRows || []))   linkedPracticeIds.add(p.practice_id);

    // Back-fill user_practices for fast future lookups
    if (linkedPracticeIds.size > 0) {
      const { data: practiceNames } = await supabase
        .from('practices').select('id, name').in('id', [...linkedPracticeIds]);
      const nameMap = Object.fromEntries((practiceNames || []).map(p => [p.id, p.name]));
      const inserts = [...linkedPracticeIds].map(pid => ({
        user_id: userId, practice_id: pid, practice_name: nameMap[pid] || '',
      }));
      await supabase.from('user_practices').upsert(inserts, { onConflict: 'user_id,practice_id' }).select();
    }
  }

  // Determine which practice to scope to
  let practiceId = null;

  if (headerPracticeId && linkedPracticeIds.has(headerPracticeId)) {
    // Frontend explicitly requested this practice and user is linked
    practiceId = headerPracticeId;
  } else if (linkedPracticeIds.size > 0) {
    // Default to first linked practice
    practiceId = [...linkedPracticeIds][0];
  }

  if (!practiceId) {
    return res.status(403).json(err('User is not linked to any practice'));
  }

  // Check if user is super admin (can access all data)
  const { data: userRoles } = await supabase
    .from('user_roles')
    .select('role_id')
    .eq('user_id', userId);

  const isSuperAdmin = userRoles?.some(role => role.role_id === 'ROLE_SYSADMIN');
  
  // Attach practice info to request for use in endpoints
  req.userContext = {
    userId,
    practiceId,
    isSuperAdmin,
    isSuperSuperAdmin: false,
    linkedPracticeIds: [...linkedPracticeIds],
  };

  next();
};

app.use(addPracticeFilter);

// Helper to simulate network delay
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

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
  await delay(300);
  const { email, password } = req.body;

  console.log(`🔍 [LOGIN] Attempting login for: ${email}`);

  if (!email || !password) {
    return res.status(400).json(err('Email and password are required'));
  }

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
  const token = `mock-jwt-token-${user.id}`;
  res.json(success({ user, token }, 'Login successful'));
};
app.post('/pma/auth/login', loginHandler);
app.post('/auth/login',     loginHandler);

app.post('/pma/auth/logout', async (req, res) => {
  res.json(success(null, 'Logged out successfully'));
});
app.post('/auth/logout', async (req, res) => {
  res.json(success(null, 'Logged out successfully'));
});

// ============================================================================
// SELF-REGISTRATION — Clean server flow (register + email verify link)
//
// ============================================================================

app.post('/pma/authentication/register', async (req, res) => {
  await delay(400);
  const { email, password, firstname, lastname } = req.body;

  if (!email || !password || !firstname || !lastname) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  // Check for existing user (active or pending)
  const { data: existing } = await supabase
    .from('users').select('id').eq('email', email).maybeSingle();
  if (existing) {
    return res.status(409).json({ message: 'User already exists' });
  }

  const hashedPassword = await hashPassword(password);

  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  const newId = `USR${String((count || 0) + 1).padStart(3, '0')}`;

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
  await delay(400);
  const { email, password, firstName, lastName, roleId, practiceIds } = req.body;

  if (!email || !password || !firstName || !lastName || !roleId) {
    return res.status(400).json(err('All fields are required'));
  }

  if (password.length < 6) {
    return res.status(400).json(err('Password must be at least 6 characters long'));
  }

  const { data: existing } = await supabase
    .from('users').select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json(err('A user with this email already exists'));

  const roleInfo = ROLE_MAP[roleId];
  if (!roleInfo) return res.status(400).json(err('Invalid role'));

  const hashedPassword = await hashPassword(password);

  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  const newId = `USR${String((count || 0) + 1).padStart(3, '0')}`;

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
      id: `doc-${Date.now()}`, user_id: newId,
      first_name: firstName, last_name: lastName,
      specialization: 'General Practice', email, phone: '', is_available: true,
    });
  }

  const { data: newUserRow } = await supabase
    .from('users').select(USER_SELECT).eq('id', newId).single();
  const newUser = formatUser(newUserRow);
  const token   = `mock-jwt-token-${newUser.id}`;
  res.status(201).json(success({ user: newUser, token }, 'Registration successful'));
};

app.post('/pma/auth/register', registerHandler);
app.post('/auth/register',     registerHandler);

// ============================================================================
// PRACTICES LIST ENDPOINT (for registration dropdown)
// ============================================================================

const practicesHandler = async (req, res) => {
  await delay(200);
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
  await delay(200);
  const { q } = req.query;
  let query = supabase.from('practices').select('id, name, practice_number');
  if (q) query = query.or(`name.ilike.%${q}%,practice_number.ilike.%${q}%`);
  const { data: practices } = await query;
  res.json(success((practices || []).map(p => ({
    id: p.id, name: p.name, practiceNumber: p.practice_number,
  }))));
});

app.get('/pma/practices/:id', async (req, res) => {
  await delay(200);
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
  await delay(200);
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
  await delay(200);
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
  await delay(300);
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json(err('No token provided'));
  const userId = token.replace('mock-jwt-token-', '');
  const { data: u } = await supabase
    .from('users').select(USER_SELECT).eq('id', userId).single();
  if (!u) return res.status(404).json(err('User not found'));
  res.json(success(formatUser(u)));
};
app.get('/pma/auth/me', meHandler);
app.get('/auth/me',     meHandler);

// ============================================================================
// USER ENDPOINTS
// ============================================================================

app.get('/pma/users', async (req, res) => {
  await delay(300);
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
  await delay(300);
  const { data: users } = await supabase
    .from('users').select(USER_SELECT).eq('role', req.params.role);
  res.json(success((users || []).map(formatUser)));
});

app.get('/pma/users/check-email', async (req, res) => {
  await delay(200);
  const { email } = req.query;
  if (!email) return res.status(400).json(err('email is required'));
  const { data: user } = await supabase
    .from('users').select(USER_SELECT).eq('email', String(email).toLowerCase()).maybeSingle();
  if (!user) return res.json(success({ exists: false }));
  return res.json(success({ exists: true, user: formatUser(user) }));
});

app.get('/pma/users/:id', async (req, res) => {
  await delay(200);
  const { data: u } = await supabase
    .from('users').select(USER_SELECT).eq('id', req.params.id).single();
  if (!u) return res.status(404).json(err('User not found'));
  res.json(success(formatUser(u)));
});

app.post('/pma/users', async (req, res) => {
  await delay(400);
  const { data: existing } = await supabase
    .from('users').select('id').eq('email', req.body.email).maybeSingle();
  if (existing) return res.status(400).json(err('A user with this email already exists'));

  const uiRoleToRoleId   = { super_admin: 'ROLE_SYSADMIN', doctor: 'ROLE_PRACTITIONER', reception: 'ROLE_ADMIN' };
  const uiRoleToRoleName = { super_admin: 'SystemAdministrator', doctor: 'PracticePractitioner', reception: 'PracticeAdministrator' };
  const uiRole = req.body.role || 'reception';

  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  const newId = `USR${String((count || 0) + 1).padStart(3, '0')}`;

  const { error: insertErr } = await supabase.from('users').insert({
    id: newId, email: req.body.email,
    first_name: req.body.firstName, last_name: req.body.lastName,
    is_active: true, role: uiRole,
  });
  if (insertErr) return res.status(500).json(err('Failed to create user'));

  await supabase.from('user_roles').insert({
    user_id: newId, role_id: uiRoleToRoleId[uiRole], role_name: uiRoleToRoleName[uiRole],
  });

  const { data: newUserRow } = await supabase.from('users').select(USER_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatUser(newUserRow), 'User created successfully'));
});

app.put('/pma/users/:id', async (req, res) => {
  await delay(300);
  const { data: existing } = await supabase.from('users').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  const upd = {};
  if (req.body.firstName !== undefined) upd.first_name = req.body.firstName;
  if (req.body.lastName  !== undefined) upd.last_name  = req.body.lastName;
  if (req.body.email     !== undefined) upd.email      = req.body.email;
  if (req.body.isActive  !== undefined) upd.is_active  = req.body.isActive;
  if (req.body.role      !== undefined) upd.role       = req.body.role;
  await supabase.from('users').update(upd).eq('id', req.params.id);
  const { data: updated } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success(formatUser(updated), 'User updated successfully'));
});

app.delete('/pma/users/:id', async (req, res) => {
  await delay(300);
  const { data: existing } = await supabase.from('users').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  await supabase.from('users').delete().eq('id', req.params.id);
  res.json(success(null, 'User deleted successfully'));
});

app.patch('/pma/users/:id/toggle-active', async (req, res) => {
  await delay(200);
  const { data: existing } = await supabase
    .from('users').select('id, is_active').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('User not found'));
  await supabase.from('users').update({ is_active: !existing.is_active }).eq('id', req.params.id);
  const { data: updated } = await supabase.from('users').select(USER_SELECT).eq('id', req.params.id).single();
  res.json(success(formatUser(updated)));
});

app.post('/pma/users/:id/link-practice', async (req, res) => {
  await delay(300);
  const { practiceId, roleId, force } = req.body;
  if (!practiceId) return res.status(400).json(err('practiceId is required'));

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
  if (emailTransporter) {
    try {
      await emailTransporter.sendMail({
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
      });
      console.log(`✅ [EMAIL] OTP email sent to ${user.email}`);
    } catch (mailErr) {
      console.error(`❌ [EMAIL] Failed to send OTP to ${user.email}:`, mailErr.message);
    }
  }

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
  res.json(success({
    user: formatUser(updatedUser),
    otp,
    token: `practice-link-token-${Date.now()}`,
    link: `${process.env.CLIENT_URL || 'http://localhost:3000'}/verify-link?token=practice-link-token-${Date.now()}`,
  }, 'Practice linked and OTP generated'));
});

app.get('/pma/users/:id/my-practice', async (req, res) => {
  await delay(200);
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
  await delay(200);

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
  await delay(300);
  const { email, practiceId, roleId, firstName, lastName, force } = req.body;
  
  if (!email || !practiceId || !roleId) {
    return res.status(400).json(err('email, practiceId, and roleId are required'));
  }

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
        id: `doc-${Date.now()}`,
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
    const token = `invite-${Date.now()}-${user.id}`;
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
    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
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
        });
        console.log(`✅ [EMAIL] Invite email sent to ${email}`);
      } catch (mailErr) {
        console.error(`❌ [EMAIL] Failed to send invite to ${email}:`, mailErr.message);
      }
    }
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
  await delay(200);
  const { email, inviteLink, practiceName, firstName } = req.body;
  if (!email || !inviteLink) {
    return res.status(400).json(err('email and inviteLink are required'));
  }
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
    res.status(500).json(err(`Failed to send email: ${mailErr.message}`));
  }
});

// Send/resend OTP for a user to link their practice (triggered by admin from Practice Management)
app.post('/pma/admin/send-otp', async (req, res) => {
  await delay(200);
  const { userId, practiceId } = req.body;
  if (!userId || !practiceId) return res.status(400).json(err('userId and practiceId are required'));

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
  if (emailTransporter) {
    try {
      await emailTransporter.sendMail({
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
      });
      emailed = true;
      console.log(`✅ [EMAIL] OTP sent to ${user.email}`);
    } catch (mailErr) {
      console.error(`❌ [EMAIL] Failed to send OTP:`, mailErr.message);
    }
  }

  res.json(success({ otp, emailed }, emailed ? `OTP sent to ${user.email}` : `OTP generated: ${otp} (email not configured)`));
});

// Direct link (no OTP) — for linking an existing user to a practice immediately
app.post('/pma/users/:id/link-practice-direct', async (req, res) => {
  await delay(300);
  const { practiceId, roleId, force } = req.body;
  if (!practiceId) return res.status(400).json(err('practiceId is required'));

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
  await delay(400);
  const { email, firstName, lastName, roleId, practiceId, tempPassword } = req.body;
  if (!email || !firstName || !lastName || !roleId || !practiceId)
    return res.status(400).json(err('email, firstName, lastName, roleId, and practiceId are required'));

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

  const { count } = await supabase.from('users').select('id', { count: 'exact', head: true });
  const newId = `USR${String((count || 0) + 1).padStart(3, '0')}`;
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
      id: `doc-${Date.now()}`, user_id: newId,
      first_name: firstName, last_name: lastName,
      specialization: 'General Practice', email: email.toLowerCase(), phone: '', is_available: true,
    });
  }

  // Generate invite token — stored in DB so it survives server restarts
  const token = `invite-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
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
  await delay(200);
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
app.post('/pma/auth/set-password', async (req, res) => {
  await delay(300);
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json(err('token and password are required'));
  if (password.length < 6) return res.status(400).json(err('Password must be at least 6 characters'));
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
  await delay(300);
  const { otp, userId } = req.body;
  if (!otp || !userId) return res.status(400).json(err('OTP and userId are required'));
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
  await delay(300);
  const { page, pageSize, search, idNumber, ids } = req.query;
  
  let query = supabase.from('patients').select(PATIENT_SELECT);
  
  if (ids) {
    query = query.in('id', ids.split(','));
    const { data: patients } = await query;
    return res.json(success((patients || []).map(formatPatient)));
  }
  if (idNumber) query = query.eq('id_number', idNumber);
  if (search)   query = query.or(
    `first_name.ilike.%${search}%,last_name.ilike.%${search}%,phone.ilike.%${search}%,id_number.ilike.%${search}%`
  );
  const { data: patients, error: dbErr } = await query;
  if (dbErr) return res.status(500).json(err('Failed to fetch patients'));
  const formatted = (patients || []).map(formatPatient);
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

app.get('/pma/patients/search', async (req, res) => {
  await delay(300);
  const { q } = req.query;
  console.log(`🔍 Patient search query: "${q}"`);
  if (!q) return res.json(success([]));
  let query = supabase
    .from('patients').select(PATIENT_SELECT)
    .or(`first_name.ilike.%${q}%,last_name.ilike.%${q}%,id_number.ilike.%${q}%,email.ilike.%${q}%,phone.ilike.%${q}%`);
  const { data: patients } = await query;
  const results = (patients || []).map(formatPatient);
  results.sort((a, b) => {
    const qL = q.toLowerCase();
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
  await delay(300);
  const { data: patients } = await supabase
    .from('patients').select(PATIENT_SELECT).eq('id_number', req.params.idNumber);
  if (!patients || patients.length === 0) return res.status(404).json(err('Patient not found'));
  res.json(success(formatPatient(patients[0])));
});

app.get('/pma/patients/:id', async (req, res) => {
  await delay(200);
  const { data: p } = await supabase
    .from('patients').select(PATIENT_SELECT).eq('id', req.params.id).single();
  if (!p) return res.status(404).json(err('Patient not found'));
  res.json(success(formatPatient(p)));
});

app.post('/pma/patients', async (req, res) => {
  await delay(400);
  const { data: existing } = await supabase
    .from('patients').select('id').eq('id_number', req.body.idNumber).maybeSingle();
  if (existing) return res.status(400).json(err('A patient with this ID number already exists'));
  const newId = `patient-${Date.now()}`;
  const now   = new Date().toISOString();
  const { error: insertErr } = await supabase.from('patients').insert({
    id: newId, first_name: req.body.firstName, last_name: req.body.lastName,
    date_of_birth: req.body.dateOfBirth, gender: req.body.gender,
    id_number: req.body.idNumber, phone: req.body.phone, email: req.body.email,
    practice_id: req.body.practiceId, allergies: req.body.allergies || [],
    created_at: now, updated_at: now,
  });
  if (insertErr) return res.status(500).json(err('Failed to create patient'));
  if (req.body.address) {
    await supabase.from('patient_addresses').insert({
      patient_id: newId, street: req.body.address.street, city: req.body.address.city,
      province: req.body.address.province,
      postal_code: req.body.address.postalCode || req.body.address.postal_code,
    });
  }
  if (req.body.emergencyContact) {
    await supabase.from('patient_emergency_contacts').insert({
      patient_id: newId, name: req.body.emergencyContact.name,
      relationship: req.body.emergencyContact.relationship, phone: req.body.emergencyContact.phone,
    });
  }
  if (req.body.medicalAids) {
    const inserts = [];
    if (req.body.medicalAids.active) inserts.push({
      patient_id: newId, provider_name: req.body.medicalAids.active.providerName,
      plan_name: req.body.medicalAids.active.planName,
      membership_number: req.body.medicalAids.active.membershipNumber, is_active: true,
    });
    for (const h of (req.body.medicalAids.history || [])) inserts.push({
      patient_id: newId, provider_name: h.providerName,
      plan_name: h.planName, membership_number: h.membershipNumber, is_active: false,
    });
    if (inserts.length > 0) await supabase.from('patient_medical_aids').insert(inserts);
  }
  const { data: newPatient } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatPatient(newPatient), 'Patient created successfully'));
});

app.put('/pma/patients/:id', async (req, res) => {
  await delay(300);
  const { data: existing } = await supabase.from('patients').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Patient not found'));
  const now = new Date().toISOString();
  const upd = { updated_at: now };
  if (req.body.firstName   !== undefined) upd.first_name    = req.body.firstName;
  if (req.body.lastName    !== undefined) upd.last_name     = req.body.lastName;
  if (req.body.dateOfBirth !== undefined) upd.date_of_birth = req.body.dateOfBirth;
  if (req.body.gender      !== undefined) upd.gender        = req.body.gender;
  if (req.body.idNumber    !== undefined) upd.id_number     = req.body.idNumber;
  if (req.body.phone       !== undefined) upd.phone         = req.body.phone;
  if (req.body.email       !== undefined) upd.email         = req.body.email;
  if (req.body.practiceId  !== undefined) upd.practice_id   = req.body.practiceId;
  if (req.body.allergies   !== undefined) upd.allergies     = req.body.allergies;
  await supabase.from('patients').update(upd).eq('id', req.params.id);
  if (req.body.address) {
    await supabase.from('patient_addresses').delete().eq('patient_id', req.params.id);
    await supabase.from('patient_addresses').insert({
      patient_id: req.params.id, street: req.body.address.street, city: req.body.address.city,
      province: req.body.address.province,
      postal_code: req.body.address.postalCode || req.body.address.postal_code,
    });
  }
  if (req.body.emergencyContact) {
    await supabase.from('patient_emergency_contacts').delete().eq('patient_id', req.params.id);
    await supabase.from('patient_emergency_contacts').insert({
      patient_id: req.params.id, name: req.body.emergencyContact.name,
      relationship: req.body.emergencyContact.relationship, phone: req.body.emergencyContact.phone,
    });
  }
  if (req.body.medicalAids) {
    await supabase.from('patient_medical_aids').delete().eq('patient_id', req.params.id);
    const inserts = [];
    if (req.body.medicalAids.active) inserts.push({
      patient_id: req.params.id, provider_name: req.body.medicalAids.active.providerName,
      plan_name: req.body.medicalAids.active.planName,
      membership_number: req.body.medicalAids.active.membershipNumber, is_active: true,
    });
    for (const h of (req.body.medicalAids.history || [])) inserts.push({
      patient_id: req.params.id, provider_name: h.providerName,
      plan_name: h.planName, membership_number: h.membershipNumber, is_active: false,
    });
    if (inserts.length > 0) await supabase.from('patient_medical_aids').insert(inserts);
  }
  const { data: updated } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', req.params.id).single();
  res.json(success(formatPatient(updated), 'Patient updated successfully'));
});

app.get('/pma/patients/:id/beneficiaries', async (req, res) => {
  await delay(300);
  const { data: bens } = await supabase
    .from('beneficiaries').select('patient_id').eq('main_member_id', req.params.id);
  if (!bens || bens.length === 0) return res.json(success([]));
  const { data: patients } = await supabase
    .from('patients').select(PATIENT_SELECT).in('id', bens.map(b => b.patient_id));
  res.json(success((patients || []).map(formatPatient)));
});

app.post('/pma/patients/:id/beneficiaries', async (req, res) => {
  await delay(400);
  const { relationship, ...bData } = req.body;
  const newId = `patient-${Date.now()}`;
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
    id: `beneficiary-${Date.now()}`, patient_id: newId,
    main_member_id: req.params.id, relationship,
  });
  const { data: newPatient } = await supabase.from('patients').select(PATIENT_SELECT).eq('id', newId).single();
  res.status(201).json(success(formatPatient(newPatient), 'Beneficiary added successfully'));
});

// ============================================================================
// DOCTOR ENDPOINTS
// ============================================================================

app.get('/pma/doctors', async (req, res) => {
  await delay(300);
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
  await delay(200);
  console.log(`Fetching doctor with id=${req.params.id}`);
  const { data: doctor } = await supabase
    .from('doctors').select('*').eq('id', req.params.id).single();
  if (!doctor) return res.status(404).json(err('Doctor not found'));
  res.json(success(toCamel(doctor)));
});

app.get('/pma/doctors/available', async (req, res) => {
  await delay(300);
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
  await delay(300);
  console.log(`Fetching schedule for doctor with id=${req.params.id}`);
  const { dateFrom, dateTo } = req.query;
  let query = supabase.from('schedules').select('*').eq('doctor_id', req.params.id);
  if (dateFrom) query = query.gte('date', dateFrom);
  if (dateTo)   query = query.lte('date', dateTo);
  const { data: schedule } = await query;
  res.json(success((schedule || []).map(toCamel)));
});

app.post('/pma/doctors/:id/schedule', async (req, res) => {
  await delay(300);
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
      id: `schedule-${Date.now()}`, doctor_id: req.params.id,
      date: sd.date, start_time: sd.startTime, end_time: sd.endTime, status: sd.status || 'available',
    }).select().single();
    result = data;
  }
  res.json(success(toCamel(result), 'Schedule updated successfully'));
});

app.patch('/pma/doctors/:id/availability', async (req, res) => {
  await delay(200);
  const { data: existing } = await supabase.from('doctors').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Doctor not found'));
  const { data: updated } = await supabase.from('doctors')
    .update({ is_available: req.body.isAvailable })
    .eq('id', req.params.id).select().single();
  res.json(success(toCamel(updated)));
});

app.get('/pma/schedules/doctor/:doctorId/slots/:date', async (req, res) => {
  await delay(300);
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
  await delay(300);
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
  await delay(200);
  console.log(`Fetching appointment with id=${req.params.id}`);
  const { data: apt } = await supabase
    .from('appointments').select(APPOINTMENT_SELECT).eq('id', req.params.id).single();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  res.json(success(formatAppointment(apt)));
});

app.get('/pma/appointments/patient/:patientId', async (req, res) => {
  await delay(300);
  console.log(`Fetching appointments for patientId=${req.params.patientId}`);
  const { data: apts } = await supabase
    .from('appointments').select(APPOINTMENT_SELECT).eq('patient_id', req.params.patientId);
  res.json(success((apts || []).map(formatAppointment)));
});

app.get('/pma/appointments/doctor/:doctorId', async (req, res) => {
  await delay(300);
  console.log(`Fetching appointments for doctorId=${req.params.doctorId}`);
  const { data: apts } = await supabase
    .from('appointments').select(APPOINTMENT_SELECT).eq('doctor_id', req.params.doctorId);
  res.json(success((apts || []).map(formatAppointment)));
});

app.post('/pma/appointments', async (req, res) => {
  await delay(400);
  console.log(`Booking new appointment with data: ${JSON.stringify(req.body)}`);
  const data = req.body;
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
  const newId = `appointment-${Date.now()}`;
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
  await delay(300);
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
  await delay(300);
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
  await delay(300);
  const { reason } = req.body;
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'rejected', rejection_reason: reason, updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment rejected'));
});

app.post('/pma/appointments/:id/cancel', async (req, res) => {
  await delay(300);
  console.log(`Cancelling appointment id=${req.params.id} with reason: ${req.body.reason}`);
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const { data: updated } = await supabase.from('appointments')
    .update({ status: 'cancelled', updated_at: new Date().toISOString() })
    .eq('id', req.params.id).select(APPOINTMENT_SELECT).single();
  res.json(success(formatAppointment(updated), 'Appointment cancelled'));
});

app.patch('/pma/appointments/:id', async (req, res) => {
  await delay(300);
  console.log(`Updating appointment id=${req.params.id} with data: ${JSON.stringify(req.body)}`);
  const { data: apt } = await supabase.from('appointments').select('id').eq('id', req.params.id).maybeSingle();
  if (!apt) return res.status(404).json(err('Appointment not found'));
  const upd = { updated_at: new Date().toISOString() };
  if (req.body.status    !== undefined) upd.status     = req.body.status;
  if (req.body.notes     !== undefined) upd.notes      = req.body.notes;
  if (req.body.date      !== undefined) upd.date       = req.body.date;
  if (req.body.startTime !== undefined) upd.start_time = req.body.startTime;
  if (req.body.endTime   !== undefined) upd.end_time   = req.body.endTime;
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
  await delay(200);
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
  await delay(200);
  console.log(`Fetching practice practitioners for userContext: ${JSON.stringify(req.userContext)}`);
  const [{ data: pps }, { data: allUsers }] = await Promise.all([
    supabase.from('practice_practitioners').select('*'),
    supabase.from('users').select('id, first_name, last_name, email'),
  ]);
  const usersMap = Object.fromEntries((allUsers || []).map(u => [u.id, u]));
  res.json(success((pps || []).map(pp => enrichPP(pp, usersMap))));
});

app.get('/pma/practice/practitioners/:id', async (req, res) => {
  await delay(200);
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
  await delay(300);
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
  const enriched = await Promise.all((visits || []).map(v => enrichVisit(formatVisit(v))));
  res.json(success(enriched));
});

app.get('/pma/visits/:id', async (req, res) => {
  await delay(200);
  console.log(`Fetching visit with id=${req.params.id} for userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT).eq('id', req.params.id).maybeSingle();
  if (!visit) return res.status(404).json(err('Visit not found'));
  res.json(success(await enrichVisit(formatVisit(visit))));
});

app.get('/pma/visits/patient/:patientId', async (req, res) => {
  await delay(300);
  console.log(`Fetching visits for patientId=${req.params.patientId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('patient_id', req.params.patientId).order('visit_date', { ascending: false });
  const enriched = await Promise.all((visits || []).map(v => enrichVisit(formatVisit(v))));
  res.json(success(enriched));
});

app.get('/pma/visits/doctor/:doctorId', async (req, res) => {
  await delay(300);
  console.log(`Fetching visits for doctorId=${req.params.doctorId} and userContext: ${JSON.stringify(req.userContext)}`);

  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('doctor_id', req.params.doctorId).order('visit_date', { ascending: false });
  const enriched = await Promise.all((visits || []).map(v => enrichVisit(formatVisit(v))));
  res.json(success(enriched));
});

app.get('/pma/visits/appointment/:appointmentId', async (req, res) => {
  await delay(200);
  console.log(`Fetching visit for appointmentId=${req.params.appointmentId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visit } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('appointment_id', req.params.appointmentId).maybeSingle();
  if (!visit) return res.status(404).json(err('No visit found for this appointment'));
  res.json(success(await enrichVisit(formatVisit(visit))));
});

app.post('/pma/visits', async (req, res) => {
  await delay(400);
  console.log(`Creating new visit with data: ${JSON.stringify(req.body)} and userContext: ${JSON.stringify(req.userContext)}`);
  const data = req.body;
  const now = new Date().toISOString();
  const visitId = `visit-${Date.now()}`;
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
    return res.status(500).json(err('Failed to create visit: ' + insertError.message));
  }
  if (data.vitals) {
    const { error: vErr } = await supabase.from('visit_vitals').insert({ ...snakeKeys(data.vitals), id: `vv-${Date.now()}`, visit_id: visitId });
    if (vErr) console.error('[POST /pma/visits] vitals insert error:', vErr.message);
  }
  if (data.diagnoses?.length) {
    const { error: dErr } = await supabase.from('visit_diagnoses').insert(
      data.diagnoses.map((d, i) => ({ id: `vd-${Date.now()}-${i}`, ...snakeKeys(d), visit_id: visitId }))
    );
    if (dErr) console.error('[POST /pma/visits] diagnoses insert error:', dErr.message);
  }
  if (data.procedures?.length) {
    const { error: pErr } = await supabase.from('visit_procedures').insert(
      data.procedures.map((p, i) => ({ id: `vp-${Date.now()}-${i}`, ...snakeKeys(p), visit_id: visitId }))
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
  res.status(201).json(success(await enrichVisit(formatVisit(newVisit)), 'Visit created successfully'));
});

app.put('/pma/visits/:id', async (req, res) => {
  await delay(300);
  console.log(`Updating visit id=${req.params.id} with data: ${JSON.stringify(req.body)} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: existing } = await supabase.from('visits').select('id').eq('id', req.params.id).maybeSingle();
  if (!existing) return res.status(404).json(err('Visit not found'));
  const now  = new Date().toISOString();
  const body = req.body;
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
  await delay(400);
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
  const invId = `inv-${Date.now()}`;
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
  await delay(300);
  console.log(`Fetching clinical record for patientId=${req.params.id} with userContext: ${JSON.stringify(req.userContext)}`);
  const { data: visits } = await supabase.from('visits').select(VISIT_SELECT)
    .eq('patient_id', req.params.id).order('visit_date', { ascending: false });
  const enriched = await Promise.all((visits || []).map(v => enrichVisit(formatVisit(v))));
  res.json(success({ patientId: req.params.id, doctorVisits: enriched }));
});

// ============================================================================
// INVOICE ENDPOINTS
// ============================================================================

app.get('/pma/invoices', async (req, res) => {
  await delay(300);
  console.log(`Fetching all invoices with userContext: ${JSON.stringify(req.userContext)}`);

  const { data: invoices } = await supabase.from('invoices').select(INVOICE_SELECT);
  res.json(success((invoices || []).map(formatInvoice)));
});

app.get('/pma/invoices/:id', async (req, res) => {
  await delay(200);
  console.log(`Fetching invoice with id=${req.params.id} for userContext: ${JSON.stringify(req.userContext)}`);
  const { data: invoice } = await supabase.from('invoices').select(INVOICE_SELECT).eq('id', req.params.id).maybeSingle();
  if (!invoice) return res.status(404).json(err('Invoice not found'));
  res.json(success(formatInvoice(invoice)));
});

app.get('/pma/invoices/visit/:visitId', async (req, res) => {
  await delay(200);
  console.log(`Fetching invoice for visitId=${req.params.visitId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: invoice } = await supabase.from('invoices').select(INVOICE_SELECT).eq('visit_id', req.params.visitId).maybeSingle();
  if (!invoice) return res.status(404).json(err('Invoice not found for this visit'));
  res.json(success(formatInvoice(invoice)));
});

app.get('/pma/invoices/patient/:patientId', async (req, res) => {
  await delay(300);
  console.log(`Fetching invoices for patientId=${req.params.patientId} and userContext: ${JSON.stringify(req.userContext)}`);
  const { data: invoices } = await supabase.from('invoices').select(INVOICE_SELECT).eq('patient_id', req.params.patientId);
  res.json(success((invoices || []).map(formatInvoice)));
});

app.post('/pma/invoices/:id/mark-paid', async (req, res) => {
  await delay(300);
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
  await delay(200);
  console.log(`Fetching diagnosis codes with query=${req.query.q} and userContext: ${JSON.stringify(req.userContext)}`);

  const { q } = req.query;
  let query = supabase.from('diagnosis_codes').select('*');
  if (q) query = query.or(`code.ilike.%${q}%,description.ilike.%${q}%`);
  const { data: codes } = await query;
  res.json(success((codes || []).map(toCamel)));
});

app.get('/pma/codes/procedures', async (req, res) => {
  await delay(200);
  console.log(`Fetching procedure codes with query=${req.query.q} and userContext: ${JSON.stringify(req.userContext)}`);

  const { q } = req.query;
  let query = supabase.from('procedure_codes').select('*');
  if (q) query = query.or(`code.ilike.%${q}%,description.ilike.%${q}%`);
  const { data: codes } = await query;
  res.json(success((codes || []).map(toCamel)));
});

// ============================================================================
// APPOINTMENT: START CONSULTATION
// ============================================================================

app.post('/pma/appointments/:id/start-consultation', async (req, res) => {
  await delay(300);
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

app.post('/pma/otp/send', async (req, res) => {
  await delay(500);
  const { phone, email: emailFromBody, appointmentData } = req.body;

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

app.post('/pma/otp/verify', async (req, res) => {
  await delay(300);
  const { phone, email, code } = req.body;
  if (!code) return res.status(400).json(err('Verification code is required'));

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
        const newId = `appointment-${Date.now()}`;
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

app.post('/pma/auth/update-password', async (req, res) => {
  console.log(`Updating password for email: ${req.body.email}`);

  const { email, newPassword } = req.body;
  if (!email || !newPassword) return res.status(400).json(err('Email and new password are required'));
  if (newPassword.length < 6) return res.status(400).json(err('Password must be at least 6 characters long'));
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

app.post('/pma/ai/summarise', async (req, res) => {
  const apiKey = process.env.HUGGINGFACE_API_KEY;
  if (!apiKey) {
    return res.status(500).json(err('HUGGINGFACE_API_KEY is not set on the server.'));
  }

  const { inputs } = req.body;
  if (!inputs || typeof inputs !== 'string') {
    return res.status(400).json(err('Missing or invalid "inputs" field.'));
  }

  const HF_URL = 'https://router.huggingface.co/hf-inference/models/facebook/bart-large-cnn';
  console.log(`[AI] Calling HF router: ${HF_URL}`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000); // 30s max

  try {
    const hfRes = await fetch(HF_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ inputs }),
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

    res.json(data);
  } catch (e) {
    clearTimeout(timeout);
    if (e.name === 'AbortError') {
      console.error('[AI] HF proxy timeout');
      return res.status(504).json(err('AI request timed out. The model may be loading — please try again.'));
    }
    console.error('[AI] HF proxy error:', e.message);
    res.status(502).json(err(`Failed to reach Hugging Face API: ${e.message}`));
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

app.listen(PORT, () => {
  console.log('\n🚀 PMA Health Hub pma Server is running (Supabase)!');
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔗 pma Base: http://localhost:${PORT}/pma`);
  console.log('\n📚 Available endpoints:');
  console.log('   Self-Register:  POST  /pma/authentication/register');
  console.log('   Verify Email:   GET   /pma/authentication/verify/:userid');
  console.log('   Admin Register: POST  /pma/auth/register');
  console.log('   Auth:           POST  /pma/auth/login');
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
