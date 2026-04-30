import { z } from 'zod';

// ─── Primitive building blocks ───────────────────────────────────────────────
export const email   = z.string().trim().email().toLowerCase().max(254);
export const name    = z.string().trim().min(1).max(100);
export const pwd     = z.string().min(6).max(100);
export const roleId  = z.enum(['ROLE_SYSADMIN', 'ROLE_ADMIN', 'ROLE_PRACTITIONER']);
export const uiRole  = z.enum(['super_admin', 'doctor', 'reception', 'unlinked']);
export const isoDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Expected YYYY-MM-DD');
export const timeStr = z.string().regex(/^\d{2}:\d{2}$/, 'Expected HH:MM');

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const loginSchema = z.object({ email, password: pwd });

export const selfRegisterSchema = z.object({
  email, password: pwd, firstName: name, lastName: name,
});

export const adminRegisterSchema = z.object({
  email, password: pwd, firstName: name, lastName: name,
  roleId, practiceIds: z.array(z.string()).optional(),
});

export const setPasswordSchema = z.object({
  token: z.string().min(1).max(500), password: pwd,
});

export const updatePasswordSchema = z.object({ email, newPassword: pwd });

// ─── Users ────────────────────────────────────────────────────────────────────
export const createUserSchema = z.object({
  email, firstName: name, lastName: name, role: uiRole.optional(),
});

export const updateUserSchema = z.object({
  email: email.optional(), firstName: name.optional(), lastName: name.optional(),
  isActive: z.boolean().optional(), role: uiRole.optional(),
});

export const linkPracticeSchema = z.object({
  practiceId: z.string().min(1).max(100),
  roleId: roleId.optional(),
  force: z.boolean().optional(),
});

// ─── Admin ────────────────────────────────────────────────────────────────────
export const adminLinkSchema = z.object({
  email, practiceId: z.string().min(1).max(100), roleId,
  firstName: name.optional(), lastName: name.optional(), force: z.boolean().optional(),
});

export const sendInviteEmailSchema = z.object({
  email, inviteLink: z.string().url(),
  practiceName: z.string().max(200).optional(), firstName: name.optional(),
});

export const sendOtpAdminSchema = z.object({
  userId: z.string().min(1).max(100), practiceId: z.string().min(1).max(100),
});

export const createAndInviteSchema = z.object({
  email, firstName: name, lastName: name, roleId,
  practiceId: z.string().min(1).max(100), tempPassword: pwd.optional(),
});

export const verifyPracticeOtpSchema = z.object({
  otp: z.string().length(6).regex(/^\d+$/), userId: z.string().min(1).max(100),
});

// ─── Patients ─────────────────────────────────────────────────────────────────
const patientAddressSchema = z.object({
  street: z.string().max(200).optional(), city: z.string().max(100).optional(),
  province: z.string().max(100).optional(), postalCode: z.string().max(20).optional(),
  postal_code: z.string().max(20).optional(),
}).optional();

const emergencyContactSchema = z.object({
  name: z.string().max(100).optional(), relationship: z.string().max(50).optional(),
  phone: z.string().max(30).optional(),
}).optional();

export const createPatientSchema = z.object({
  firstName: name, lastName: name,
  dateOfBirth: isoDate.optional(), gender: z.string().max(20).optional(),
  idNumber: z.string().max(20).optional(), phone: z.string().max(30).optional(),
  email: email.optional().or(z.literal('')), practiceId: z.string().max(100).optional(),
  allergies: z.array(z.string()).optional(),
  address: patientAddressSchema, emergencyContact: emergencyContactSchema,
  medicalAids: z.any().optional(),
});

export const updatePatientSchema = createPatientSchema.partial();

export const beneficiarySchema = z.object({
  firstName: name, lastName: name,
  relationship: z.string().min(1).max(50),
  dateOfBirth: isoDate.optional(), gender: z.string().max(20).optional(),
  idNumber: z.string().max(20).optional(), phone: z.string().max(30).optional(),
  email: email.optional().or(z.literal('')), practiceId: z.string().max(100).optional(),
  allergies: z.array(z.string()).optional(),
  address: patientAddressSchema,
});

// ─── Appointments ─────────────────────────────────────────────────────────────
export const createAppointmentSchema = z.object({
  patientId: z.string().min(1).max(100), doctorId: z.string().min(1).max(100),
  practiceId: z.string().max(100).optional(), beneficiaryId: z.string().max(100).optional(),
  date: isoDate, startTime: timeStr, notes: z.string().max(2000).optional(),
});

export const patchAppointmentSchema = z.object({
  status: z.string().max(50).optional(), notes: z.string().max(2000).optional(),
  date: isoDate.optional(), startTime: timeStr.optional(), endTime: timeStr.optional(),
});

// ─── OTP ──────────────────────────────────────────────────────────────────────
export const otpSendSchema = z.object({
  phone: z.string().max(30).optional(),
  email: email.optional().or(z.literal('')),
  appointmentData: z.any().optional(),
});

export const otpVerifySchema = z.object({
  phone: z.string().max(30).optional(),
  email: email.optional().or(z.literal('')),
  code: z.string().length(6).regex(/^\d+$/),
});

// ─── Visits ───────────────────────────────────────────────────────────────────
export const createVisitSchema = z.object({
  appointmentId: z.string().max(100).optional(),
  patientId: z.string().min(1).max(100), doctorId: z.string().min(1).max(100),
  practicePractitionerId: z.string().max(100).optional(),
  reasonForVisit: z.string().max(2000).optional(),
  consultationNotes: z.string().max(10000).optional(),
  vitals: z.any().optional(), diagnoses: z.array(z.any()).optional(),
  procedures: z.array(z.any()).optional(), prescriptions: z.array(z.any()).optional(),
  clinicalDocuments: z.array(z.any()).optional(),
});

export const updateVisitSchema = createVisitSchema.partial();

// ─── Practices ────────────────────────────────────────────────────────────────
export const createPracticeSchema = z.object({
  name,
  userId: z.string().min(1).max(100),
  practiceNumber: z.string().min(1).max(50),
  address: z.string().max(300).optional().or(z.literal('')),
  phoneNumber: z.string().max(30).optional().or(z.literal('')),
});

export const updatePracticeSchema = z.object({
  name: name.optional(),
  userId: z.string().min(1).max(100).optional(),
  practiceNumber: z.string().min(1).max(50).optional(),
  address: z.string().max(300).optional().or(z.literal('')),
  phoneNumber: z.string().max(30).optional().or(z.literal('')),
});

// ─── Generic request validator ────────────────────────────────────────────────
export const validate = (schema, req, res) => {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    const message = result.error.issues
      .map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
    res.status(400).json({ success: false, message: `Invalid input: ${message}` });
    return null;
  }
  return result.data;
};
