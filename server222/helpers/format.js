// ─── Case conversion ──────────────────────────────────────────────────────────
export const toCamel = (obj) => {
  if (Array.isArray(obj)) return obj.map(toCamel);
  if (obj !== null && obj !== undefined && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [
        k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()), toCamel(v),
      ])
    );
  }
  return obj;
};

export const snakeKeys = (obj) => {
  if (Array.isArray(obj)) return obj.map(snakeKeys);
  if (obj !== null && obj !== undefined && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [
        k.replace(/([A-Z])/g, (c) => `_${c.toLowerCase()}`), snakeKeys(v),
      ])
    );
  }
  return obj;
};

// ─── Response helpers ─────────────────────────────────────────────────────────
export const success = (data, message) => ({ success: true, data, message });
export const err = (message) => ({ success: false, error: message });

// ─── Patient ──────────────────────────────────────────────────────────────────
export const PATIENT_SELECT = `*, patient_addresses(*), patient_emergency_contacts(*), patient_medical_aids(*)`;

export const formatPatient = (p) => {
  if (!p) return null;
  const { patient_addresses, patient_emergency_contacts, patient_medical_aids, ...core } = p;
  const addr = patient_addresses?.[0] || {};
  const ec   = patient_emergency_contacts?.[0] || {};
  const activeAid   = patient_medical_aids?.find(m => m.is_active);
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

// ─── User ─────────────────────────────────────────────────────────────────────
export const USER_SELECT = `*, user_roles(*), user_practices(*)`;

export const formatUser = (u) => {
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

// ─── Invoice ──────────────────────────────────────────────────────────────────
export const INVOICE_SELECT = `*, invoice_line_items(*)`;

export const formatInvoice = (inv) => {
  if (!inv) return null;
  const { invoice_line_items, ...core } = inv;
  return {
    ...toCamel(core),
    lineItems: (invoice_line_items || []).map(item => ({
      referenceCode: item.reference_code, description: item.description, amount: item.amount,
    })),
  };
};

// ─── Appointment ──────────────────────────────────────────────────────────────
export const APPOINTMENT_SELECT = `*, patients!patient_id(*), doctors!doctor_id(*)`;

export const formatAppointment = (a) => {
  if (!a) return null;
  const { patients, doctors, ...core } = a;
  return {
    ...toCamel(core),
    patient: patients ? toCamel(patients) : undefined,
    doctor:  doctors  ? toCamel(doctors)  : undefined,
  };
};

// ─── Visit ────────────────────────────────────────────────────────────────────
export const VISIT_SELECT = `*, visit_vitals(*), visit_diagnoses(*), visit_procedures(*), visit_prescriptions(*), visit_clinical_documents(*)`;

export const formatVisit = (v) => {
  if (!v) return null;
  const {
    visit_vitals, visit_diagnoses, visit_procedures,
    visit_prescriptions, visit_clinical_documents, ...core
  } = v;
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

// ─── Practice practitioner ────────────────────────────────────────────────────
export const enrichPP = (pp, usersMap) => {
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
