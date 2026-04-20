import { supabase } from '../supabase.js';
import { PATIENT_SELECT, INVOICE_SELECT, formatPatient, formatInvoice, toCamel } from './format.js';

export const enrichVisit = async (visit) => {
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

export const enrichVisitsBatch = async (formattedVisits) => {
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
