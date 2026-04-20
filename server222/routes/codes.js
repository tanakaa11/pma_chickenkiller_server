import { Router } from 'express';
import { supabase } from '../supabase.js';
import { toCamel, success } from '../helpers/format.js';
import { sanitizeSearch } from '../utils/constants.js';

const router = Router();

// GET /pma/codes/diagnoses?q=
router.get('/diagnoses', async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('diagnosis_codes').select('*');
  if (q) { const sq = sanitizeSearch(q); query = query.or(`code.ilike.%${sq}%,description.ilike.%${sq}%`); }
  const { data: codes } = await query;
  res.json(success((codes || []).map(toCamel)));
});

// GET /pma/codes/procedures?q=
router.get('/procedures', async (req, res) => {
  const { q } = req.query;
  let query = supabase.from('procedure_codes').select('*');
  if (q) { const sq = sanitizeSearch(q); query = query.or(`code.ilike.%${sq}%,description.ilike.%${sq}%`); }
  const { data: codes } = await query;
  res.json(success((codes || []).map(toCamel)));
});

export default router;
