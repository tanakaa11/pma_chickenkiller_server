import { Router } from 'express';
import { supabase } from '../supabase.js';
import { toCamel, success, err } from '../helpers/format.js';

const router = Router();

const requireAdmin = (req, res, next) => {
  const { isSuperAdmin, isSuperSuperAdmin } = req.userContext || {};
  if (!isSuperAdmin && !isSuperSuperAdmin) {
    return res.status(403).json({ success: false, message: 'Forbidden: admin access required' });
  }
  next();
};

// GET /pma/audit-logs
router.get('/', requireAdmin, async (req, res) => {
  const { action, userId, dateFrom, dateTo } = req.query;

  let query = supabase
    .from('audit_logs')
    .select('id, user_id, action, resource_id, ip_address, created_at')
    .order('created_at', { ascending: false })
    .limit(500);

  if (action)   query = query.eq('action', action);
  if (userId)   query = query.eq('user_id', userId);
  if (dateFrom) query = query.gte('created_at', new Date(dateFrom).toISOString());
  if (dateTo) {
    const end = new Date(dateTo);
    end.setHours(23, 59, 59, 999);
    query = query.lte('created_at', end.toISOString());
  }

  const { data, error } = await query;
  if (error) return res.status(500).json(err('Failed to fetch audit logs'));

  res.json(success((data || []).map(toCamel)));
});

export default router;
