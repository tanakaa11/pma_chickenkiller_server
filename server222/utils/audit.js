import { supabase } from '../supabase.js';

export const logAudit = (req, action, resourceId) => {
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
