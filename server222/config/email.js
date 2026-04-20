import nodemailer from 'nodemailer';
import { SMTP_USER, SMTP_PASS } from './env.js';

export const emailTransporter = (SMTP_USER && SMTP_PASS)
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    })
  : null;

if (emailTransporter) {
  console.log(`📧 Email transporter configured for ${SMTP_USER}`);
} else {
  console.log('📧 Email transporter NOT configured (set SMTP_USER and SMTP_APP_PASS to enable)');
}

/**
 * Fire-and-forget email helper. Silently no-ops when transporter is not configured.
 */
export const sendMailAsync = (opts, label = 'email') => {
  if (!emailTransporter) return;
  emailTransporter.sendMail(opts)
    .then(() => console.log(`✅ [EMAIL] ${label} sent to ${opts.to}`))
    .catch(e  => console.error(`❌ [EMAIL] Failed to send ${label} to ${opts.to}:`, e.message));
};
