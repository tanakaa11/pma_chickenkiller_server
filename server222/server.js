import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { PORT, CLIENT_URL, ALLOWED_ORIGINS, AMPLIFY_ORIGIN_REGEX } from './config/env.js';
import { addPracticeFilter } from './middleware/practice.js';

// Route modules
import authRouter      from './routes/auth.js';
import adminRouter     from './routes/admin.js';
import usersRouter     from './routes/users.js';
import patientsRouter  from './routes/patients.js';
import doctorsRouter   from './routes/doctors.js';
import schedulesRouter from './routes/schedules.js';
import appointmentsRouter from './routes/appointments.js';
import visitsRouter    from './routes/visits.js';
import practicesRouter from './routes/practices.js';
import practiceInfoRouter from './routes/practiceInfo.js';
import otpRouter       from './routes/otp.js';
import invoicesRouter  from './routes/invoices.js';
import codesRouter     from './routes/codes.js';
import aiRouter        from './routes/ai.js';

const app = express();

// ============================================================================
// SECURITY — helmet first, then cors
// ============================================================================
app.use(helmet({
  crossOriginResourcePolicy:  false,
  crossOriginOpenerPolicy:    false,
  crossOriginEmbedderPolicy:  false,
  contentSecurityPolicy:      false,
  originAgentCluster:         false,
}));

const corsMiddleware = cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    if (AMPLIFY_ORIGIN_REGEX.test(origin)) return callback(null, true);
    console.warn(`CORS blocked: ${origin}`);
    return callback(new Error(`CORS blocked: ${origin}`));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 'Authorization', 'X-Practice-Id',
    'Cache-Control', 'Pragma', 'Expires',
  ],
  credentials: false,
  optionsSuccessStatus: 204,
});
app.use(corsMiddleware);
app.options('*', corsMiddleware);

// ============================================================================
// BODY PARSING + COMMON MIDDLEWARE
// ============================================================================
app.use(express.json());

// Disable caching for all API responses
app.use((_req, res, next) => {
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Surrogate-Control': 'no-store',
  });
  next();
});

// Request logging
app.use((req, _res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ============================================================================
// HEALTH CHECK (no auth needed)
// ============================================================================
app.get('/health', (_req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// ============================================================================
// PRACTICE FILTER MIDDLEWARE (injects req.userContext)
// ============================================================================
app.use(addPracticeFilter);

// ============================================================================
// ROUTES
// ============================================================================
// Auth — mounted at both /pma/auth and /auth for legacy compatibility
app.use('/pma/auth', authRouter);
app.use('/auth',     authRouter);

// Admin registration also lives on /pma/auth/register
app.use('/pma/auth', adminRouter);

// Admin management endpoints
app.use('/pma/admin', adminRouter);

// Users
app.use('/pma/users', usersRouter);

// Patients
app.use('/pma/patients', patientsRouter);

// Doctors
app.use('/pma/doctors', doctorsRouter);

// Schedules (slot availability)
app.use('/pma/schedules', schedulesRouter);

// Appointments
app.use('/pma/appointments', appointmentsRouter);

// Visits
app.use('/pma/visits', visitsRouter);

// Practices (list/search/detail/members)
app.use('/pma/practices', practicesRouter);
app.use('/practices',     practicesRouter);

// Practice info (current practice context)
app.use('/pma/practice', practiceInfoRouter);

// OTP (guest appointment booking)
app.use('/pma/otp', otpRouter);

// Invoices
app.use('/pma/invoices', invoicesRouter);

// Diagnosis & procedure codes
app.use('/pma/codes', codesRouter);

// AI proxy
app.use('/pma/ai', aiRouter);

// ============================================================================
// ERROR HANDLERS
// ============================================================================
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((error, _req, res, _next) => {
  console.error('Server error:', error);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ============================================================================
// START SERVER
// ============================================================================
export const startServer = () => {
  const server = app.listen(PORT, () => {
    console.log('\n🚀 PMA Health Hub Server running!');
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log(`🌐 Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
    console.log('\n📚 Key endpoints:');
    console.log('   Auth:         POST /pma/auth/login');
    console.log('   Refresh:      POST /pma/auth/refresh');
    console.log('   Patients:     GET  /pma/patients');
    console.log('   Appointments: GET  /pma/appointments');
    console.log('   Visits:       GET  /pma/visits');
    console.log('   Invoices:     GET  /pma/invoices');
    console.log('   Health:       GET  /health');
    console.log('\n✅ Connected to Supabase\n');
  });

  const gracefulShutdown = (signal) => {
    console.log(`\n${signal} received — shutting down gracefully`);
    server.close(() => { console.log('✅ Server closed gracefully'); process.exit(0); });
    setTimeout(() => { console.error('⚠️  Force exit after timeout'); process.exit(1); }, 10_000).unref();
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT',  () => gracefulShutdown('SIGINT'));

  return server;
};

export default app;
