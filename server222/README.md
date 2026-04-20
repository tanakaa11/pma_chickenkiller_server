# PMA Health Hub — Server

Express.js REST API server for PMA Health Hub. Uses Supabase (PostgreSQL) as the database, JWT for auth, and Nodemailer (Gmail SMTP) for emails.

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Copy the env template and fill in your values
cp .env.example .env   # (or create .env manually — see env vars below)

# 3. Start the server (uses the monolithic index.js)
npm start              # node index.js

# 4. Or start using the new modular entry point
node server-new.js
```

Server runs on **http://localhost:5000** by default.

---

## Required Environment Variables

Create a `.env` file in this folder:

```env
# Required — server will exit on startup without this
JWT_SECRET=your_super_secret_key

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key

# Email (Gmail SMTP) — optional, disables email features if missing
SMTP_USER=youremail@gmail.com
SMTP_APP_PASS=your_gmail_app_password

# Frontend URL — used in invite/verification links
CLIENT_URL=http://localhost:5173

# Port (optional, defaults to 5000)
PORT=5000

# AI summarisation (optional)
HUGGINGFACE_API_KEY=hf_...
```

---

## Project Structure

```
server222/
├── index.js              ← Original monolithic server (2200+ lines) — still works
├── server-new.js         ← New thin entry point  →  imports server.js
├── server.js             ← Express app wiring (use this going forward)
├── supabase.js           ← Supabase client singleton
│
├── config/               ← Env + service configuration
│   ├── env.js            ← Loads .env, exports PORT / CLIENT_URL / ALLOWED_ORIGINS
│   ├── db.js             ← Re-exports supabase from ../supabase.js
│   ├── jwt.js            ← JWT_EXPIRY, signToken(), verifyToken(), hashToken()
│   └── email.js          ← Nodemailer transporter + sendMailAsync()
│
├── utils/                ← Pure helpers, no Express dependencies
│   ├── validation.js     ← All Zod schemas + validate(schema, req, res)
│   ├── constants.js      ← ROLE_MAP, ROLE_NAMES, ROLE_UI_MAP, withTimeout(), sanitizeSearch()
│   ├── password.js       ← hashPassword(), verifyPassword()  (bcrypt)
│   ├── jwt.js            ← Re-exports from config/jwt.js
│   └── audit.js          ← logAudit(req, action, resourceId) — writes to audit_logs table
│
├── helpers/              ← Data formatting tied to Supabase shapes
│   ├── format.js         ← toCamel(), snakeKeys(), success(), err()
│   │                        SELECT constants: PATIENT_SELECT, USER_SELECT, etc.
│   │                        Formatters: formatPatient(), formatUser(), formatVisit(), etc.
│   │                        enrichPP() — enriches practice_practitioners rows
│   └── enrichment.js     ← enrichVisit(), enrichVisitsBatch() — async, reads Supabase
│
├── middleware/           ← Express middleware functions
│   ├── practice.js       ← addPracticeFilter — reads X-Practice-Id header,
│   │                        verifies JWT, injects req.userContext
│   └── auth.js           ← meHandler — GET /auth/me response handler
│
└── routes/               ← One file per resource domain
    ├── auth.js           ← /pma/auth/* — login, logout, refresh, register, set-password
    ├── admin.js          ← /pma/admin/* + /pma/auth/register — user creation, invites, OTP admin
    ├── users.js          ← /pma/users/* — CRUD, toggle-active, link-practice, my-practice(s)
    ├── patients.js       ← /pma/patients/* — CRUD, search, id-number lookup, beneficiaries
    ├── doctors.js        ← /pma/doctors/* — list, availability, schedule CRUD
    ├── schedules.js      ← /pma/schedules/* — slot availability grid
    ├── appointments.js   ← /pma/appointments/* — full booking workflow
    ├── visits.js         ← /pma/visits/* — clinical visits + invoice generation on complete
    ├── practices.js      ← /pma/practices/* — list, search, detail, doctors, members, verify-otp
    ├── practiceInfo.js   ← /pma/practice/* — current-practice info and practitioners
    ├── invoices.js       ← /pma/invoices/* — CRUD + mark-paid
    ├── codes.js          ← /pma/codes/* — diagnosis and procedure code search
    ├── otp.js            ← /pma/otp/* — guest appointment booking OTP (in-memory store)
    └── ai.js             ← /pma/ai/* — HuggingFace BART summarisation proxy
```

---

## How Routing Works

All routes are prefixed with `/pma/`. Some auth endpoints are also available without the prefix for legacy compatibility (e.g. `/auth/login` = `/pma/auth/login`).

| Prefix | Router file |
|---|---|
| `/pma/auth` | `routes/auth.js` + `routes/admin.js` |
| `/pma/admin` | `routes/admin.js` |
| `/pma/users` | `routes/users.js` |
| `/pma/patients` | `routes/patients.js` |
| `/pma/doctors` | `routes/doctors.js` |
| `/pma/schedules` | `routes/schedules.js` |
| `/pma/appointments` | `routes/appointments.js` |
| `/pma/visits` | `routes/visits.js` |
| `/pma/practices` | `routes/practices.js` |
| `/pma/practice` | `routes/practiceInfo.js` |
| `/pma/invoices` | `routes/invoices.js` |
| `/pma/codes` | `routes/codes.js` |
| `/pma/otp` | `routes/otp.js` |
| `/pma/ai` | `routes/ai.js` |

---

## All Responses Follow This Shape

```json
{ "success": true,  "data": { ... } }
{ "success": false, "message": "Human-readable error" }
```

Use the helpers from `helpers/format.js`:

```js
import { success, err } from '../helpers/format.js';

res.json(success(data));           // { success: true, data }
res.json(success(data, 'Created')); // { success: true, data, message }
res.status(404).json(err('Not found')); // { success: false, message: 'Not found' }
```

---

## How to Add a New Endpoint

### Step 1 — Add it to the right route file

Open the relevant file in `routes/`. Each file exports a single Express `Router`.

```js
// Example: adding GET /pma/patients/:id/summary to routes/patients.js

import { success, err, PATIENT_SELECT, formatPatient } from '../helpers/format.js';
import { supabase } from '../supabase.js';

router.get('/:id/summary', async (req, res) => {
  const { data: p } = await supabase
    .from('patients')
    .select(PATIENT_SELECT)
    .eq('id', req.params.id)
    .single();

  if (!p) return res.status(404).json(err('Patient not found'));
  res.json(success(formatPatient(p)));
});
```

### Step 2 — Add a Zod schema if the endpoint accepts a body

Open `utils/validation.js` and add your schema, then import and use `validate()` in your handler:

```js
// utils/validation.js
export const createSummarySchema = z.object({
  title: z.string().min(1).max(200),
});

// routes/patients.js
import { validate, createSummarySchema } from '../utils/validation.js';

router.post('/:id/summary', async (req, res) => {
  const data = validate(createSummarySchema, req, res);
  if (!data) return; // validate() already sent a 400 response
  // ... continue
});
```

### Step 3 — Add formatters for new tables (if needed)

If you're querying a new Supabase table, add the SELECT string and formatter to `helpers/format.js`:

```js
// helpers/format.js
export const NOTE_SELECT = 'id, patient_id, content, created_at';

export const formatNote = (n) => ({
  id: n.id,
  patientId: n.patient_id,
  content: n.content,
  createdAt: n.created_at,
});
```

### Step 4 — Register a new router in server.js (new domain only)

Only needed if you're creating a **completely new route file**. Open `server.js` and add:

```js
import myNewRouter from './routes/myNew.js';
// ...
app.use('/pma/mynew', myNewRouter);
```

---

## Multi-Tenancy (Practice Scoping)

Most endpoints are automatically scoped to a practice via the `addPracticeFilter` middleware, which runs before every route. It reads the `X-Practice-Id` header and the JWT, then injects:

```js
req.userContext = {
  userId,
  practiceId,     // from X-Practice-Id header
  isSuperAdmin,   // true if role is ROLE_SYSADMIN
  isSuperSuperAdmin, // true if role is 'super_super_admin'
}
```

In your route handlers, scope queries using it:

```js
const { practiceId, isSuperAdmin } = req.userContext || {};
if (!isSuperAdmin && practiceId) {
  query = query.eq('practice_id', practiceId);
}
```

---

## Auth Flow

1. `POST /pma/auth/login` → returns `{ token, refreshToken, user }`
2. JWT access tokens expire in **15 minutes**
3. `POST /pma/auth/refresh` with `{ refreshToken }` → returns a new `{ token }`
4. Refresh tokens are SHA-256 hashed and stored in the `refresh_tokens` table (7-day TTL)
5. `POST /pma/auth/logout` deletes the refresh token from the DB

---

## Role System

| `user.role` (DB) | `roleId` (user_roles table) | Meaning |
|---|---|---|
| `super_super_admin` | — | Full system access, sees all practices |
| `super_admin` | `ROLE_SYSADMIN` | System administrator |
| `doctor` | `ROLE_PRACTITIONER` | Practitioner — also has a `doctors` row |
| `reception` | `ROLE_ADMIN` | Practice staff |
| `unlinked` | — | Registered but not linked to any practice yet |

`ROLE_MAP`, `ROLE_NAMES`, and `ROLE_UI_MAP` in `utils/constants.js` are the single source of truth for mapping between these values.

---

## Switching to the Modular Server

The original `index.js` is still the active entry point (`npm start`). The new modular files are ready but the switch hasn't been made yet. To switch:

```bash
# Option A — update package.json scripts
#   "start": "node server-new.js"

# Option B — rename files
mv index.js index.legacy.js
mv server-new.js index.js
```

Both produce identical behaviour. The modular version is easier to maintain.

## Available Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user

### Users
- `GET /api/users` - List all users (with pagination)
- `GET /api/users/:id` - Get user by ID
- `GET /api/users/role/:role` - Get users by role
- `POST /api/users` - Create new user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user
- `PATCH /api/users/:id/toggle-active` - Toggle user active status

### Patients
- `GET /api/patients` - List all patients (with pagination & filters)
- `GET /api/patients?ids=pat-1,pat-2` - **Batch lookup** by IDs (for efficient joins)
- `GET /api/patients/:id` - Get patient by ID
- `GET /api/patients/id-number/:idNumber` - Get patient by ID number
- `GET /api/patients/search?q=...` - Search patients
- `POST /api/patients` - Create new patient
- `PUT /api/patients/:id` - Update patient
- `GET /api/patients/:id/beneficiaries` - Get patient beneficiaries
- `POST /api/patients/:id/beneficiaries` - Add beneficiary

### Doctors
- `GET /api/doctors` - List all doctors
- `GET /api/doctors?ids=doc-1,doc-2` - **Batch lookup** by IDs (for efficient joins)
- `GET /api/doctors/:id` - Get doctor by ID
- `GET /api/doctors/available?date=...&time=...` - Get available doctors
- `GET /api/doctors/:id/schedule` - Get doctor schedule
- `POST /api/doctors/:id/schedule` - Update doctor schedule
- `PATCH /api/doctors/:id/availability` - Set doctor availability

### Appointments
- `GET /api/appointments` - List appointments (with filters)
- `GET /api/appointments?lean=true` - **Lean mode** - returns just IDs, no enrichment (recommended for calendars!)
- `GET /api/appointments/:id` - Get appointment by ID
- `GET /api/appointments/patient/:patientId` - Get patient appointments
- `GET /api/appointments/doctor/:doctorId` - Get doctor appointments
- `POST /api/appointments` - Create new appointment
- `POST /api/appointments/:id/approve-reception` - Approve by reception
- `POST /api/appointments/:id/approve-doctor` - Approve by doctor
- `POST /api/appointments/:id/reject` - Reject appointment
- `POST /api/appointments/:id/cancel` - Cancel appointment
- `PATCH /api/appointments/:id` - Update appointment

### Schedules
- `GET /api/schedules/doctor/:doctorId/slots/:date` - Get available time slots

## 🚀 Performance Optimization: Lean Mode

### The Problem
By default, appointments are "enriched" with full patient/doctor objects:
```json
{
  "id": "apt-1",
  "patient": { "id": "pat-1", "name": "...", "phone": "...", ... },
  "doctor": { "id": "doc-1", "name": "...", "email": "...", ... }
}
```

For calendars with many appointments, this creates **massive payloads with duplicate data**.

### The Solution: Lean Mode + Batch Lookups

**Step 1:** Fetch appointments with `lean=true`
```bash
GET /api/appointments?lean=true&dateFrom=2026-01-01&dateTo=2026-01-31
```

Returns minimal data (just IDs):
```json
{
  "success": true,
  "data": [
    {
      "id": "apt-1",
      "patientId": "pat-1",
      "doctorId": "doc-1",
      "date": "2026-01-15",
      "startTime": "09:00"
    }
  ]
}
```

**Step 2:** Batch lookup patients/doctors
```bash
GET /api/patients?ids=pat-1,pat-2,pat-3
GET /api/doctors?ids=doc-1,doc-2
```

**Benefits:**
- ⚡ 60-80% smaller payloads
- 🚀 3x faster on mobile
- 💾 Cacheable patient/doctor data
- 🎯 Fetch only what you need

See [CALENDAR_DATA_GUIDE.md](../CALENDAR_DATA_GUIDE.md) for implementation details.

## Response Format

All endpoints return responses in this format:

### Success
```json
{
  "success": true,
  "data": { ... },
  "message": "Optional success message"
}
```

### Error
```json
{
  "success": false,
  "error": "Error message"
}
```

## Test Data

The server comes with pre-populated test data:

- **Users**: Admin, 2 Doctors, 1 Reception, 1 Patient
- **Patients**: 3 test patients
- **Doctors**: 2 test doctors
- **Appointments**: 3 test appointments
- **Schedules**: 4 test schedule blocks

### Test Credentials

```
Email: admin@pma.co.za
Password: any password (not validated in mock)

Email: dr.smith@pma.co.za
Password: any password

Email: reception@pma.co.za
Password: any password
```

## Modifying Data

The mock data is stored in `mockData.js`. Changes made via API calls are stored in memory and will be lost when the server restarts.

To persist changes, you would need to:
1. Add a database (e.g., MongoDB, PostgreSQL)
2. Replace the in-memory arrays with database queries
3. Update the server code to use the database

## Development

The server uses:
- **Express.js** - Web framework
- **cors** - CORS middleware
- **Node.js** - Runtime

No build step required - just run with Node.js!

## Logging

All requests are logged to the console:
```
2026-01-28T10:30:45.123Z - GET /api/users
2026-01-28T10:30:46.456Z - POST /api/auth/login
```

## Error Handling

- 404 for unknown endpoints
- 401 for authentication errors
- 400 for validation errors
- 500 for server errors

## Network Delays

The server simulates realistic network delays (200-400ms) to mimic real API behavior.

## Next Steps

When building your production API:

1. **Use this as a reference** - All endpoints are documented and implemented
2. **Match the response format** - Frontend expects `{ success, data, error }`
3. **Keep endpoint paths** - URLs match `src/api/endpoints.tsx`
4. **Add authentication** - Implement proper JWT verification
5. **Add database** - Replace in-memory data with persistent storage
6. **Add validation** - Validate request bodies properly
7. **Add security** - Rate limiting, CORS restrictions, etc.

## Troubleshooting

### Port Already in Use
If port 3000 is taken, edit `server/index.js`:
```javascript
const PORT = 3001; // Change to different port
```

Then update `.env` in frontend:
```
VITE_API_BASE_URL=http://localhost:3001/api
```

### CORS Issues
The server allows all origins by default. In production, restrict CORS:
```javascript
app.use(cors({
  origin: 'https://your-frontend-domain.com',
  credentials: true
}));
```

### Server Won't Start
Make sure you installed dependencies:
```bash
cd server
npm install
```

---

**Ready to integrate?** Just update `VITE_API_BASE_URL` in `.env` to your production API URL!
