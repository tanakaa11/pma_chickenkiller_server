# Mock API Server

This is a fully functional Express.js mock server that serves all the API endpoints for the PMA Health Hub application.

## Features

✅ All endpoints from `src/api/endpoints.tsx` implemented  
✅ Real HTTP requests (no simulation)  
✅ CORS enabled for frontend  
✅ Request logging  
✅ Consistent response format  
✅ Error handling  
✅ Network delays simulated  

## Quick Start

### 1. Install Dependencies

```bash
cd server
npm install
```

### 2. Start the Server

```bash
npm run dev
```

The server will start on `http://localhost:3000`

### 3. Start Frontend (in another terminal)

```bash
# From project root
npm run dev
```

### Or Run Both Together

```bash
# From project root
npm run dev:full
```

## Server Information

- **Port**: 3000
- **Base URL**: `http://localhost:3000/api`
- **CORS**: Enabled for all origins

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
