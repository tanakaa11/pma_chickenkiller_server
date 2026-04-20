import { Router } from 'express';
import { supabase } from '../supabase.js';
import { success, err } from '../helpers/format.js';

const router = Router();

const TIME_SLOTS = ['08:00','08:30','09:00','09:30','10:00','10:30','11:00','11:30','12:00','12:30','13:00','13:30','14:00','14:30','15:00','15:30','16:00','16:30','17:00'];

// GET /pma/schedules/doctor/:doctorId/slots/:date
router.get('/doctor/:doctorId/slots/:date', async (req, res) => {
  const { doctorId, date } = req.params;
  const [{ data: doctorSchedule }, { data: booked }] = await Promise.all([
    supabase.from('schedules').select('*').eq('doctor_id', doctorId).eq('date', date),
    supabase.from('appointments').select('start_time, end_time').eq('doctor_id', doctorId).eq('date', date).in('status', ['pending_reception', 'confirmed']),
  ]);
  const now = new Date();
  const isToday = new Date(date).toDateString() === now.toDateString();
  const currentTime = isToday ? now.toTimeString().substring(0, 5) : null;
  const slots = TIME_SLOTS.map((time, index) => {
    const nextTime = TIME_SLOTS[index + 1] || '17:30';
    const matchingSchedule = (doctorSchedule || []).find(s => s.start_time <= time && s.end_time > time);
    const isBooked = (booked || []).some(a => a.start_time === time || (a.start_time <= time && a.end_time > time));
    const isPast = isToday && currentTime && time < currentTime;
    const isAvailable = (matchingSchedule?.status === 'available' || !matchingSchedule) && !isBooked && !isPast;
    return {
      id: `slot-${time}`, startTime: time, endTime: nextTime, isAvailable,
      status: isBooked ? 'booked' : (isPast ? 'past' : (matchingSchedule?.status || 'available')),
      reason: isBooked ? 'Already booked' : (isPast ? 'Time has passed' : null),
    };
  });
  res.json(success(slots));
});

export default router;
