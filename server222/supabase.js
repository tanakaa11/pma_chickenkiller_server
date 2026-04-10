// supabase.js
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.SUPABASE_URL || 'https://zlapxdrkdgeuouywajzn.supabase.co';
const supabaseKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY ||
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpsYXB4ZHJrZGdldW91eXdhanpuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzE5ODA1NjgsImV4cCI6MjA4NzU1NjU2OH0.-XOockxSL8W5l67sT6z07Hp0iwCqiQmO05KzYiAAQn4';

export const supabase = createClient(supabaseUrl, supabaseKey);