// supabase.js
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '.env') });

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl) console.error('❌ SUPABASE_URL is not set — database calls will fail');
if (!supabaseKey) console.error('❌ SUPABASE_SERVICE_KEY is not set — database calls will fail');

// Create a placeholder client even if env vars are missing so the server can start.
// Requests that use Supabase will fail at runtime, but the process won't crash on startup.
export const supabase = (supabaseUrl && supabaseKey)
  ? createClient(supabaseUrl, supabaseKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    })
  : null;