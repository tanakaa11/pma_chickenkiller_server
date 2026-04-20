// supabase.js
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '.env') });

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;

if (!supabaseUrl) throw new Error('SUPABASE_URL is not set. Add it to server22/server222/.env');
if (!supabaseKey) throw new Error('SUPABASE_SERVICE_KEY is not set. Add it to server22/server222/.env');

// Using the service role key with persistSession:false ensures RLS is bypassed
// for all server-side queries. Never expose this client or key to the browser.
export const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
  },
});