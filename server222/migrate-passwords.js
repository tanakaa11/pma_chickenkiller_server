/**
 * One-time migration: hash all remaining plaintext passwords in the users table.
 *
 * Run ONCE:
 *   node migrate-passwords.js
 *
 * Safe to run multiple times — already-hashed passwords (starting with $2b$)
 * are skipped automatically.
 */

import dotenv from 'dotenv';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import { createClient } from '@supabase/supabase-js';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(__dirname, '.env') });

const SALT_ROUNDS = 12;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

async function run() {
  console.log('🔍 Fetching users with unhashed passwords...');

  const { data: users, error } = await supabase
    .from('users')
    .select('id, email, password')
    .not('password', 'is', null);

  if (error) {
    console.error('❌ Failed to fetch users:', error.message);
    process.exit(1);
  }

  const plaintext = users.filter(u => u.password && !u.password.startsWith('$2b$'));
  console.log(`Found ${plaintext.length} user(s) with plaintext passwords.`);

  if (plaintext.length === 0) {
    console.log('✅ Nothing to do — all passwords are already hashed.');
    return;
  }

  let updated = 0;
  let failed = 0;

  for (const user of plaintext) {
    try {
      const hashed = await bcrypt.hash(user.password, SALT_ROUNDS);
      const { error: updateErr } = await supabase
        .from('users')
        .update({ password: hashed })
        .eq('id', user.id);

      if (updateErr) {
        console.error(`  ❌ Failed to update ${user.email}:`, updateErr.message);
        failed++;
      } else {
        console.log(`  ✅ Hashed password for ${user.email}`);
        updated++;
      }
    } catch (e) {
      console.error(`  ❌ Error processing ${user.email}:`, e.message);
      failed++;
    }
  }

  console.log(`\nDone. Updated: ${updated}, Failed: ${failed}`);
  if (failed > 0) process.exit(1);
}

run();
