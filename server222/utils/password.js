import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;

export const hashPassword = async (plain) => {
  try { return await bcrypt.hash(plain, SALT_ROUNDS); }
  catch (e) { console.error('Password hashing error:', e); throw new Error('Failed to hash password'); }
};

export const verifyPassword = async (plain, hashed) => {
  try { return await bcrypt.compare(plain, hashed); }
  catch (e) { console.error('Password verification error:', e); return false; }
};
