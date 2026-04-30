import { verifyToken } from '../config/jwt.js';
import { err } from '../helpers/format.js';

export const addPracticeFilter = async (req, res, next) => {
  const skipPaths = [
    '/auth/', '/pma/auth/', '/api/auth/',
    '/practices', '/pma/practices', '/api/practices',
    '/users/check-email', '/pma/users/check-email', '/api/users/check-email',
    '/admin/', '/pma/admin/', '/api/admin/',
    '/pma/otp/',
    '/pma/doctors',
    '/pma/schedules/',
    '/pma/patients/search',
    '/pma/patients/id-number/',
  ];

  // Allow POST /pma/patients for patient mode (creating patient files without practice context)
  if (req.method === 'POST' && req.path === '/pma/patients') {
    return next();
  }

  if (skipPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json(err('Authentication required'));
  }

  const payload = verifyToken(authHeader.replace('Bearer ', ''));
  if (!payload) {
    return res.status(401).json(err('Invalid or expired token. Please log in again.'));
  }

  const { userId, role, practiceIds: tokenPracticeIds = [], isSuperAdmin, isSuperSuperAdmin } = payload;

  const userProfilePaths = [
    `/users/${userId}/my-practice`, `/pma/users/${userId}/my-practice`, `/api/users/${userId}/my-practice`,
    `/users/${userId}/my-practices`, `/pma/users/${userId}/my-practices`, `/api/users/${userId}/my-practices`,
    `/users/${userId}`, `/pma/users/${userId}`, `/api/users/${userId}`,
  ];
  if (userProfilePaths.some(path => req.path === path)) {
    req.userContext = { userId, practiceId: null, isSuperAdmin, isSuperSuperAdmin };
    return next();
  }

  if (isSuperSuperAdmin) {
    const headerPracticeId = req.headers['x-practice-id'] || null;
    req.userContext = { userId, practiceId: headerPracticeId, isSuperAdmin: true, isSuperSuperAdmin: true };
    return next();
  }

  const linkedPracticeIds = new Set(tokenPracticeIds);
  const headerPracticeId  = req.headers['x-practice-id'] || null;
  const practiceId = (headerPracticeId && linkedPracticeIds.has(headerPracticeId))
    ? headerPracticeId
    : (linkedPracticeIds.size > 0 ? [...linkedPracticeIds][0] : null);

  if (!practiceId) {
    return res.status(403).json(err('User is not linked to any practice'));
  }

  req.userContext = {
    userId, practiceId,
    isSuperAdmin: isSuperAdmin || false,
    isSuperSuperAdmin: false,
    linkedPracticeIds: [...linkedPracticeIds],
  };
  next();
};
