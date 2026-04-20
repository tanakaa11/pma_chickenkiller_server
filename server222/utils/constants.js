// Role mappings shared across routes
export const ROLE_MAP = {
  'ROLE_SYSADMIN':     { roleName: 'SystemAdministrator/ admin',      uiRole: 'super_admin' },
  'ROLE_ADMIN':        { roleName: 'PracticeAdministrator/ reception', uiRole: 'reception'   },
  'ROLE_PRACTITIONER': { roleName: 'PracticePractitioner / doctor',    uiRole: 'doctor'      },
};

export const ROLE_NAMES = {
  'ROLE_SYSADMIN':     'SystemAdministrator',
  'ROLE_ADMIN':        'PracticeAdministrator',
  'ROLE_PRACTITIONER': 'PracticePractitioner',
};

export const ROLE_UI_MAP = {
  'ROLE_ADMIN':        'reception',
  'ROLE_PRACTITIONER': 'doctor',
  'ROLE_SYSADMIN':     'super_admin',
};

export const withTimeout = (promise, ms = 8000) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Database request timed out')), ms)
    ),
  ]);

export const sanitizeSearch = (s) => String(s || '').replace(/[%,()\\]/g, '').slice(0, 100);
