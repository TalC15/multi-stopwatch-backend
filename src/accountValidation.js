// Account provisioning is a superadmin action. Existing PINs remain usable at login.
export const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const validUsername = value => typeof value === 'string' &&
  value === value.trim() && value.length >= 1 && value.length <= 25 && !/[\x00-\x1f\x7f]/.test(value);
export const validNewPin = value => typeof value === 'string' &&
  value.trim().length >= 6 && value.length <= 25 && Buffer.byteLength(value, 'utf8') <= 72;
export const validRole = value => ['worker', 'manager', 'superadmin'].includes(value);
export const validWorkspace = value => value === null || (typeof value === 'string' && uuidPattern.test(value));
