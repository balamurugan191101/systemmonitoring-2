const ROLES = Object.freeze(['Super Admin', 'Admin', 'IT Engineer', 'Viewer']);
const normalizeLogin = (value) => String(value || '').trim().toLowerCase();
function validPassword(password) {
  return typeof password === 'string' && password.length >= 12 && password.length <= 128 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /[0-9]/.test(password);
}
function mayViewComputer(role, grants, computerId) {
  return role === 'Super Admin' || (ROLES.includes(role) && grants.includes(computerId));
}
function mayAdministerUsers(role) { return role === 'Super Admin'; }
function mayReviewAudit(role) { return role === 'Super Admin'; }
module.exports = { ROLES, normalizeLogin, validPassword, mayViewComputer, mayAdministerUsers, mayReviewAudit };
