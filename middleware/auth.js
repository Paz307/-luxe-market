const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    req.flash('error', 'Please login to access this page.');
    return res.redirect('/login');
  }
  next();
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.session.userId) return res.redirect('/login');
  if (!roles.includes(req.session.role)) return res.status(403).send('Access Denied');
  next();
};

module.exports = { requireAuth, requireRole };
