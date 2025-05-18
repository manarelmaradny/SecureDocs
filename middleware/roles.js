function requireRole(role) {
  return (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    }
    return res.redirect('/dashboard'); // Redirect to dashboard if user is not an ADMIN
  };
}

module.exports = { requireRole };
