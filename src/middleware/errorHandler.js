const logger = require('../utils/logger');

module.exports = function errorHandler(err, req, res, _next) {
  logger.error({ err, requestId: req.requestId }, 'unhandled_error');
  if (res.headersSent) return;
  const status = err.status || 500;
  res.status(status).json({ success: false, error: { message: err.message || 'Internal server error' } });
};
