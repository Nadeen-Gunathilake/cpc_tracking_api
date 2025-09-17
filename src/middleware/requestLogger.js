const logger = require('../utils/logger');
const { randomUUID } = require('crypto');

module.exports = function requestLogger(req, res, next) {
  const start = Date.now();
  const id = req.headers['x-request-id'] || randomUUID();
  req.requestId = id;
  res.setHeader('x-request-id', id);

  logger.info({ id, method: req.method, url: req.originalUrl }, 'request:start');

  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info({ id, status: res.statusCode, duration }, 'request:complete');
  });

  next();
};
