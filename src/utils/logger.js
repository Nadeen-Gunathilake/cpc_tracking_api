const pino = require('pino');
const config = require('../config');

const logger = pino({
  level: process.env.LOG_LEVEL || (config.env === 'production' ? 'info' : 'debug'),
  transport: config.env === 'production' ? undefined : {
    target: 'pino-pretty',
    options: { translateTime: 'SYS:standard', ignore: 'pid,hostname' }
  }
});

module.exports = logger;
