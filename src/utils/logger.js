const pino = require('pino');
const config = require('../config');

let transport;
if (config.env !== 'production') {
  try {
    // Only configure pretty transport if pino-pretty is actually installed
    require.resolve('pino-pretty');
    transport = {
      target: 'pino-pretty',
      options: { translateTime: 'SYS:standard', ignore: 'pid,hostname' }
    };
  } catch (_) {
    // Fallback: no pretty transport available
    transport = undefined;
  }
}

const logger = pino({
  level: process.env.LOG_LEVEL || (config.env === 'production' ? 'info' : 'debug'),
  transport
});

module.exports = logger;
