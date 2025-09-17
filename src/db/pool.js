const sql = require('mssql');
const config = require('../config');

let poolPromise;

async function getPool() {
  if (!poolPromise) {
    poolPromise = new sql.ConnectionPool(config.db)
      .connect()
      .then(p => {
        return p;
      })
      .catch(err => {
        console.error('Failed to create DB pool', err);
        throw err;
      });
  }
  return poolPromise;
}

module.exports = { sql, getPool };
