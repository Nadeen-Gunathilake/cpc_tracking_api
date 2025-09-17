#!/usr/bin/env node
require('dotenv').config();
const bcrypt = require('bcrypt');
const { sql, getPool } = require('../src/db/pool');
const config = require('../src/config');

(async () => {
  try {
    const pool = await getPool();
    const existing = await pool.request().query('SELECT TOP 1 empId FROM Employee WHERE adminRights = 1');
    if (existing.recordset.length > 0) {
      console.log('Admin user already exists. Nothing to do.');
      process.exit(0);
    }

    const firstName = process.env.BOOTSTRAP_ADMIN_FIRSTNAME || 'Admin';
    const lastName = process.env.BOOTSTRAP_ADMIN_LASTNAME || 'User';
    const EPF = process.env.BOOTSTRAP_ADMIN_EPF || 'ADMIN001';
    const email = process.env.BOOTSTRAP_ADMIN_EMAIL || 'admin@example.com';
  const rawPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || 'ChangeMe123!';

    if (rawPassword === 'ChangeMe123!') {
      console.warn('WARNING: Using default bootstrap password. Change it immediately.');
    }

    const hash = await bcrypt.hash(rawPassword, config.security.bcryptRounds);
    const request = pool.request()
      .input('firstName', sql.VarChar, firstName)
      .input('lastName', sql.VarChar, lastName)
      .input('EPF', sql.VarChar, EPF)
      .input('email', sql.VarChar, email)
      .input('passwordHash', sql.VarChar, hash)
      .input('adminRights', sql.Bit, true);

    const insertSql = `INSERT INTO Employee (firstName, lastName, EPF, email, passwordHash, adminRights)
         OUTPUT INSERTED.empId
         VALUES (@firstName, @lastName, @EPF, @email, @passwordHash, @adminRights)`;

    const result = await request.query(insertSql);

    console.log('Bootstrap admin created with empId:', result.recordset[0].empId);
    console.log('EPF:', EPF);
    console.log('Email:', email);
    console.log('Password:', rawPassword);
  process.exit(0);
  } catch (err) {
    console.error('Bootstrap failed:', err);
    process.exit(1);
  }
})();
