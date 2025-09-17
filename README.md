## CPC Tracking API

Phone number support has been added. To enable it you must add a column to the Employee table before deploying the updated code.

### Migration

Run this SQL in your database (idempotent pattern shown):

```
IF COL_LENGTH('Employee','phoneNumber') IS NULL
	ALTER TABLE Employee ADD phoneNumber VARCHAR(32) NULL;
```

Optional: create an index if you plan to search by phone in future:

```
-- CREATE INDEX IX_Employee_phoneNumber ON Employee(phoneNumber);
```

### Environment

See `.env.example` for all variables. New optional variable:

`BOOTSTRAP_ADMIN_PHONE` – sets a phone number when seeding the initial admin (accepted formats: leading 0 local e.g. 0712345678 or international with + e.g. +94712345678).

### Code Changes Summary

- Added phoneNumber to Employee CRUD (INSERT/UPDATE/SELECT and responses).
- Login and /api/auth/validate endpoints now include phoneNumber.
- EPF location search returns employee.phoneNumber.
- Bootstrap script optionally inserts phoneNumber when BOOTSTRAP_ADMIN_PHONE is set.

### Rollout Steps

1. Apply migration above.
2. Deploy updated application code.
3. Update `.env` with BOOTSTRAP_ADMIN_PHONE if desired and rerun bootstrap (only creates admin if absent).
4. Frontend: include phoneNumber field when creating/updating employees (optional).

### Validation Rules

Accepted patterns (Joi):
- Local starting with 0: e.g. 0712345678, 070-123-4567
- International with +: +94712345678

Characters allowed after the leading digit(s): digits, space, hyphen. Length 6–21 chars inclusive.

### Notes

If you skip the migration, API calls touching Employee will fail with `Invalid column name 'phoneNumber'`.

