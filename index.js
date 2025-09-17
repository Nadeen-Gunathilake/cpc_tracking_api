require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const config = require('./src/config');
const { sql, getPool } = require('./src/db/pool');
const { authenticateToken, requireAdmin } = require('./src/middleware/auth');
const requestLogger = require('./src/middleware/requestLogger');
const errorHandler = require('./src/middleware/errorHandler');
const logger = require('./src/utils/logger');
const { createEmployeeSchema, updateEmployeeSchema } = require('./src/schemas/employee');
const { locationSchema } = require('./src/schemas/location');
const { loginSchema } = require('./src/schemas/auth');

const app = express();


app.use(cors({
    origin: [
        'http://localhost:3001',
        'http://localhost:3000',
        'http://192.168.100.71:3001',
        'http://127.0.0.1:3001'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true
}));
app.use(helmet());
app.disable('x-powered-by');

app.use(express.json());
app.use(requestLogger);

// Rate limiting only for auth endpoints (applied later via middleware style inline)

// Maintain original APIs without path changes


// Using externalized DB config via config module & pool helper


/*
const dbConfig = {
    server: 'localhost\\SQLExpress',   
    database: 'CPC_TRACKING',
    driver: 'msnodesqlv8',
    options: {
        trustedConnection: true        
    }
};
*/

// JWT secret sourced from config
const JWT_SECRET = config.jwt.secret;


// Auth middleware now imported (logic unchanged for external behavior)

app.get('/', (req, res) => {
    res.send('CPC Tracking API - Employee Management System');
});

// Employee Management Routes

// Get all employees (Admin only)
app.get('/api/employees', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const pool = await getPool();
        const result = await pool.request()
            .query('SELECT empId, firstName, lastName, EPF, email, adminRights FROM Employee');

        res.json(result.recordset);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get single employee
app.get('/api/employees/:id', authenticateToken, async (req, res) => {
    try {
        const empId = parseInt(req.params.id);

        // Users can only view their own data unless they're admin
        if (req.user.empId !== empId && !req.user.adminRights) {
            return res.status(403).json({ message: 'Access denied' });
        }

    const pool = await getPool();
        const result = await pool.request()
            .input('empId', sql.Int, empId)
            .query('SELECT empId, firstName, lastName, EPF, email, adminRights FROM Employee WHERE empId = @empId');

        if (result.recordset.length === 0) {
            return res.status(404).json({ message: 'Employee not found' });
        }
        res.json(result.recordset[0]);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Create new employee (Admin only)
app.post('/api/employees', authenticateToken, requireAdmin, async (req, res) => {
    const { error } = createEmployeeSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { firstName, lastName, EPF, email, password, adminRights } = req.body;

    const hashedPassword = await bcrypt.hash(password, config.security.bcryptRounds);

    const pool = await getPool();
        const result = await pool.request()
            .input('firstName', sql.VarChar, firstName)
            .input('lastName', sql.VarChar, lastName)
            .input('EPF', sql.VarChar, EPF)
            .input('email', sql.VarChar, email)
            .input('passwordHash', sql.VarChar, hashedPassword)
            .input('adminRights', sql.Bit, adminRights)
            .query(`INSERT INTO Employee (firstName, lastName, EPF, email, passwordHash, adminRights) 
                    OUTPUT INSERTED.empId, INSERTED.firstName, INSERTED.lastName, INSERTED.EPF, INSERTED.email, INSERTED.adminRights
                    VALUES (@firstName, @lastName, @EPF, @email, @passwordHash, @adminRights)`);

        res.status(201).json(result.recordset[0]);
    } catch (error) {
        if (error.number === 2627) { // Unique constraint violation
            return res.status(400).json({ message: 'EPF number/email already exists' });
        }
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update employee (Admin only)
app.put('/api/employees/:id', authenticateToken, requireAdmin, async (req, res) => {
    const { error } = updateEmployeeSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const empId = parseInt(req.params.id);
        const { firstName, lastName, EPF, email, adminRights } = req.body;

    const pool = await getPool();
        const result = await pool.request()
            .input('empId', sql.Int, empId)
            .input('firstName', sql.VarChar, firstName)
            .input('lastName', sql.VarChar, lastName)
            .input('EPF', sql.VarChar, EPF)
            .input('email', sql.VarChar, email)
            .input('adminRights', sql.Bit, adminRights)
            .query(`UPDATE Employee 
                    SET firstName = @firstName, lastName = @lastName, EPF = @EPF, email = @email, adminRights = @adminRights
                    OUTPUT INSERTED.empId, INSERTED.firstName, INSERTED.lastName, INSERTED.EPF, INSERTED.email, INSERTED.adminRights
                    WHERE empId = @empId`);

        if (result.recordset.length === 0) {
            return res.status(404).json({ message: 'Employee not found' });
        }

        res.json(result.recordset[0]);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete employee (Admin optional)
app.delete('/api/employees/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const empId = parseInt(req.params.id);
        const pool = await getPool();
        const result = await pool.request()
            .input('empId', sql.Int, empId)
            .query('DELETE FROM Employee OUTPUT DELETED.* WHERE empId = @empId');

        if (result.recordset.length === 0) {
            return res.status(404).json({ message: 'Employee not found' });
        }

        res.json({ message: 'Employee deleted successfully', employee: result.recordset[0] });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Location Management Routes

// Get employee locations (Admin can see all, users can see their own)
app.get('/api/locations/:empId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const empId = parseInt(req.params.empId);
        const pool = await getPool();
        const result = await pool.request()
            .input('empId', sql.Int, empId)
            .query('SELECT * FROM Location WHERE empId = @empId ORDER BY timestamp DESC');

        res.json(result.recordset);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Add location tracking
app.post('/api/locations', authenticateToken, async (req, res) => {
    const { error } = locationSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { empId, latitude, longitude } = req.body;

        // Users can only add their own locations unless they're admin
        if (req.user.empId !== empId && !req.user.adminRights) {
            return res.status(403).json({ message: 'Access denied' });
        }

    const pool = await getPool();
        const result = await pool.request()
            .input('empId', sql.Int, empId)
            .input('latitude', sql.Decimal(10, 7), latitude)
            .input('longitude', sql.Decimal(11, 8), longitude)
            .query(`INSERT INTO Location (empId, latitude, longitude) 
                    OUTPUT INSERTED.*
                    VALUES (@empId, @latitude, @longitude)`);

        res.status(201).json(result.recordset[0]);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});



const loginLimiter = rateLimit({ windowMs: config.rateLimit.windowMs, max: config.rateLimit.max });
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { EPF, password } = req.body;
    const pool = await getPool();
        const result = await pool.request()
            .input('EPF', sql.VarChar, EPF)
            .query('SELECT * FROM Employee WHERE EPF = @EPF');

        if (result.recordset.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const employee = result.recordset[0];
        const validPassword = await bcrypt.compare(password, employee.passwordHash);

        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const sessionId = uuidv4();

        const token = jwt.sign(
            {
                empId: employee.empId,
                EPF: employee.EPF,
                adminRights: employee.adminRights,
                sessionId
            },
            JWT_SECRET,
            { expiresIn: '12h' }
        );

        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 12);


        await pool.request()
            .input('sessionId', sql.UniqueIdentifier, sessionId)
            .input('empId', sql.Int, employee.empId)
            .input('token', sql.NVarChar, token)
            .input('expiresAt', sql.DateTime, expiresAt)
            .query(`INSERT INTO Sessions (sessionId, empId, token, expiresAt)
                    VALUES (@sessionId, @empId, @token, @expiresAt)`);

        // Send token and employee info
        res.json({
            token,
            employee: {
                empId: employee.empId,
                firstName: employee.firstName,
                lastName: employee.lastName,
                EPF: employee.EPF,
                email: employee.email,
                adminRights: employee.adminRights
            }
        });

    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const sessionId = req.user.sessionId;

    const pool = await getPool();
        await pool.request()
            .input('sessionId', sql.UniqueIdentifier, sessionId)
            .query('DELETE FROM Sessions WHERE sessionId = @sessionId');

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Validation functions moved to schemas directory

app.use(errorHandler);

const port = config.port;
app.listen(port, '0.0.0.0', () => logger.info(`CPC Tracking API running on port ${port}...`));









/*const Joi = require('joi');
const express = require('express');
const app = express();

app.use(express.json());


const courses = [
    { id: 1, name: 'course1' },
    { id: 2, name: 'course2' },
    { id: 3, name: 'course3' },
];

app.get('/', (req, res) => {
    res.send('Hello World!!!');
});

app.get('/api/courses', (req, res) => {
    res.send(courses);
});


app.post('/api/courses', (req, res) => {
    const { error } = validateCourse(req.body);

    if (error) return res.status(400).send(error.details[0].message);

    const course = {
        id: courses.length + 1,
        name: req.body.name
    };
    courses.push(course);
    res.send(course);
});

app.put('/api/courses/:id', (req, res) => {
    const course = courses.find(c => c.id === parseInt(req.params.id));
    if (!course) return res.status(404).send('The course with the given ID was not found');


    const { error } = validateCourse(req.body);

    if (error) return res.status(400).send(error.details[0].message);
    
    


    course.name = req.body.name;
    res.send(course);

});

app.get('/api/courses/:id', (req, res) => {
    const course = courses.find(c => c.id === parseInt(req.params.id));
    if (!course) return res.status(404).send('The course with the given ID was not found');
    res.send(course);
});


const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}...`));

function validateCourse(course) {
    const schema = Joi.object({
        name: Joi.string().min(3).required()
    });

    return schema.validate(course);

}

app.delete('/api/courses/:id', (req, res) => {
    const course = courses.find(c => c.id === parseInt(req.params.id));
    if (!course) return res.status(404).send('The course with the given ID was not found');

    const index = courses.indexOf(course);
    courses.splice(index, 1);

    res.send(course);
});
*/