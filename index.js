const Joi = require('joi');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sql = require('mssql'); // For SQL Server
const app = express();

app.use(express.json());

// Database configuration
const dbConfig = {
    user: 'sa',
    password: 'cpc@609$',
    server: '192.168.100.71',
    database: 'CPC_TRACKING',
    options: {
        encrypt: true, // Use encryption
        trustServerCertificate: true // For development
    }
};

// JWT Secret (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || '84583b13-c3a5-49f8-a4b9-7707fb11a156';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Middleware to check admin rights
const requireAdmin = (req, res, next) => {
    if (!req.user.adminRights) {
        return res.status(403).json({ message: 'Admin rights required' });
    }
    next();
};

app.get('/', (req, res) => {
    res.send('CPC Tracking API - Employee Management System');
});

// Employee Management Routes

// Get all employees (Admin only)
app.get('/api/employees', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
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

        const pool = await sql.connect(dbConfig);
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
app.post('/api/employees', authenticateToken,requireAdmin, async (req, res) => {
    const { error } = validateEmployee(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { firstName, lastName, EPF, email, password,adminRights } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);

        const pool = await sql.connect(dbConfig);
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
app.put('/api/employees/:id', authenticateToken,requireAdmin, async (req, res) => {
    const { error } = validateEmployeeUpdate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const empId = parseInt(req.params.id);
        const { firstName, lastName, EPF, email, adminRights } = req.body;

        const pool = await sql.connect(dbConfig);
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

        const pool = await sql.connect(dbConfig);
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
app.get('/api/locations/:empId', authenticateToken,requireAdmin, async (req, res) => {
    try {
        const empId = parseInt(req.params.empId);

        const pool = await sql.connect(dbConfig);
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
    const { error } = validateLocation(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { empId, latitude, longitude } = req.body;

        // Users can only add their own locations unless they're admin
        if (req.user.empId !== empId && !req.user.adminRights) {
            return res.status(403).json({ message: 'Access denied' });
        }

        const pool = await sql.connect(dbConfig);
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

// Authentication Routes

// Login
app.post('/api/auth/login', async (req, res) => {
    const { error } = validateLogin(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    try {
        const { EPF, password } = req.body;

        const pool = await sql.connect(dbConfig);
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

        const token = jwt.sign(
            {
                empId: employee.empId,
                EPF: employee.EPF,
                adminRights: employee.adminRights
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            employee: {
                empId: employee.empId,
                firstName: employee.firstName,
                lastName: employee.lastName,
                EPF: employee.EPF,
                adminRights: employee.adminRights
            }
        });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// Validation functions
function validateEmployee(employee) {
    const schema = Joi.object({
        firstName: Joi.string().min(2).max(100).required(),
        lastName: Joi.string().min(2).max(100).required(),
        EPF: Joi.string().min(3).max(10).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        adminRights: Joi.boolean()
    });
    return schema.validate(employee);
}

function validateEmployeeUpdate(employee) {
    const schema = Joi.object({
        firstName: Joi.string().min(2).max(100).required(),
        lastName: Joi.string().min(2).max(100).required(),
        EPF: Joi.string().min(3).max(10).required(),
        email: Joi.string().email().required(),
        adminRights: Joi.boolean().required()
    });
    return schema.validate(employee);
}

function validateLocation(location) {
    const schema = Joi.object({
        empId: Joi.number().integer().required(),
        latitude: Joi.number().min(-90).max(90).required(),
        longitude: Joi.number().min(-180).max(180).required()
    });
    return schema.validate(location);
}

function validateLogin(credentials) {
    const schema = Joi.object({
        EPF: Joi.string().required(),
        password: Joi.string().required()
    });
    return schema.validate(credentials);
}

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => console.log(`CPC Tracking API running on port ${port}...`));









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