const sql = require('mssql');

const dbConfig = {
    user: 'sa',
    password: 'cpc@609$',
    server: '192.168.100.71',
    database: 'CPC_TRACKING',
    options: {
        encrypt: true,
        trustServerCertificate: true
    }
};

async function testConnection() {
    try {
        await sql.connect(dbConfig);
        console.log('✅ Connected to SQL Server successfully!');
        
        const result = await sql.query`SELECT @@version`;
        console.log('SQL Server version:', result.recordset[0]);
        
        sql.close();
    } catch (err) {
        console.error('❌ SQL Server connection failed:', err.message);
    }
}

testConnection();