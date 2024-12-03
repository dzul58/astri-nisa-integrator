const express = require('express');
const mysql = require('mysql2/promise');
const { Pool } = require('pg');

const app = express();
const port = 3000;

const observiumPool = mysql.createPool({
  host: '172.17.12.153',
  port: 3306,
  user: 'root',
  password: 'Myrep123!',
  database: 'observium',
  connectTimeout: 20000
});

const pgPool = new Pool({
  user: 'noc',
  host: '172.17.76.36',
  database: 'nisa',
  password: 'myrep123!',
  port: 5432,
});

app.get('/sync-observium-data', async (req, res) => {
  try {
    // Mengambil data dari Observium
    const [rows] = await observiumPool.query('SELECT device_id, ip, hostname, snmp_community FROM devices');

    // Insert data ke PostgreSQL
    const pgClient = await pgPool.connect();
    try {
      await pgClient.query('BEGIN');

      for (const row of rows) {
        await pgClient.query(
          'INSERT INTO observium_device_comparison (ip, hostname, snmp_community, created_at) VALUES ($1, $2, $3, $4)',
          [row.ip, row.hostname, row.snmp_community, new Date()]
        );
      }

      await pgClient.query('COMMIT');
    } catch (error) {
      await pgClient.query('ROLLBACK');
      throw error;
    } finally {
      pgClient.release();
    }

    res.json({ message: 'Data berhasil disinkronkan', count: rows.length });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Terjadi kesalahan saat sinkronisasi data' });
  }
});

app.listen(port, () => {
  console.log(`Server berjalan pada port ${port}`);
});