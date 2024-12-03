// app.js
const express = require('express');
const mysql = require('mysql2/promise');
const { Pool } = require('pg');
const snmp = require('net-snmp');
const { NodeSSH } = require('node-ssh');
const cron = require('node-cron');
const fs = require('fs').promises;
const dns = require('dns').promises;

const app = express();
const port = 3000;

// Database configurations
const mysqlConfig = {
  host: '172.17.76.12',
  port: 3306,
  user: 'noc-viewer',
  password: '~5n(VL3YT>0if=Ix',
  database: 'mobile_app',
  connectTimeout: 30000,
  acquireTimeout: 30000
};

const pgConfig = {
  user: 'noc',
  host: '172.17.76.36',
  database: 'nisa',
  password: 'myrep123!',
  port: 5432,
  connectionTimeoutMillis: 30000
};

// Create database connections
const mysqlConnection = mysql.createPool(mysqlConfig);
const pgPool = new Pool(pgConfig);

// Constants
const SSH_CONFIG = {
  host: '172.17.12.153',
  username: 'cloud',
  password: 'cloud123!',
  readyTimeout: 30000
};

const SNMP_COMMUNITIES = ['noc-public', 'Myrepublic@123'];
const SUDO_PASSWORD = 'Myrep123!';

// Utility function for delay
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Save log function
async function saveLog(logData) {
  const { ip_address, hostname, snmp_status, snmp_community, ssh_status, observium_status, error_message } = logData;
  
  try {
    await pgPool.query(
      `INSERT INTO olt_observium_update_log 
      (ip_address, hostname, snmp_status, snmp_community, ssh_status, observium_status, error_message, created_at) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [ip_address, hostname, snmp_status, snmp_community, ssh_status, observium_status, error_message]
    );
    console.log('Log saved successfully for IP:', ip_address);
  } catch (error) {
    console.error('Error saving log:', error);
    throw error;
  }
}

// SNMP check function with retry mechanism
function performSNMPCheck(ip, community, timeout = 5000, retries = 2) {
  return new Promise((resolve, reject) => {
    if (typeof ip !== 'string' || typeof community !== 'string') {
      reject(new Error('IP address and community must be strings'));
      return;
    }

    let attemptCount = 0;

    function attemptSNMP() {
      attemptCount++;
      console.log(`SNMP check attempt ${attemptCount} for IP ${ip} with community ${community}`);
      
      const session = snmp.createSession(ip, community, { 
        timeout: timeout,
        retries: 1,
        transport: "udp4",
        version: snmp.Version2c
      });

      const oid = '1.3.6.1.2.1.1.5.0'; // sysName OID

      session.get([oid], (error, varbinds) => {
        if (error) {
          console.error(`SNMP error for ${ip} (attempt ${attemptCount}):`, error);
          session.close();
          
          if (attemptCount < retries) {
            console.log(`Retrying SNMP check for ${ip} in 2 seconds...`);
            setTimeout(attemptSNMP, 2000);
          } else {
            resolve({ success: false, sysName: null, community: null, error: error.message });
          }
        } else {
          if (snmp.isVarbindError(varbinds[0])) {
            console.error(`SNMP varbind error for ${ip}:`, snmp.varbindError(varbinds[0]));
            session.close();
            resolve({ success: false, sysName: null, community: null, error: 'Varbind error' });
          } else {
            const sysName = varbinds[0].value.toString();
            console.log(`SNMP check successful for ${ip} with sysName: ${sysName}`);
            session.close();
            resolve({ success: true, sysName, community });
          }
        }
      });

      session.on('error', (error) => {
        console.error(`SNMP session error for ${ip}:`, error);
        session.close();
      });
    }

    attemptSNMP();
  });
}

// Verify DNS resolution
async function verifyDNSResolution(hostname, ip) {
  try {
    console.log(`Verifying DNS resolution for ${hostname} (${ip})`);
    const addresses = await dns.resolve4(hostname);
    const isResolved = addresses.includes(ip);
    console.log(`DNS resolution ${isResolved ? 'successful' : 'failed'} for ${hostname}`);
    return isResolved;
  } catch (error) {
    console.error(`DNS resolution error for ${hostname}:`, error);
    return false;
  }
}

// Verify and update hosts file
async function verifyHostsEntry(ssh, ip, hostname) {
  try {
    console.log(`Verifying hosts entry for ${ip} ${hostname}`);
    
    // Tambahkan delay sebelum membaca hosts file
    await delay(2000);
    
    const { stdout: hostsContent } = await ssh.execCommand('cat /etc/hosts', {
      execOptions: { pty: true }
    });

    const entries = hostsContent.split('\n');
    const existingEntry = entries.find(entry => {
      const parts = entry.trim().split(/\s+/);
      return parts[0] === ip;
    });

    if (existingEntry) {
      const parts = existingEntry.trim().split(/\s+/);
      if (parts[1] !== hostname) {
        console.log(`Updating hosts entry for ${ip} from ${parts[1]} to ${hostname}`);
        
        // Backup hosts file sebelum modifikasi
        await ssh.execCommand(
          `echo "${SUDO_PASSWORD}" | sudo -S cp /etc/hosts /etc/hosts.backup`,
          { execOptions: { pty: true } }
        );
        
        // Gunakan sed dengan opsi yang lebih aman
        const sedCommand = `echo "${SUDO_PASSWORD}" | sudo -S sed -i.bak 's/^${ip}[[:space:]]*.*/${ip} ${hostname}/g' /etc/hosts`;
        const { stdout, stderr } = await ssh.execCommand(sedCommand, { 
          execOptions: { pty: true } 
        });
        
        if (stderr) {
          console.log('Sed command stderr:', stderr);
        }
      }
    } else {
      console.log(`Adding new hosts entry for ${ip} ${hostname}`);
      // Tambahkan newline sebelum entry baru
      await ssh.execCommand(
        `echo "${SUDO_PASSWORD}" | sudo -S bash -c 'echo -e "\n${ip} ${hostname}" >> /etc/hosts'`,
        { execOptions: { pty: true } }
      );
    }

    // Tambahkan delay sebelum restart service
    await delay(3000);

    console.log('Restarting systemd-resolved service');
    await ssh.execCommand(
      `echo "${SUDO_PASSWORD}" | sudo -S systemctl restart systemd-resolved`,
      { execOptions: { pty: true } }
    );

    // Tambahkan delay lebih lama setelah restart service
    await delay(8000);

    // Verifikasi dengan multiple checks
    const checks = [];
    
    // Check 1: Verifikasi konten hosts file
    const { stdout: verifyContent } = await ssh.execCommand('cat /etc/hosts', {
      execOptions: { pty: true }
    });
    checks.push(verifyContent.includes(`${ip} ${hostname}`));
    
    // Check 2: Verifikasi dengan getent
    const { code: getentCode } = await ssh.execCommand(`getent hosts ${hostname}`, {
      execOptions: { pty: true }
    });
    checks.push(getentCode === 0);
    
    // Check 3: Verifikasi dengan nslookup
    const { code: nslookupCode } = await ssh.execCommand(`nslookup ${hostname}`, {
      execOptions: { pty: true }
    });
    checks.push(nslookupCode === 0);
    
    const isVerified = checks.some(check => check === true);
    console.log(`Hosts entry verification results:`, {
      hostsFile: checks[0],
      getent: checks[1],
      nslookup: checks[2]
    });
    
    if (!isVerified) {
      throw new Error(`Verification failed for ${ip} ${hostname}`);
    }
    
    return true;
  } catch (error) {
    console.error('Error in verifyHostsEntry:', error);
    throw error;
  }
}


// Add device to Observium
async function addDeviceToObservium(ssh, hostname, community) {
  try {
    console.log(`Adding device ${hostname} to Observium with community ${community}`);

    const dnsCheck = await ssh.execCommand(`getent hosts ${hostname}`, {
      execOptions: { pty: true }
    });

    if (dnsCheck.code !== 0) {
      throw new Error(`DNS resolution failed for ${hostname}`);
    }

    const result = await ssh.execCommand(
      `echo "${SUDO_PASSWORD}" | sudo -S /opt/observium/add_device.php ${hostname} ${community} v2c 161 udp`,
      {
        cwd: '/',
        execOptions: { pty: true }
      }
    );

    console.log('Observium add_device output:', result.stdout);
    console.log('Observium add_device errors:', result.stderr);

    const isSuccess = !result.stdout.includes('Could not resolve') && 
                     (result.stdout.includes('Added device') || 
                      result.stdout.includes('already exists'));

    console.log(`Device addition ${isSuccess ? 'successful' : 'failed'} for ${hostname}`);
    return isSuccess;
  } catch (error) {
    console.error('Error in addDeviceToObservium:', error);
    throw error;
  }
}

// Main SSH operation
async function performSSHOperation(ip, sysName, community, hostname) {
  const ssh = new NodeSSH();
  let retryCount = 0;
  const maxRetries = 3;

  while (retryCount < maxRetries) {
    try {
      console.log(`Starting SSH operation for ${hostname} (${ip}) - Attempt ${retryCount + 1}`);
      await ssh.connect(SSH_CONFIG);

      const hostsUpdated = await verifyHostsEntry(ssh, ip, hostname);
      if (!hostsUpdated) {
        throw new Error('Failed to update hosts file');
      }

      console.log('Waiting for DNS cache update...');
      await delay(10000); // Increased delay

      const success = await addDeviceToObservium(ssh, hostname, community);

      ssh.dispose();
      return success;
    } catch (error) {
      console.error(`SSH operation attempt ${retryCount + 1} failed:`, error);
      retryCount++;
      
      if (retryCount < maxRetries) {
        console.log(`Retrying in 5 seconds...`);
        await delay(5000);
      } else {
        ssh.dispose();
        throw error;
      }
    }
  }
}

// Main comparison and update function
async function compareAndUpdate() {
  try {
    console.log('Starting comparison and update process');

    // Get MySQL data
    const [mysqlResults] = await mysqlConnection.execute(
      "SELECT ip_address, hostname FROM ref_olts r WHERE r.hostname LIKE '%olt%'"
    );

    // Get PostgreSQL data
    const pgResult = await pgPool.query(
      "SELECT ip, hostname, snmp_community FROM olt_observium_comparison"
    );

    // Get all logged IPs from olt_observium_update_log
    const logsResult = await pgPool.query(
      `SELECT DISTINCT ip_address 
       FROM olt_observium_update_log`
    );

    const pgData = pgResult.rows;
    const loggedIPs = logsResult.rows.map(row => row.ip_address);
    console.log(`Found ${mysqlResults.length} OLTs in MySQL, ${pgData.length} in PostgreSQL, and ${loggedIPs.length} in logs`);

    for (const mysqlRow of mysqlResults) {
      try {
        const cleanIpAddress = mysqlRow.ip_address ? mysqlRow.ip_address.trim() : null;
        
        if (!cleanIpAddress) {
          console.error(`Invalid IP address for row:`, mysqlRow);
          continue;
        }

        const matchingPgRow = pgData.find(pgRow => pgRow.ip === cleanIpAddress);
        const isAlreadyLogged = loggedIPs.includes(cleanIpAddress);

        // Skip if already in PostgreSQL comparison table
        if (matchingPgRow) {
          console.log(`Skipping ${cleanIpAddress} - already in PostgreSQL comparison table`);
          continue;
        }

        // Skip if IP exists in logs
        if (isAlreadyLogged) {
          console.log(`Skipping ${cleanIpAddress} - already exists in update log`);
          continue;
        }

        // Process only new OLTs that have never been logged
        console.log(`Processing new OLT: ${cleanIpAddress} (${mysqlRow.hostname})`);
        
        let logData = {
          ip_address: cleanIpAddress,
          hostname: mysqlRow.hostname,
          snmp_status: false,
          snmp_community: null,
          ssh_status: false,
          observium_status: false,
          error_message: null
        };

        let snmpResult;
        for (const community of SNMP_COMMUNITIES) {
          try {
            snmpResult = await performSNMPCheck(cleanIpAddress, community);
            if (snmpResult.success) {
              logData.snmp_status = true;
              logData.snmp_community = snmpResult.community;
              break;
            }
          } catch (snmpError) {
            console.error(`SNMP check failed for ${cleanIpAddress} with ${community}:`, snmpError);
            logData.error_message = `SNMP check failed: ${snmpError.message}`;
          }
        }

        if (snmpResult && snmpResult.success) {
          try {
            const sshSuccess = await performSSHOperation(
              cleanIpAddress,
              snmpResult.sysName,
              snmpResult.community,
              mysqlRow.hostname
            );

            if (sshSuccess) {
              logData.ssh_status = true;
              logData.observium_status = true;

              await pgPool.query(
                'INSERT INTO olt_observium_comparison (ip, hostname, snmp_community, created_at) VALUES ($1, $2, $3, NOW())',
                [cleanIpAddress, mysqlRow.hostname, snmpResult.community]
              );
              
              console.log(`Successfully added ${cleanIpAddress} to PostgreSQL`);
            } else {
              logData.error_message = 'SSH operation failed';
            }
          } catch (sshError) {
            console.error(`SSH operation failed for ${cleanIpAddress}:`, sshError);
            logData.error_message = `SSH operation failed: ${sshError.message}`;
          }
        }

        await saveLog(logData);
      } catch (rowError) {
        console.error(`Error processing row:`, rowError);
        await saveLog({
          ip_address: mysqlRow.ip_address,
          hostname: mysqlRow.hostname,
          snmp_status: false,
          snmp_community: null,
          ssh_status: false,
          observium_status: false,
          error_message: `Error processing row: ${rowError.message}`
        });
      }
    }

    console.log('Comparison and update process completed');
  } catch (error) {
    console.error('Error in compareAndUpdate:', error);
  }
}

// Initialize application
async function initializeApp() {
  try {
    await compareAndUpdate();

    cron.schedule('0 */12 * * *', async () => {
      console.log('Running scheduled comparison and update...');
      await compareAndUpdate();
    });

    app.get('/status', (req, res) => {
      res.send('OLT Comparison and Update service is running');
    });

    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error('Error initializing application:', error);
    process.exit(1);
  }
}

// Start the application
initializeApp();

module.exports = app;