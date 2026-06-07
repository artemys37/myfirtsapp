// MongoDB initialisation script
// Runs once on first container startup

db = db.getSiblingDB('netaudit');

// Create application user
db.createUser({
  user: 'netaudit_app',
  pwd: 'netaudit_app_pass',
  roles: [{ role: 'readWrite', db: 'netaudit' }]
});

// Create collections with schema validation
db.createCollection('campaigns', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['name', 'target', 'status'],
      properties: {
        name:   { bsonType: 'string' },
        status: { enum: ['pending', 'running', 'done', 'failed'] }
      }
    }
  }
});

db.createCollection('hosts');
db.createCollection('vulns');
db.createCollection('auth_results');
db.createCollection('reports');

// Indexes for performance
db.campaigns.createIndex({ created_at: -1 });
db.hosts.createIndex({ scan_id: 1 });
db.hosts.createIndex({ ip: 1, scan_id: 1 }, { unique: true });
db.vulns.createIndex({ scan_id: 1 });
db.vulns.createIndex({ host_ip: 1 });
db.auth_results.createIndex({ scan_id: 1 });
db.auth_results.createIndex({ success: 1 });
db.reports.createIndex({ scan_id: 1, created_at: -1 });

print('✅ netaudit database initialised');
