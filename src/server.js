/**
 * Assertara Visual Sentry - Backend Service Entrypoint
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const config = require('./config/env');
const { handleEvaluateTransaction } = require('./controllers/evaluateController');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json({ limit: '25mb' })); // Support base64 viewport screenshots
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Assertara Visual Sentry',
    version: '1.0.0',
    models: {
      sam: config.samModel,
      muse: config.museModel
    },
    metaApiBaseUrl: config.metaApiBaseUrl,
    nodeEnv: config.nodeEnv
  });
});

// Primary Evaluation Endpoint
app.post('/api/v1/evaluate', handleEvaluateTransaction);

// Serve test fixtures and demo dApp mock pages
app.use('/demo', express.static(path.resolve(__dirname, '../test/fixtures')));

// Start listening
if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`====================================================`);
    console.log(`  Assertara Visual Sentry Server running on :${config.port} `);
    console.log(`  Health Check: http://localhost:${config.port}/health        `);
    console.log(`  Evaluation:   http://localhost:${config.port}/api/v1/evaluate`);
    console.log(`====================================================`);
  });
}

module.exports = app;
