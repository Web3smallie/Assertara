require('dotenv').config();

const config = {
  port: parseInt(process.env.PORT, 10) || 3001,
  nodeEnv: process.env.NODE_ENV || 'development',
  modelApiKey: process.env.MODEL_API_KEY || '',
  metaApiBaseUrl: process.env.META_API_BASE_URL || 'https://api.meta.ai/v1',
  samModel: process.env.SAM_MODEL || 'sam-3-1',
  museModel: process.env.MUSE_MODEL || 'muse-spark-1.3',
  ethereumRpcUrl: process.env.ETHEREUM_RPC_URL || 'https://ethereum-rpc.publicnode.com',
  anvilPort: parseInt(process.env.ANVIL_PORT, 10) || 8545,
};

module.exports = config;
