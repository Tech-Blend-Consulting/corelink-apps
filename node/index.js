'use strict';

const { TransitClient } = require('./lib/client');
const { Watcher } = require('./lib/watcher');
const { computeFingerprint } = require('./lib/fingerprint');
const { StaleEnvelope, CorruptEnvelope, WrongSecret } = require('./lib/sealed');
const {
  Deployment,
  DeploymentError,
  loadDeployment,
  loadDeploymentIfPresent,
  DEFAULT_DEPLOYMENT_PATH,
  DEPLOYMENT_PATH_ENV,
} = require('./lib/deployment');
const { Lease, LeaseExhausted, LeaseNotFound, RESOURCE_SECRET, RESOURCE_DATABASE, RESOURCE_CLOUD } = require('./lib/leases');

module.exports = {
  TransitClient,
  Watcher,
  computeFingerprint,
  StaleEnvelope,
  CorruptEnvelope,
  WrongSecret,
  Deployment,
  DeploymentError,
  loadDeployment,
  loadDeploymentIfPresent,
  DEFAULT_DEPLOYMENT_PATH,
  DEPLOYMENT_PATH_ENV,
  Lease,
  LeaseExhausted,
  LeaseNotFound,
  RESOURCE_SECRET,
  RESOURCE_DATABASE,
  RESOURCE_CLOUD,
};
