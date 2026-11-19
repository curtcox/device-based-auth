/**
 * The three first-party audiences and their action catalogs. hashbin and cronly actions mirror
 * those sites' own scope lists (hashbin src/auth/scopes.js USER_SCOPES; cronly
 * src/auth/scopes.js) so a DBA grant maps one-to-one onto the checks they already make.
 * "<ns>:session" means "may sign in to the site's web UI".
 */
export const DBA_SCOPES = Object.freeze({
  'account:read': 'Read the account balance and monthly spend.',
  'transactions:read': 'Read the account ledger and audit trail.',
  'credentials:read': 'List and read devices, credentials and decisions.',
  'credentials:issue': 'Issue credentials (paid from the balance). A device can only issue credentials narrower than its own; an API key can grant devicebasedauth.org (dba:) actions only within its own scopes.',
  'credentials:revoke': 'Revoke credentials and devices.',
  'audiences:read': 'Read registered audiences.',
  'audiences:write': 'Register and change audiences you own.',
  'authorize': 'Ask for online authorization decisions for audiences you own (paid from the balance).',
  'gates:read': 'List the account\'s gates (devices and services that approve requests).',
  'gates:write': 'Add and remove gates (needs a recent sign-in).',
  'approvals:answer': 'Answer gate requests as a DBA device gate (devices only: a device answers for the gates that name it).'
});

const catalog = (ns, entries) => Object.entries(entries).map(([action, description]) => ({ action: `${ns}:${action}`, description }));

export const FIRST_PARTY = Object.freeze([
  {
    name: 'devicebasedauth.org', namespace: 'dba', description: 'devicebasedauth.org itself: manage devices, credentials and audiences.',
    catalog: catalog('dba', { session: 'Sign in to the devicebasedauth.org dashboard with this device.', ...DBA_SCOPES }),
    redirect_uris: []
  },
  {
    name: 'hashbin.org', namespace: 'hashbin', description: 'HashBin: pay-to-publish content addressed by 256t hashes.',
    catalog: catalog('hashbin', {
      session: 'Sign in to hashbin.org.',
      'aliases:read': 'Read your personal aliases and owned global aliases.',
      'aliases:write': 'Change alias values and renewal settings; delete personal aliases.',
      'aliases:purchase': 'Buy and renew aliases and make or withdraw offers, paid from your hashbin balance.',
      'aliases:sell': 'List global aliases for sale and accept or decline offers.',
      'content:write': 'Publish content, paid from your hashbin balance.',
      'content:extend': 'Extend how long content is kept, paid from your hashbin balance.',
      'content:delete': 'Delete content you uploaded.',
      'uploads:read': 'List the content you uploaded.',
      'balance:read': 'Read your hashbin balance.',
      'transactions:read': 'Read your hashbin balance history.',
      'ratelimit:purchase': 'Buy download allowances, paid from your hashbin balance.',
      'downloads:spend': 'Pay for downloads from your hashbin balance, within your caps.',
      'suppliers:read': 'List your alternate suppliers.',
      'suppliers:write': 'Register, change and remove alternate suppliers.'
    }),
    redirect_uris: ['https://hashbin.org/auth/dba/callback', 'https://hashbin.org/oauth/dba/callback']
  },
  {
    name: 'cronly.org', namespace: 'cronly', description: 'cronly: named HTTP and JavaScript actions on a schedule, paid per run.',
    catalog: catalog('cronly', {
      session: 'Sign in to cronly.org.',
      read: 'Read jobs, runs, costs and configuration.',
      run: 'Run jobs and test actions, paid from your cronly balance.',
      change: 'Change actions, variables, jobs, triggers and keys.',
      prose: 'Translate prose to and from cron, paid from your cronly balance.',
      'secrets:write': 'Set and rotate secrets.'
    }),
    redirect_uris: ['https://cronly.org/auth/dba/callback']
  }
]);
