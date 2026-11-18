// Pushes Worker secrets from the deploy environment with `wrangler secret bulk` (values never printed).
import { spawnSync } from 'node:child_process';
const names = ['ISSUER_KEYS', 'TOKEN_SIGNING_KEY', 'CLERK_SECRET_KEY', 'CLERK_PUBLISHABLE_KEY', 'CLERK_WEBHOOK_SECRET', 'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_CREDIT_PRODUCT_ID', 'STRIPE_CARD_COST_PRODUCT_ID', 'OPERATOR_ACCOUNT', 'CLOUDFLARE_ANALYTICS_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'COST_SAFETY_DO_NAMESPACES', 'COST_SAFETY_HARD_STOP', 'LAUNCH_APPROVED', 'ALERT_WEBHOOK_URL'];
const secrets = Object.fromEntries(names.filter(n => process.env[n]).map(n => [n, process.env[n]]));
const result = spawnSync('npx', ['wrangler', 'secret', 'bulk'], { input: JSON.stringify(secrets), stdio: ['pipe', 'inherit', 'inherit'] });
process.exit(result.status ?? 1);
