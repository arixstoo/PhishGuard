// Test de charge de l'analyse d'URL sans enrichissement (étape 4.13, docs/load-test.md).
//
//   make loadtest                      # API en conteneur, k6 en conteneur, 50 req/s × 60 s
//   BASE_URL=... API_KEY=... RATE=50 DURATION=60s k6 run scripts/loadtest/analyze_url.js
//
// Débit constant (constant-arrival-rate) : k6 envoie 50 requêtes par seconde quelle que
// soit la latence. Un test « N utilisateurs en boucle » ralentirait avec le serveur et
// masquerait la saturation (omission coordonnée).
import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8000';
const API_KEY = __ENV.API_KEY || '';
const RATE = Number(__ENV.RATE || 50);
const DURATION = __ENV.DURATION || '60s';

// URLs variées, domaines réservés : pas de cache possible côté serveur, rien de réel.
const HOSTS = [
  'secure-login-verify.example', 'paypa1-account.test', 'www.example.com',
  'news.example.org', 'appleid.apple.com.verify.example', 'shop.example.net',
  'xn--pple-43d.example', '192.0.2.10', 'bit.ly', 'docs.example.co.uk',
];
const PATHS = ['/', '/login', '/verify/account/123456', '/blog/2026/11/post', '/signin.php?next=/'];

export const options = {
  discardResponseBodies: true,
  scenarios: {
    analyze_url: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  // Objectif du module 4 : médiane sous 50 ms. Aucune erreur tolérée (429 compris).
  thresholds: {
    'http_req_duration{expected_response:true}': ['med<50'],
    http_req_failed: ['rate==0'],
    checks: ['rate==1'],
  },
  summaryTrendStats: ['min', 'med', 'avg', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const host = HOSTS[Math.floor(Math.random() * HOSTS.length)];
  const path = PATHS[Math.floor(Math.random() * PATHS.length)];
  const scheme = Math.random() < 0.5 ? 'http' : 'https';
  const headers = { 'Content-Type': 'application/json' };
  if (API_KEY) headers['X-API-Key'] = API_KEY;
  const response = http.post(
    `${BASE_URL}/v1/analyze/url`,
    JSON.stringify({ url: `${scheme}://${host}${path}`, use_threat_intel: false }),
    { headers, tags: { route: '/v1/analyze/url' } },
  );
  check(response, { 'statut 200': (r) => r.status === 200 });
}

export function handleSummary(data) {
  const out = __ENV.SUMMARY_PATH;
  const result = { stdout: textSummary(data) };
  if (out) result[out] = JSON.stringify(data, null, 1);
  return result;
}

function textSummary(data) {
  const d = data.metrics.http_req_duration.values;
  const reqs = data.metrics.http_reqs.values;
  const failed = data.metrics.http_req_failed.values.rate;
  const fmt = (v) => `${v.toFixed(1)} ms`;
  return [
    `requêtes : ${reqs.count} (${reqs.rate.toFixed(1)}/s), échecs : ${(failed * 100).toFixed(2)} %`,
    `latence : médiane ${fmt(d.med)}, p90 ${fmt(d['p(90)'])}, p95 ${fmt(d['p(95)'])}, ` +
      `p99 ${fmt(d['p(99)'])}, max ${fmt(d.max)}`,
    '',
  ].join('\n');
}
