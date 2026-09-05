/**
 * Short Link Configuration Table.
 * Generated via admin.html
 */

import { ShortLinkConfig } from '../types';

export const config: ShortLinkConfig = {
  settings: {
    domain: 'stev.cc',
    notFoundUrl: 'https://stevezmt.top/404?from=${FULL_URL}',
    notFoundMode: 'redirect',
    defaultUtm: {
      utm_source: 'shortlink',
      utm_medium: 'redirect',
    },
    challenge: {
      provider: 'turnstile',
      siteKey: '0x4AAAAAAEpTJ77zUTj5eTnC',
    },
  },

  links: {
    '/': 'https://stevezmt.top',
    'blog:/*': 'https://blog.stevezmt.top/$1',
    pubgpg: 'https://key.stevezmt.top',
    'academic-abuse': 'https://link.stevezmt.top/avoid-political-disputes/index.html',
    ethcalc: 'https://link.stevezmt.top/ethtool-advertise-bitmap-calc/index.html',
    'blog/*': 'https://blog.stevezmt.top/$1',
    rss: 'https://blog.stevezmt.top/atom.xml',
    vcard: 'aes-gcm:v1:0SRJ9+OmuOyT9jLWBrVT/+cwYCdWQYYKuTVaQPMw59SYfUBYpJxaVWK6rYTZJvn17y/sMRpxDDx9xRVVNDwunsJ6+7I59dqE+GKjrBCutSqutFJgFFNkLwW8Ls3/',
  },
};
