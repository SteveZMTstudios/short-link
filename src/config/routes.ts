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
    vcard: 'aes-gcm:v1:xE5qK38jlDE6/NKb5mJW+Og5PVshMwFrMQcRCM9xV0UlwKwzAD+94BgCGdwVG15KhIIJCf00Pg9HBBtMKdNyCJ+O0U5W8Xmpjv1nE3fDuOfOEZXxqyHJ7DXIKMFv',
    blog: 'https://blog.stevezmt.top/',
    phi: 'https://stevezmt.top/Phigros-history',
  },
};
