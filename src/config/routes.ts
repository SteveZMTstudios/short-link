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
  },

  links: {
    '/': 'https://stevezmt.top',
    'blog:/*': 'https://blog.stevezmt.top/$1',
    pubgpg: 'https://key.stevezmt.top',
    'academic-abuse': 'https://link.stevezmt.top/avoid-political-disputes/index.html',
    ethcalc: 'https://link.stevezmt.top/ethtool-advertise-bitmap-calc/index.html',
    'blog/*': 'https://blog.stevezmt.top/$1',
    rss: 'https://blog.stevezmt.top/atom.xml',
    vcard: 'aes-gcm:v1:GZZdpmkW98GqPCYRkTUZ8UrSCvc6JoMqd0DoW3Gxqgqf73KG6qsBB7u15b5rnrPdNmMYwo/WCP0MQkUg/sTKMOXu5gEORdeK3PztInAkk/j7r1i7+YCH/UKppwLi',
  },
};
