/**
 * Short Link Configuration Table.
 * Generated via admin.html
 */

import { ShortLinkConfig } from '../types';

export const config: ShortLinkConfig = {
  settings: {
    domain: 'stevezmt.top',
    notFoundUrl: 'https://stevezmt.top/404?from=${FULL_URL}',
    notFoundMode: 'redirect',
    defaultUtm: {
      utm_source: 'shortlink',
      utm_medium: 'redirect',
    },
    challenge: {
      provider: 'cap',
      siteKey: '8704cf7f-b00c-4801-a1bc-1572e585e623',
    },
  },

  links: {
    '/': 'https://stevezmt.top',
    test: 'aes-gcm:v1:4Xbi9L4OgDE58ZziPf6TjO032BTv5uG9c2C4g6GqktYzrFwoFF8NGmBlsOJ77WVtm6hanvToxA==',
  },
};
