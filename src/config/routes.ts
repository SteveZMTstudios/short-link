/**
 * Short Link Configuration Table.
 * 
 * ##################################################
 * SAMPLE! REDEPLOY MUST CONFIGURE ME!
 * ##################################################
 * 
 * Read README for details.
 * - Centralized Settings: Domain, 404, and UTM defaults are defined in ONE place.
 * - Minimal Default Template: Only routes root '/' to destination when accessed.
 * - Optional Symmetric Encryption: Supports `encrypted: 'aes-gcm:v1:...'` with ROUTES_KEY env var.
 */

import { ShortLinkConfig } from '../types';

export const config: ShortLinkConfig = {
  // 1. 全局站点与部署配置
  settings: {
    domain: 'stevezmt.top',
    notFoundUrl: 'https://stevezmt.top/404?from=${FULL_URL}',
    notFoundMode: 'redirect',
    defaultUtm: {
      utm_source: 'shortlink',
      utm_medium: 'redirect',
    },
  },

  // 2. 默认路由：仅保留自身被访问时（根路径 /）重定向的目标地址
  links: {
    '/': 'https://stevezmt.top',
  },
};
