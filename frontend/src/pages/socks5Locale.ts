import type { Lang } from '../i18n/context';

const healthStatusLabels: Record<string, [string, string]> = {
  ONLINE: ['在线', 'Online'], OFFLINE: ['离线', 'Offline'], AUTH_FAILED: ['认证失败', 'Authentication failed'], TIMEOUT: ['超时', 'Timeout'],
  CONNECT_FAILED: ['连接失败', 'Connection failed'], DISABLED: ['已禁用', 'Disabled'], UNKNOWN: ['未知', 'Unknown'],
};

const selectionModeLabels: Record<string, [string, string]> = {
  RECOMMENDED: ['推荐节点', 'Recommended'], MANUAL: ['手动指定', 'Manual'], LEGACY: ['按分组兼容', 'Legacy group'],
};

export const socks5DisplayText = (lang: Lang, zh: string, en: string) => lang === 'zh-CN' ? zh : en;

export const socks5HealthStatusText = (lang: Lang, value: string) => {
  const pair = healthStatusLabels[value];
  return pair ? socks5DisplayText(lang, pair[0], pair[1]) : value;
};

export const socks5SelectionModeText = (lang: Lang, value: string) => {
  const pair = selectionModeLabels[value];
  return pair ? socks5DisplayText(lang, pair[0], pair[1]) : value;
};
