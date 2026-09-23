import type { SmartRelayCreated } from '../api/types';

export const formatRelayEndpoint = (host: string, port: number) =>
  `${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${port}`;

export const buildSocksUrl = (result: SmartRelayCreated) => {
  if (!result.relay_password) return '';
  return `socks5://${encodeURIComponent(result.relay_username)}:${encodeURIComponent(result.relay_password)}@${formatRelayEndpoint(result.host, result.port)}`;
};
