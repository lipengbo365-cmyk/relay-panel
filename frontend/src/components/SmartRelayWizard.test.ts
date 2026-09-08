import { describe, expect, it } from 'vitest';
import type { SmartRelayCreated } from '../api/types';
import { buildSocksUrl, formatRelayEndpoint } from '../utils/smartRelayEndpoint';

const result = (overrides: Partial<SmartRelayCreated> = {}): SmartRelayCreated => ({
  rule_id: 1,
  relay_node_id: 2,
  resource_id: 3,
  host: 'relay.example.com',
  port: 10001,
  relay_username: 'r_user',
  relay_password: 'p@ss:/word',
  protocol: 'SOCKS5',
  exit_ip: '198.51.100.8',
  exit_country: 'US',
  selection_mode: 'RECOMMENDED',
  deployment_status: 'CREATED',
  replayed: false,
  password_shown_once: true,
  ...overrides,
});

describe('smart relay endpoint rendering', () => {
  it('brackets a raw IPv6 host exactly once', () => {
    expect(formatRelayEndpoint('2001:db8::7', 10001)).toBe('[2001:db8::7]:10001');
    expect(formatRelayEndpoint('[2001:db8::7]', 10001)).toBe('[2001:db8::7]:10001');
  });

  it('keeps IPv4 and DNS endpoints unbracketed', () => {
    expect(formatRelayEndpoint('192.0.2.1', 10001)).toBe('192.0.2.1:10001');
    expect(formatRelayEndpoint('relay.example.com', 10001)).toBe('relay.example.com:10001');
  });

  it('percent-encodes one-time credentials in the copy URL', () => {
    expect(buildSocksUrl(result())).toBe(
      'socks5://r_user:p%40ss%3A%2Fword@relay.example.com:10001',
    );
  });

  it('cannot reconstruct a URL after an idempotent replay omits the password', () => {
    expect(buildSocksUrl(result({ relay_password: undefined, replayed: true, password_shown_once: false }))).toBe('');
  });
});
