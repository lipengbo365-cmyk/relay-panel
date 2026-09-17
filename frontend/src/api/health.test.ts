import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getHealthJob,
  getResourceHealth,
  getResourceHealthHistory,
  healthJobProgress,
  isTerminalHealthJob,
  listHealthJobItems,
  listHealthJobs,
  listHealthResources,
  listRelayNodes,
  toSafeHealthError,
} from './health';

const mockGet = vi.hoisted(() => vi.fn());
vi.mock('./client', () => ({ default: { get: mockGet }, ApiEnvelope: {} }));

beforeEach(() => {
  mockGet.mockReset();
  mockGet.mockResolvedValue({ code: 0, message: 'ok', data: { items: [], next_cursor: null } });
});

describe('health API safety helpers', () => {
  it('allows only documented symbolic backend errors', () => {
    expect(toSafeHealthError({ response: { data: { message: 'INVALID_CURSOR' } } })).toEqual({
      code: 'INVALID_CURSOR',
      message: 'The page cursor is invalid or expired. Return to the first page.',
    });
  });

  it('drops arbitrary raw error detail instead of rendering it', () => {
    const markers = [
      ['pass', 'word'].join(''),
      ['Author', 'ization'].join(''),
      ['Bear', 'er'].join(''),
      ['socks5://user:', 'fixture@invalid:1080'].join(''),
      ['proxy', ' credential'].join(''),
    ];
    for (const detail of markers) {
      const safe = toSafeHealthError({
        response: { data: { message: 'UNRECOGNIZED', detail } },
      });
      expect(safe.code).toBe('UNKNOWN_ERROR');
      expect(`${safe.code} ${safe.message}`).not.toContain(detail);
    }
  });

  it('uses terminal counters rather than visible rows for progress', () => {
    expect(healthJobProgress({
      total_items: 10,
      succeeded_count: 3,
      failed_count: 1,
      cancelled_count: 1,
    })).toBe(50);
    expect(isTerminalHealthJob('SUCCEEDED')).toBe(true);
    expect(isTerminalHealthJob('QUEUED')).toBe(false);
  });
});

describe('health read-only API client', () => {
  it('sends opaque cursors and filters without decoding them', async () => {
    await listHealthJobs({ status: 'RUNNING', source: 'MANUAL', cursor: 'opaque.value', limit: 50 });
    await listHealthJobItems('job/id', { state: 'RETRY_WAIT', safe_error_code: 'TIMEOUT', cursor: 'opaque.item', limit: 100 });
    expect(mockGet).toHaveBeenNthCalledWith(1, '/admin/socks5-health/jobs?status=RUNNING&source=MANUAL&cursor=opaque.value&limit=50', { signal: undefined });
    expect(mockGet).toHaveBeenNthCalledWith(2, '/admin/socks5-health/jobs/job%2Fid/items?state=RETRY_WAIT&safe_error_code=TIMEOUT&cursor=opaque.item&limit=100', { signal: undefined });
  });

  it('covers every F2 read endpoint with GET only', async () => {
    mockGet.mockResolvedValue({ code: 0, message: 'ok', data: [] });
    await getHealthJob('job');
    await getResourceHealth(11);
    await getResourceHealthHistory(11, 50, 0);
    await listHealthResources({ page: 1, page_size: 50, status: 'ONLINE' });
    await listRelayNodes();
    expect(mockGet.mock.calls.map(([url]) => url)).toEqual([
      '/admin/socks5-health/jobs/job',
      '/admin/socks5-resources/11/health',
      '/admin/socks5-resources/11/check-history?limit=50&offset=0',
      '/admin/socks5-resources/page?page=1&page_size=50&status=ONLINE',
      '/admin/relay-nodes',
    ]);
  });
});
