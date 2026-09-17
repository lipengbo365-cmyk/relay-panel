import { describe, expect, it } from 'vitest';
import { healthJobProgress, isTerminalHealthJob, toSafeHealthError } from './health';

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
