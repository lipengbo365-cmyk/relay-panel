import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { I18nContext, type Lang } from '../i18n/context';
import { enUS } from '../i18n/en-US';
import { zhCN } from '../i18n/zh-CN';
import { countryMatchDisplay } from '../components/smartRelayLocale';
import { getHealthCopy } from '../components/health/healthLocale';
import Socks5 from './Socks5';
import { socks5HealthStatusText, socks5SelectionModeText } from './socks5Locale';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

const envelope = <T,>(data: T) => ({ code: 0, message: 'ok', data });

function renderSocks5(lang: Lang) {
  const dictionary = lang === 'zh-CN' ? zhCN : enUS;
  return render(
    <I18nContext.Provider value={{ lang, setLang: vi.fn(), t: (key) => dictionary[key] }}>
      <Socks5 />
    </I18nContext.Provider>,
  );
}

beforeEach(() => {
  mockGet.mockReset();
  mockGet.mockImplementation((url: string) => {
    if (url.startsWith('/admin/socks5-resources/page?')) {
      return Promise.resolve(envelope({ items: [], total: 0, page: 1, page_size: 50 }));
    }
    if (url === '/admin/socks5-rules' || url === '/groups' || url === '/admin/relay-nodes') {
      return Promise.resolve(envelope([]));
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
});

describe('Alpha6 localization v2 language contract', () => {
  it('keeps Dashboard, Node Status, and navigation labels bilingual', () => {
    expect(zhCN.dashboard).toBe('仪表盘');
    expect(enUS.dashboard).toBe('Dashboard');
    expect(zhCN.nodeStatus).toBe('节点状态');
    expect(enUS.nodeStatus).toBe('Node Status');
    expect(zhCN.socks5Relay).toBe('SOCKS5 中转');
    expect(enUS.socks5Relay).toBe('SOCKS5 Relay');
  });

  it('keeps Health Center copy bilingual for errors and empty states', () => {
    expect(getHealthCopy('zh-CN').healthLoadFailed).toBe('健康数据加载失败');
    expect(getHealthCopy('en-US').healthLoadFailed).toBe('Health data could not be loaded');
    expect(getHealthCopy('zh-CN').noHealthJobs).toBe('暂无健康检测任务');
    expect(getHealthCopy('en-US').noHealthJobs).toBe('No health jobs');
  });

  it('maps UNKNOWN to Unknown/未知 without changing the machine value', () => {
    const machineValue = 'UNKNOWN' as const;
    expect(countryMatchDisplay(machineValue, true)).toBe('未知');
    expect(countryMatchDisplay(machineValue, false)).toBe('Unknown');
    expect(socks5HealthStatusText('zh-CN', machineValue)).toBe('未知');
    expect(socks5HealthStatusText('en-US', machineValue)).toBe('Unknown');
    expect(machineValue).toBe('UNKNOWN');
    expect(countryMatchDisplay(machineValue, true)).not.toBe('跨国');
  });

  it('keeps status display values bilingual while preserving unknown machine values', () => {
    expect(socks5SelectionModeText('zh-CN', 'RECOMMENDED')).toBe('推荐节点');
    expect(socks5SelectionModeText('en-US', 'RECOMMENDED')).toBe('Recommended');
    expect(socks5SelectionModeText('en-US', 'FUTURE_MODE')).toBe('FUTURE_MODE');
  });

  it('renders the SOCKS5 Import/Preview entry in English without v2 Chinese labels', async () => {
    renderSocks5('en-US');
    expect(await screen.findByText('SOCKS5 Relay')).toBeInTheDocument();
    expect(screen.getByText('SOCKS5 Resources')).toBeInTheDocument();
    expect(screen.queryByText('SOCKS5 中转')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /Batch Import/ }));
    expect(await screen.findByText('Batch Import SOCKS5')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Generate Preview' })).toBeInTheDocument();
    expect(screen.queryByText('批量导入 SOCKS5')).not.toBeInTheDocument();
  });

  it('renders the same SOCKS5 entry points in Simplified Chinese', async () => {
    renderSocks5('zh-CN');
    expect(await screen.findByText('SOCKS5 中转')).toBeInTheDocument();
    expect(screen.getByText('SOCKS5 资源')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: /批量导入/ }));
    expect(await screen.findByText('批量导入 SOCKS5')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '生成预览' })).toBeInTheDocument();
    await waitFor(() => expect(mockGet).toHaveBeenCalled());
  });
});
