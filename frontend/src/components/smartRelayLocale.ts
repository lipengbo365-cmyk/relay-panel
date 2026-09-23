import type { RelayCandidate } from '../api/types';

export function countryMatchDisplay(value: RelayCandidate['country_match'], chinese: boolean) {
  if (value === 'MATCHED') return chinese ? '国家匹配' : 'Country matched';
  if (value === 'CROSS_COUNTRY') return chinese ? '跨国' : 'Cross-country';
  return chinese ? '未知' : 'Unknown';
}
