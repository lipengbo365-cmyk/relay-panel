import type {
  CreateHealthJobRequest,
  HealthStatus,
  HealthTagMatch,
} from '../../api/health';

export interface HealthSelectorForm {
  resource_ids: number[];
  resource_country_codes: string;
  resource_statuses: HealthStatus[];
  resource_tags: string;
  resource_enabled: 'true' | 'false' | 'any';
  resource_tag_match: HealthTagMatch;
  node_ids: number[];
  node_country_codes: string;
  node_tags: string;
  node_enabled: 'true' | 'false' | 'any';
  node_tag_match: HealthTagMatch;
  max_items: number;
}

function canonicalNumbers(values: number[]): number[] {
  return [...new Set(values.filter((value) => Number.isInteger(value) && value > 0))]
    .sort((left, right) => left - right);
}

function canonicalStrings(value: string, upper: boolean): string[] {
  return [...new Set(value.split(',').map((part) => part.trim()).filter(Boolean)
    .map((part) => upper ? part.toUpperCase() : part.toLowerCase()))].sort();
}

function enabledValue(value: HealthSelectorForm['resource_enabled']): boolean | null {
  if (value === 'any') return null;
  return value === 'true';
}

export function buildHealthJobRequest(draft: HealthSelectorForm): CreateHealthJobRequest {
  return {
    resource_selector: {
      ids: canonicalNumbers(draft.resource_ids),
      enabled: enabledValue(draft.resource_enabled),
      country_codes: canonicalStrings(draft.resource_country_codes, true),
      statuses: [...new Set(draft.resource_statuses)].sort(),
      tags: canonicalStrings(draft.resource_tags, false),
      tag_match: draft.resource_tag_match,
    },
    node_selector: {
      ids: canonicalNumbers(draft.node_ids),
      enabled: enabledValue(draft.node_enabled),
      country_codes: canonicalStrings(draft.node_country_codes, true),
      tags: canonicalStrings(draft.node_tags, false),
      tag_match: draft.node_tag_match,
    },
    matrix_mode: 'CARTESIAN',
    max_items: draft.max_items,
  };
}
