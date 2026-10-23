import {
  useEffect,
  useMemo,
  useState,
  useCallback,
  type KeyboardEvent,
} from 'react';

import {
  Activity,
  ArrowUpRight,
  ChevronDown,
  ChevronRight,
  CircleX,
  Download,
  ExternalLink,
  Globe,
  Hash,
  Link2,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Target,
  TerminalSquare,
  X,
} from 'lucide-react';

import { dataProvider } from '../services/dataProvider';
import { useAppData } from '../contexts/AppDataContext';
import { useAuth } from '../../contexts/AuthContext';
import { isPublicDemo } from '../utils/demoMode';
import EmptyState from '../components/common/EmptyState';
import PageHeader from '../components/layout/PageHeader';

/* -------------------------------------------------------------------------- */
/*                                   Types                                    */
/* -------------------------------------------------------------------------- */

type IocType =
  | 'ip'
  | 'domain'
  | 'hash'
  | 'url';

type IocSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | string;

type InspectorTab =
  | 'Overview'
  | 'Timeline'
  | 'Relationships';

interface IocRecord {
  id: string;
  type: IocType | string;
  value: string;
  source: string;
  severity: IocSeverity;
  firstSeen?: string;
  lastSeen?: string;
  tags: string[];
}

interface ParsedAdvancedQuery {
  text: string;
  type?: IocType;
  severity?: IocSeverity;
  source?: string;
  tag?: string;
}

interface StixIndicator {
  type: 'indicator';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  pattern: string;
  pattern_type: 'stix';
  valid_from: string;
  labels: string[];
  name: string;
  description: string;
  external_references: Array<{
    source_name: string;
    external_id: string;
  }>;
}

/* -------------------------------------------------------------------------- */
/*                              Type metadata                                 */
/* -------------------------------------------------------------------------- */

const TYPE_ICONS = {
  ip: Server,
  domain: Globe,
  hash: Hash,
  url: Link2,
} as const;

const TYPE_LABELS = {
  ip: 'IP ADDRESS',
  domain: 'DOMAIN',
  hash: 'HASH',
  url: 'URL',
} as const;

/* -------------------------------------------------------------------------- */
/*                                  Helpers                                   */
/* -------------------------------------------------------------------------- */

function normalizeIoc(
  value: unknown,
): IocRecord | null {
  if (!value || typeof value !== 'object') {
    return null;
  }

  const source = value as Partial<IocRecord>;

  if (
    typeof source.id !== 'string' ||
    typeof source.value !== 'string'
  ) {
    return null;
  }

  const normalizedType =
    typeof source.type === 'string'
      ? source.type.toLowerCase()
      : 'unknown';

  const severity =
    typeof source.severity === 'string'
      ? source.severity.toLowerCase()
      : 'low';

  return {
    id: source.id,
    type: normalizedType,
    value: source.value,
    source:
      typeof source.source === 'string'
        ? source.source
        : 'Unknown',
    severity,
    firstSeen:
      typeof source.firstSeen === 'string'
        ? source.firstSeen
        : undefined,
    lastSeen:
      typeof source.lastSeen === 'string'
        ? source.lastSeen
        : undefined,
    tags: Array.isArray(source.tags)
      ? source.tags.filter(
        (tag): tag is string =>
          typeof tag === 'string',
      )
      : [],
  };
}

function formatDate(
  value: string | undefined,
): string {
  if (!value) {
    return 'Unknown';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Unknown';
  }

  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
  });
}

function formatDateTime(
  value: string | undefined,
): string {
  if (!value) {
    return 'Unknown';
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return 'Unknown';
  }

  return date.toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

function severityClass(
  severity: IocSeverity,
): string {
  return String(severity).toLowerCase();
}

function typeLabel(
  type: string,
): string {
  if (
    type in TYPE_LABELS
  ) {
    return TYPE_LABELS[
      type as keyof typeof TYPE_LABELS
    ];
  }

  return type
    .replace(/[_-]/g, ' ')
    .toUpperCase();
}

function escapeCsvValue(
  value: unknown,
): string {
  return `"${String(value ?? '').replace(
    /"/g,
    '""',
  )}"`;
}

function downloadFile(
  filename: string,
  content: string,
  mimeType: string,
): void {
  const blob = new Blob([content], {
    type: mimeType,
  });

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');

  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';

  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  URL.revokeObjectURL(url);
}

function escapeStixValue(
  value: string,
): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'");
}

function buildStixPattern(
  ioc: IocRecord,
): string {
  const value = escapeStixValue(
    ioc.value,
  );

  switch (ioc.type) {
    case 'ip':
      return `[ipv4-addr:value = '${value}']`;

    case 'domain':
      return `[domain-name:value = '${value}']`;

    case 'hash':
      return `[file:hashes.MD5 = '${value}']`;

    case 'url':
      return `[url:value = '${value}']`;

    default:
      return `[artifact:mime_type = '${value}']`;
  }
}

function buildStixIndicator(
  ioc: IocRecord,
): StixIndicator {
  const now =
    new Date().toISOString();

  const stableId =
    `indicator--${crypto.randomUUID()}`;

  return {
    type: 'indicator',
    spec_version: '2.1',
    id: stableId,
    created: now,
    modified: now,
    pattern: buildStixPattern(ioc),
    pattern_type: 'stix',
    valid_from:
      ioc.firstSeen ||
      now,
    labels: [
      ioc.severity,
      ...ioc.tags,
    ].filter(Boolean),
    name: `${typeLabel(ioc.type)} — ${ioc.value}`,
    description: `ANTITODE IOC exported from ${ioc.source}.`,
    external_references: [
      {
        source_name:
          'ANTITODE',
        external_id: ioc.id,
      },
    ],
  };
}

function parseAdvancedQuery(
  input: string,
): ParsedAdvancedQuery {
  const tokens = input
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  const textTokens: string[] = [];

  let type:
    | IocType
    | undefined;

  let severity:
    | IocSeverity
    | undefined;

  let source: string | undefined;
  let tag: string | undefined;

  for (const token of tokens) {
    const separator =
      token.indexOf(':');

    if (separator <= 0) {
      textTokens.push(token);
      continue;
    }

    const key = token
      .slice(0, separator)
      .toLowerCase();

    const rawValue = token
      .slice(separator + 1)
      .trim();

    const value =
      rawValue.toLowerCase();

    if (!rawValue) {
      continue;
    }

    if (
      key === 'type' &&
      ['ip', 'domain', 'hash', 'url'].includes(
        value,
      )
    ) {
      type = value as IocType;
      continue;
    }

    if (
      key === 'severity'
    ) {
      severity = value;
      continue;
    }

    if (key === 'source') {
      source = rawValue;
      continue;
    }

    if (key === 'tag') {
      tag = rawValue;
      continue;
    }

    textTokens.push(token);
  }

  return {
    text: textTokens.join(' '),
    type,
    severity,
    source,
    tag,
  };
}

/* -------------------------------------------------------------------------- */
/*                               IOC Page                                     */
/* -------------------------------------------------------------------------- */

export default function IocPage() {
  const { onNavigate } = useAppData();
  const { permissions } = useAuth();
  const canExportIoc = permissions.includes('ioc.feed.export');
  const [liveIocs, setLiveIocs] = useState<IocRecord[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [availableSources, setAvailableSources] = useState<string[]>([]);
  const [iocStats, setIocStats] = useState<{
    total_indicators: number;
    active_network_iocs: number;
    file_hashes: number;
    new_24h: number;
  }>({
    total_indicators: 0,
    active_network_iocs: 0,
    file_hashes: 0,
    new_24h: 0,
  });

  const [search, setSearch] = useState('');
  const [advancedMode, setAdvancedMode] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<IocSeverity | 'ALL'>('ALL');
  const [typeFilter, setTypeFilter] = useState<IocType | 'ALL'>('ALL');
  const [sourceFilter, setSourceFilter] = useState('');
  const [selectedIocId, setSelectedIocId] = useState<string | null>(null);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('Overview');
  const [showFilters, setShowFilters] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 100;

  const fetchIocData = useCallback(async (page = 1, isManualRefresh = false) => {
    if (isManualRefresh) setIsRefreshing(true);
    else setIsLoading(true);

    try {
      const typeParam = typeFilter === 'ALL' ? undefined : (typeFilter === 'ip' ? 'network' : typeFilter === 'hash' ? 'hash' : undefined);
      const [feedRes, statsRes, filterRes] = await Promise.allSettled([
        dataProvider.getIocFeed({
          page,
          limit: ITEMS_PER_PAGE,
          search: search.trim() || undefined,
          type: typeParam as any,
          source: sourceFilter || undefined,
        }),
        dataProvider.getIocStats(),
        dataProvider.getIocFilters(),
      ]);

      if (feedRes.status === 'fulfilled' && feedRes.value) {
        const feed = feedRes.value;
        const normalizedItems: IocRecord[] = (feed.data || []).map((item: any) => ({
          id: `${item.source || 'src'}-${item.indicator_value || item.id || Math.random()}`,
          type: (item.indicator_type || item.type || 'ip').toLowerCase(),
          value: item.indicator_value || item.value || '',
          source: item.source || 'Threat Intel',
          severity: (item.severity || 'medium').toLowerCase(),
          firstSeen: item.first_seen || item.firstSeen || new Date().toISOString(),
          lastSeen: item.last_seen || item.lastSeen || new Date().toISOString(),
          tags: item.tags || [],
        }));
        setLiveIocs(normalizedItems);
        setTotal(feed.total ?? normalizedItems.length);
        setTotalPages(feed.pages || Math.max(1, Math.ceil((feed.total ?? normalizedItems.length) / ITEMS_PER_PAGE)));
      } else {
        setLiveIocs([]);
        setTotal(0);
        setTotalPages(1);
      }

      if (statsRes.status === 'fulfilled' && statsRes.value?.data) {
        setIocStats(statsRes.value.data);
      }

      if (filterRes.status === 'fulfilled' && filterRes.value?.data?.sources) {
        setAvailableSources(filterRes.value.data.sources);
      }
    } catch (err) {
      console.error('Failed to load IOC feed:', err);
      setLiveIocs([]);
      setTotal(0);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [typeFilter, sourceFilter, search]);

  useEffect(() => {
    void fetchIocData(currentPage);
  }, [fetchIocData, currentPage]);

  useEffect(() => {
    setCurrentPage(1);
  }, [search, typeFilter, severityFilter, sourceFilter, advancedMode]);

  const iocs = liveIocs;

  /* ------------------------------------------------------------------------ */
  /*                       Synchronize inspector                              */
  /* ------------------------------------------------------------------------ */

  useEffect(() => {
    if (iocs.length === 0) {
      setSelectedIocId(null);
      return;
    }

    if (
      selectedIocId &&
      iocs.some(
        (ioc) =>
          ioc.id ===
          selectedIocId,
      )
    ) {
      return;
    }

    setSelectedIocId(
      iocs[0]?.id ?? null,
    );
  }, [iocs, selectedIocId]);

  /* ------------------------------------------------------------------------ */
  /*                            Selected IOC                                  */
  /* ------------------------------------------------------------------------ */

  const selectedIoc = useMemo(
    () =>
      iocs.find(
        (ioc) =>
          ioc.id ===
          selectedIocId,
      ) ?? null,
    [iocs, selectedIocId],
  );

  /* ------------------------------------------------------------------------ */
  /*                         Filter options                                  */
  /* ------------------------------------------------------------------------ */

  const sourceOptions =
    useMemo(
      () =>
        availableSources.length > 0
          ? availableSources
          : Array.from(
              new Set(
                iocs
                  .map(
                    (ioc) =>
                      ioc.source,
                  )
                  .filter(Boolean),
              ),
            ).sort((a, b) =>
              a.localeCompare(b),
            ),
      [availableSources, iocs],
    );

  /* ------------------------------------------------------------------------ */
  /*                          Advanced query                                 */
  /* ------------------------------------------------------------------------ */

  const parsedQuery = useMemo(
    () =>
      advancedMode
        ? parseAdvancedQuery(
          search,
        )
        : {
          text: search.trim(),
        },
    [advancedMode, search],
  );

  /* ------------------------------------------------------------------------ */
  /*                              Filtering                                  */
  /* ------------------------------------------------------------------------ */

  const filtered =
    useMemo(() => {
      const text =
        parsedQuery.text
          .toLowerCase()
          .trim();

      return [...iocs]
        .filter((ioc) => {
          if (!text) {
            return true;
          }

          const haystack = [
            ioc.value,
            ioc.source,
            ioc.type,
            ioc.severity,
            ...ioc.tags,
          ]
            .join(' ')
            .toLowerCase();

          return haystack.includes(
            text,
          );
        })
        .filter((ioc) => {
          if (
            typeFilter ===
            'ALL'
          ) {
            return true;
          }

          return (
            ioc.type ===
            typeFilter
          );
        })
        .filter((ioc) => {
          if (
            severityFilter ===
            'ALL'
          ) {
            return true;
          }

          return (
            ioc.severity ===
            severityFilter
          );
        })
        .filter((ioc) => {
          if (!sourceFilter) {
            return true;
          }

          return (
            ioc.source ===
            sourceFilter
          );
        })
        .filter((ioc) => {
          if (
            !parsedQuery.type
          ) {
            return true;
          }

          return (
            ioc.type ===
            parsedQuery.type
          );
        })
        .filter((ioc) => {
          if (
            !parsedQuery.severity
          ) {
            return true;
          }

          return (
            ioc.severity ===
            parsedQuery.severity
          );
        })
        .filter((ioc) => {
          if (
            !parsedQuery.source
          ) {
            return true;
          }

          return ioc.source
            .toLowerCase()
            .includes(
              parsedQuery.source.toLowerCase(),
            );
        })
        .filter((ioc) => {
          if (
            !parsedQuery.tag
          ) {
            return true;
          }

          return ioc.tags.some(
            (tag) =>
              tag
                .toLowerCase()
                .includes(
                  parsedQuery.tag!.toLowerCase(),
                ),
          );
        })
        .sort((a, b) => {
          const severityRank: Record<
            string,
            number
          > = {
            critical: 4,
            high: 3,
            medium: 2,
            low: 1,
          };

          const rankDifference =
            (severityRank[
              b.severity
            ] ?? 0) -
            (severityRank[
              a.severity
            ] ?? 0);

          if (rankDifference !== 0) {
            return rankDifference;
          }

          return (
            new Date(
              b.lastSeen ??
              b.firstSeen ??
              0,
            ).getTime() -
            new Date(
              a.lastSeen ??
              a.firstSeen ??
              0,
            ).getTime()
          );
        });
    }, [
      iocs,
      parsedQuery,
      typeFilter,
      severityFilter,
      sourceFilter,
    ]);

  /* ------------------------------------------------------------------------ */
  /*                               Counts                                    */
  /* ------------------------------------------------------------------------ */

  const typeCounts =
    useMemo(
      () => ({
        ip: iocs.filter(
          (ioc) =>
            ioc.type === 'ip',
        ).length,

        domain: iocs.filter(
          (ioc) =>
            ioc.type ===
            'domain',
        ).length,

        hash: iocStats.file_hashes || iocs.filter(
          (ioc) =>
            ioc.type === 'hash',
        ).length,

        url: iocs.filter(
          (ioc) =>
            ioc.type === 'url',
        ).length,
      }),
      [iocs, iocStats],
    );

  const criticalCount =
    iocs.filter(
      (ioc) =>
        String(ioc.severity).toLowerCase() ===
        'critical',
    ).length;

  const highCount =
    iocs.filter(
      (ioc) =>
        String(ioc.severity).toLowerCase() === 'high',
    ).length;

  /* ------------------------------------------------------------------------ */
  /*                           Active filters                                */
  /* ------------------------------------------------------------------------ */

  const activeFilters =
    useMemo(() => {
      const filters: string[] =
        [];

      if (
        typeFilter !==
        'ALL'
      ) {
        filters.push(
          `type:${typeFilter}`,
        );
      }

      if (
        severityFilter !==
        'ALL'
      ) {
        filters.push(
          `severity:${String(
            severityFilter,
          ).toLowerCase()}`,
        );
      }

      if (sourceFilter) {
        filters.push(
          `source:${sourceFilter}`,
        );
      }

      return filters;
    }, [
      typeFilter,
      severityFilter,
      sourceFilter,
    ]);

  const hasFilters =
    Boolean(search.trim()) ||
    activeFilters.length >
    0;

  /* ------------------------------------------------------------------------ */
  /*                               Actions                                   */
  /* ------------------------------------------------------------------------ */

  const removeFilter = (
    filter: string,
  ) => {
    if (
      filter.startsWith(
        'type:',
      )
    ) {
      setTypeFilter('ALL');
    }

    if (
      filter.startsWith(
        'severity:',
      )
    ) {
      setSeverityFilter(
        'ALL',
      );
    }

    if (
      filter.startsWith(
        'source:',
      )
    ) {
      setSourceFilter('');
    }
  };

  const clearAllFilters =
    () => {
      setActiveSearch('');
      setTypeFilter('ALL');
      setSeverityFilter(
        'ALL',
      );
      setSourceFilter('');
    };

  const setActiveSearch = (
    value: string,
  ) => {
    setSearch(value);
  };


  /* ------------------------------------------------------------------------ */
  /*                                Export                                   */
  /* ------------------------------------------------------------------------ */

  const exportStix =
    () => {
      if (
        filtered.length === 0
      ) {
        return;
      }

      const indicators =
        filtered.map(
          buildStixIndicator,
        );

      const bundle = {
        type: 'bundle',
        id: `bundle--${crypto.randomUUID()}`,
        spec_version: '2.1',
        objects: indicators,
      };

      downloadFile(
        `antitode-iocs-${new Date()
          .toISOString()
          .slice(0, 10)}.json`,
        JSON.stringify(
          bundle,
          null,
          2,
        ),
        'application/stix+json;charset=utf-8',
      );
    };

  const exportCsv =
    () => {
      if (
        filtered.length === 0
      ) {
        return;
      }

      const headers = [
        'ID',
        'Type',
        'Indicator',
        'Severity',
        'Source',
        'First Seen',
        'Last Seen',
        'Tags',
      ];

      const rows =
        filtered.map(
          (ioc) => [
            ioc.id,
            ioc.type,
            ioc.value,
            ioc.severity,
            ioc.source,
            ioc.firstSeen,
            ioc.lastSeen,
            ioc.tags.join(
              ' | ',
            ),
          ],
        );

      const csv = [
        headers
          .map(escapeCsvValue)
          .join(','),
        ...rows.map((row) =>
          row
            .map(
              escapeCsvValue,
            )
            .join(','),
        ),
      ].join('\n');

      downloadFile(
        `antitode-iocs-${new Date()
          .toISOString()
          .slice(0, 10)}.csv`,
        csv,
        'text/csv;charset=utf-8',
      );
    };

  const exportSelectedIoc =
    () => {
      if (!selectedIoc) {
        return;
      }

      const payload =
        JSON.stringify(
          selectedIoc,
          null,
          2,
        );

      downloadFile(
        `antitode-ioc-${selectedIoc.id}.json`,
        payload,
        'application/json;charset=utf-8',
      );
    };

  /* ------------------------------------------------------------------------ */
  /*                           Keyboard interaction                           */
  /* ------------------------------------------------------------------------ */

  const handleRowKeyDown =
    (
      event: KeyboardEvent<HTMLTableRowElement>,
      id: string,
    ) => {
      if (
        event.key ===
        'Enter' ||
        event.key === ' '
      ) {
        event.preventDefault();
        setSelectedIocId(id);
      }
    };

  /* ------------------------------------------------------------------------ */
  /*                                  Render                                  */
  /* ------------------------------------------------------------------------ */

  if (!isLoading && liveIocs.length === 0 && !isPublicDemo()) {
    return (
      <div className="flex flex-col h-full overflow-hidden bg-[#0a0a0a]">
        <PageHeader
          breadcrumbs={[
            { label: 'Intelligence' },
            { label: 'IOC' },
          ]}
          title="Indicators of Compromise"
          description="Manage and analyze IPs, domains, hashes, and URLs."
          actions={
            <button
              type="button"
              className="at-btn at-btn-secondary at-btn-sm"
              onClick={() => void fetchIocData(currentPage, true)}
              disabled={isRefreshing}
            >
              <RefreshCw size={13} className={isRefreshing ? 'at-spin' : ''} />
              {isRefreshing ? 'Refreshing' : 'Refresh'}
            </button>
          }
        />
        <div style={{ padding: '24px' }}>
          <EmptyState
            title="No Threat Indicators Found"
            description="Indicators of Compromise (IPs, hashes, domains, and URLs) extracted from attacker traffic will populate here automatically."
            actionLabel="Connect Your First Honeypot"
            onAction={() => onNavigate('infrastructure')}
            secondaryLabel="Explore SOC Documentation"
            onSecondaryAction={() => onNavigate('help')}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-hidden bg-[#0a0a0a]">
      {/* ================================================================== */
      /* PAGE HEADER                                                         */
      /* ================================================================== */}

      <PageHeader
        breadcrumbs={[
          {
            label: 'Intelligence',
          },
          {
            label: 'IOC',
          },
        ]}
        title="Indicators of Compromise"
        description="Manage and analyze IPs, domains, hashes, and URLs."
        actions={
          <>
            <button
              type="button"
              className="at-btn at-btn-secondary at-btn-sm"
              onClick={() => void fetchIocData(currentPage, true)}
              disabled={isRefreshing}
            >
              <RefreshCw size={13} className={isRefreshing ? 'at-spin' : ''} />
              {isRefreshing ? 'Refreshing' : 'Refresh'}
            </button>

            {canExportIoc && (<button
              type="button"
              className="at-btn at-btn-secondary at-btn-sm"
              onClick={exportStix}
              disabled={
                filtered.length === 0
              }
            >
              <Download size={13} />
              STIX 2.1
            </button>)}
          </>
        }
      />


                  <div className="flex-1 overflow-y-auto custom-scrollbar">
        <div className="max-w-[1800px] mx-auto w-full flex flex-col min-h-full relative px-6">
      {/* ================================================================== */
      /* INTELLIGENCE SUMMARY                                                */
      /* ================================================================== */}

      <section className="flex flex-col md:flex-row bg-[#111] border border-[#222] rounded-lg mt-2 overflow-hidden shrink-0">
        {/* Intro */}
        <div className="flex-1 p-3 px-4 border-b md:border-b-0 md:border-r border-[#222] flex flex-col justify-center">
          <span className="text-[9px] font-bold text-[#666] tracking-wider uppercase block mb-1">
            INDICATOR REPOSITORY
          </span>
          <strong className="text-2xl font-light text-white block">
            {(iocStats?.total_indicators || total || iocs.length).toLocaleString()}
          </strong>
          <span className="text-[10px] text-[#888]">
            tracked indicators
          </span>
        </div>

        {/* Types */}
        <div className="flex-[1.5] p-3 px-4 border-b md:border-b-0 md:border-r border-[#222] grid grid-cols-2 gap-y-2 gap-x-4">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-blue-900/20 text-blue-400 border border-blue-900/50 flex items-center justify-center shrink-0">
              <Server size={12} />
            </div>
            <div className="flex flex-col min-w-0">
              <strong className="text-xs text-white truncate">{typeCounts.ip.toLocaleString()}</strong>
              <span className="text-[9px] text-[#888] uppercase truncate leading-none mt-0.5">IP addresses</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-purple-900/20 text-purple-400 border border-purple-900/50 flex items-center justify-center shrink-0">
              <Globe size={12} />
            </div>
            <div className="flex flex-col min-w-0">
              <strong className="text-xs text-white truncate">{typeCounts.domain.toLocaleString()}</strong>
              <span className="text-[9px] text-[#888] uppercase truncate leading-none mt-0.5">Domains</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-orange-900/20 text-orange-400 border border-orange-900/50 flex items-center justify-center shrink-0">
              <Hash size={12} />
            </div>
            <div className="flex flex-col min-w-0">
              <strong className="text-xs text-white truncate">{typeCounts.hash.toLocaleString()}</strong>
              <span className="text-[9px] text-[#888] uppercase truncate leading-none mt-0.5">Hashes</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-emerald-900/20 text-emerald-400 border border-emerald-900/50 flex items-center justify-center shrink-0">
              <Link2 size={12} />
            </div>
            <div className="flex flex-col min-w-0">
              <strong className="text-xs text-white truncate">{typeCounts.url.toLocaleString()}</strong>
              <span className="text-[9px] text-[#888] uppercase truncate leading-none mt-0.5">URLs</span>
            </div>
          </div>
        </div>

        {/* Severity */}
        <div className="flex-1 p-3 px-4 flex flex-col justify-center gap-2">
          <div className="flex items-center gap-2.5">
            <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)] shrink-0"></div>
            <strong className="text-xs text-white w-12 truncate">{criticalCount.toLocaleString()}</strong>
            <span className="text-[10px] text-[#888] uppercase tracking-wider truncate">critical</span>
          </div>
          <div className="flex items-center gap-2.5">
            <div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.6)] shrink-0"></div>
            <strong className="text-xs text-white w-12 truncate">{highCount.toLocaleString()}</strong>
            <span className="text-[10px] text-[#888] uppercase tracking-wider truncate">high</span>
          </div>
        </div>
      </section>

      {/* ================================================================== */
      /* QUERY BAR                                                          */
      /* ================================================================== */}

      <div className="sticky top-0 z-20 bg-[#0a0a0a] pt-3 pb-3 border-b border-[#222] mb-4">
      <section className="flex flex-col gap-2 shrink-0">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[300px]">
            {advancedMode ? (
              <TerminalSquare size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#666]" />
            ) : (
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#666]" />
            )}

            <input
              type="text"
              className="w-full bg-[#111] border border-[#333] rounded-md py-1.5 pl-8 pr-8 text-xs text-white placeholder-[#555] focus:outline-none focus:border-red-500 transition-colors"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={
                advancedMode
                  ? 'type:domain severity:critical source:ThreatFox tag:malware'
                  : 'Search indicators, values, tags, sources...'
              }
              aria-label="Search indicators"
              spellCheck={false}
            />

            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#666] hover:text-white transition-colors"
                aria-label="Clear IOC search"
              >
                <X size={12} />
              </button>
            )}
          </div>

          <button
            type="button"
            className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-md text-xs transition-colors ${
              advancedMode ? 'bg-red-950/20 border-red-500 text-red-500' : 'bg-[#111] border-[#333] text-[#888] hover:text-white hover:border-[#444]'
            }`}
            onClick={() => setAdvancedMode((value) => !value)}
            aria-pressed={advancedMode}
          >
            <TerminalSquare size={12} />
            Advanced
          </button>

          <button
            type="button"
            className={`flex items-center gap-1.5 px-3 py-1.5 border rounded-md text-xs transition-colors ${
              showFilters ? 'bg-red-950/20 border-red-500 text-red-500' : 'bg-[#111] border-[#333] text-[#888] hover:text-white hover:border-[#444]'
            }`}
            onClick={() => setShowFilters((value) => !value)}
            aria-expanded={showFilters}
          >
            <SlidersHorizontal size={12} />
            Filters
          </button>

          <div className="ml-auto text-[10px] text-[#666] font-medium hidden md:block">
            {filtered.length.toLocaleString()} {filtered.length === 1 ? 'result' : 'results'}
          </div>
        </div>

        {showFilters && (
          <div className="flex flex-wrap items-center gap-4 p-2 bg-[#111] border border-[#222] rounded-md">
            <div className="flex items-center gap-2">
              <label className="text-[10px] text-[#888]">Type</label>
              <select
                value={typeFilter}
                onChange={(event) => setTypeFilter(event.target.value as 'ALL' | IocType)}
                className="bg-black border border-[#333] text-white text-[10px] rounded px-1.5 py-1 focus:border-red-500 outline-none cursor-pointer"
              >
                <option value="ALL">All types</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="hash">Hash</option>
                <option value="url">URL</option>
              </select>
            </div>
            
            <div className="flex items-center gap-2">
              <label className="text-[10px] text-[#888]">Severity</label>
              <select
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value as 'ALL' | 'critical' | 'high' | 'medium' | 'low')}
                className="bg-black border border-[#333] text-white text-[10px] rounded px-1.5 py-1 focus:border-red-500 outline-none cursor-pointer"
              >
                <option value="ALL">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            
            <button
              type="button"
              className="text-[10px] text-[#666] hover:text-white transition-colors flex items-center gap-1 ml-auto"
              onClick={() => {
                setTypeFilter('ALL');
                setSeverityFilter('ALL');
              }}
            >
              <CircleX size={10} />
              Clear filters
            </button>
          </div>
        )}
      </section>
      </div>

{/* ================================================================== */
      /* WORKSPACE                                                           */
      /* ================================================================== */}

      <div className="flex gap-4 flex-1 pb-10 min-h-[500px]">
        {/* ================================================================ */
        /* LIST                                                               */
        /* ================================================================ */}

        <section className="flex flex-col flex-1 border border-[#222] rounded-lg bg-[#111] overflow-visible h-auto">
          <div className="at-ioc-list-head">
            <div>
              <span className="at-v2-kicker">
                INDICATOR FEED
              </span>

              <h2>
                Threat indicators
              </h2>
            </div>

            <span className="at-ioc-list-count">
              Showing{' '}
              <strong>
                {filtered.length}
              </strong>

              {filtered.length !==
                iocs.length && (
                  <>
                    {' '}
                    of {iocs.length}
                  </>
                )}
            </span>
          </div>

          <div className="at-ioc-table-wrap !overflow-visible !min-h-0 !h-auto">
            <table className="at-ioc-table">
              <thead>
                <tr>
                  <th>
                    Type
                  </th>

                  <th>
                    Indicator
                  </th>

                  <th>
                    Severity
                  </th>

                  <th>
                    Source
                  </th>

                  <th>
                    Last Seen
                  </th>

                  <th>
                    Tags
                  </th>

                  <th />
                </tr>
              </thead>

              <tbody>
                {filtered.length ===
                  0 ? (
                  <tr className="hover:bg-transparent">
                    <td colSpan={7} className="p-0 border-b border-[#222] h-[400px]">
                      <div className="flex flex-col items-center justify-center h-full text-center p-8 w-full">
                        <div className="w-12 h-12 rounded-full bg-[#111] border border-[#333] flex items-center justify-center text-[#666] mb-4">
                          <ShieldAlert size={20} />
                        </div>
                        <strong className="text-white text-sm block mb-1">
                          No indicators found
                        </strong>
                        <span className="text-[#888] text-xs max-w-[300px] block mb-5">
                          No IOC values match the current query and filters. Try adjusting your search criteria.
                        </span>
                        <button
                          type="button"
                          className="px-4 py-2 bg-[#111] border border-[#333] text-white rounded hover:bg-[#222] transition-colors text-xs"
                          onClick={clearAllFilters}
                        >
                          Clear filters
                        </button>
                      </div>
                    </td>
                  </tr>
                ) : (
                  (filtered.length > ITEMS_PER_PAGE
                    ? filtered.slice(
                        (currentPage - 1) * ITEMS_PER_PAGE,
                        currentPage * ITEMS_PER_PAGE,
                      )
                    : filtered
                  ).map(
                    (ioc) => {
                      const Icon =
                        TYPE_ICONS[
                        ioc.type as IocType
                        ] ??
                        Hash;

                      const selected =
                        selectedIocId ===
                        ioc.id;

                      return (
                        <tr
                          key={ioc.id}
                          className={
                            selected
                              ? 'active'
                              : ''
                          }
                          tabIndex={0}
                          aria-selected={
                            selected
                          }
                          onClick={() =>
                            setSelectedIocId(
                              ioc.id,
                            )
                          }
                          onKeyDown={(
                            event,
                          ) =>
                            handleRowKeyDown(
                              event,
                              ioc.id,
                            )
                          }
                        >
                          <td>
                            <span
                              className={`at-ioc-type-icon-table ${ioc.type}`}
                            >
                              <Icon
                                size={12}
                              />
                            </span>
                          </td>

                          <td>
                            <button
                              type="button"
                              className="at-ioc-value"
                              onClick={(
                                event,
                              ) => {
                                event.stopPropagation();

                                setSelectedIocId(
                                  ioc.id,
                                );
                              }}
                              title={
                                ioc.value
                              }
                            >
                              {ioc.value}
                            </button>

                            <span className="at-ioc-type-label">
                              {typeLabel(
                                ioc.type,
                              )}
                            </span>
                          </td>

                          <td>
                            <span
                              className={`at-ioc-severity ${severityClass(
                                ioc.severity,
                              )}`}
                            >
                              <i />
                              {String(
                                ioc.severity,
                              ).toUpperCase()}
                            </span>
                          </td>

                          <td>
                            <span className="at-ioc-source">
                              {ioc.source}
                            </span>
                          </td>

                          <td>
                            <code className="at-ioc-date">
                              {formatDate(
                                ioc.lastSeen ??
                                ioc.firstSeen,
                              )}
                            </code>
                          </td>

                          <td>
                            <div className="at-ioc-tags">
                              {ioc.tags
                                .slice(
                                  0,
                                  2,
                                )
                                .map(
                                  (
                                    tag,
                                    index,
                                  ) => (
                                    <span
                                      key={`${tag}-${index}`}
                                    >
                                      {tag}
                                    </span>
                                  ),
                                )}

                              {ioc.tags
                                .length >
                                2 && (
                                  <span>
                                    +
                                    {ioc.tags
                                      .length -
                                      2}
                                  </span>
                                )}

                              {ioc.tags.length ===
                                0 && (
                                  <span>
                                    —
                                  </span>
                                )}
                            </div>
                          </td>

                          <td>
                            <ChevronRight
                              size={13}
                              className="at-ioc-row-arrow"
                              aria-hidden="true"
                            />
                          </td>
                        </tr>
                      );
                    },
                  )
                )}
              </tbody>
            </table>
          </div>

          {(totalPages > 1 || filtered.length > ITEMS_PER_PAGE) && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderTop: '1px solid var(--at-border)' }}>
              <button
                type="button"
                className="at-btn at-btn-ghost at-btn-sm"
                disabled={currentPage === 1 || isLoading}
                onClick={() => {
                  const p = Math.max(1, currentPage - 1);
                  setCurrentPage(p);
                  void fetchIocData(p);
                }}
              >
                Previous
              </button>
              <span style={{ fontSize: '12px', color: 'var(--at-text-muted)' }}>
                Page {currentPage} of {totalPages} {total > 0 ? `(${total} indicators)` : ''}
              </span>
              <button
                type="button"
                className="at-btn at-btn-ghost at-btn-sm"
                disabled={currentPage === totalPages || isLoading}
                onClick={() => {
                  const p = Math.min(totalPages, currentPage + 1);
                  setCurrentPage(p);
                  void fetchIocData(p);
                }}
              >
                Next
              </button>
            </div>
          )}
        </section>

        {/* ================================================================ */
        /* INSPECTOR                                                          */
        /* ================================================================ */}

        <aside className="w-[400px] shrink-0 border border-[#222] rounded-lg bg-[#111] flex flex-col sticky top-[90px] h-[calc(100vh-140px)] overflow-hidden">
          {!selectedIoc ? (
            <div
              className="at-ioc-empty-state"
              style={{
                flex: 1,
              }}
            >
              <ShieldAlert
                size={28}
                className="mb-2 opacity-20"
              />

              <strong>
                No Indicator Selected
              </strong>

              <span>
                Select an IOC from the list to
                view its properties and context.
              </span>
            </div>
          ) : (
            <>
              <div className="at-ioc-inspector-head">
                <div className="at-ioc-inspector-heading">
                  <span
                    className={`at-ioc-inspector-icon ${selectedIoc.type}`}
                  >
                    {(() => {
                      const Icon =
                        TYPE_ICONS[
                        selectedIoc.type as IocType
                        ] ??
                        Hash;

                      return (
                        <Icon size={19} />
                      );
                    })()}
                  </span>

                  <div>
                    <span>
                      {typeLabel(
                        selectedIoc.type,
                      )}
                    </span>

                    <strong
                      title={
                        selectedIoc.value
                      }
                    >
                      {selectedIoc.value}
                    </strong>
                  </div>
                </div>

                <button
                  type="button"
                  className="at-ioc-close"
                  onClick={() =>
                    setSelectedIocId(
                      null,
                    )
                  }
                  aria-label="Close inspector"
                >
                  <X size={15} />
                </button>
              </div>

              <div className="at-ioc-inspector-meta">
                <span
                  className={`at-ioc-inspector-severity ${selectedIoc.severity}`}
                >
                  <i />

                  {String(
                    selectedIoc.severity,
                  ).toUpperCase()}{' '}
                  RISK
                </span>

                <span className="at-ioc-inspector-source">
                  {selectedIoc.source}
                </span>
              </div>

              {/* ---------------------------------------------------------- */
              /* Tabs                                                        */
              /* ---------------------------------------------------------- */}

              <div
                className="at-ioc-tabs"
                role="tablist"
                aria-label="IOC details"
              >
                {(
                  [
                    'Overview',
                    'Timeline',
                    'Relationships',
                  ] as const
                ).map(
                  (tab) => (
                    <button
                      type="button"
                      key={tab}
                      className={
                        inspectorTab ===
                          tab
                          ? 'active'
                          : ''
                      }
                      onClick={() =>
                        setInspectorTab(
                          tab,
                        )
                      }
                      role="tab"
                      aria-selected={
                        inspectorTab ===
                        tab
                      }
                    >
                      {tab}
                    </button>
                  ),
                )}
              </div>

              {/* ---------------------------------------------------------- */
              /* Inspector content                                           */
              /* ---------------------------------------------------------- */}

              <div className="flex-1 overflow-y-auto custom-scrollbar p-0">
                {inspectorTab ===
                  'Overview' && (
                    <div className="at-ioc-inspector-content">
                      {/* Observation */}

                      <section className="at-ioc-inspector-block">
                        <div className="at-ioc-block-title">
                          <span>
                            OBSERVATION
                          </span>

                          <Activity
                            size={12}
                          />
                        </div>

                        <div className="at-ioc-observation-grid">
                          <div>
                            <span>
                              First Seen
                            </span>

                            <code>
                              {formatDateTime(
                                selectedIoc.firstSeen,
                              )}
                            </code>
                          </div>

                          <div>
                            <span>
                              Last Seen
                            </span>

                            <code>
                              {formatDateTime(
                                selectedIoc.lastSeen,
                              )}
                            </code>
                          </div>
                        </div>
                      </section>

                      {/* Intelligence tags */}

                      <section className="at-ioc-inspector-block">
                        <div className="at-ioc-block-title">
                          <span>
                            INTELLIGENCE TAGS
                          </span>

                          <Hash size={12} />
                        </div>

                        {selectedIoc.tags
                          .length > 0 ? (
                          <div className="at-ioc-inspector-tags">
                            {selectedIoc.tags.map(
                              (
                                tag,
                                index,
                              ) => (
                                <span
                                  key={`${tag}-${index}`}
                                >
                                  {tag}
                                </span>
                              ),
                            )}
                          </div>
                        ) : (
                          <div className="at-ioc-inline-empty">
                            No intelligence tags
                            recorded.
                          </div>
                        )}
                      </section>

                      {/* Source */}

                      <section className="at-ioc-inspector-block">
                        <div className="at-ioc-block-title">
                          <span>
                            SOURCE
                          </span>

                          <Globe
                            size={12}
                          />
                        </div>

                        <div className="at-ioc-source-card">
                          <strong>
                            {
                              selectedIoc.source
                            }
                          </strong>

                          <span>
                            Intelligence
                            provider
                          </span>
                        </div>
                      </section>

                      {/* Indicator metadata */}

                      <section className="at-ioc-inspector-block">
                        <div className="at-ioc-block-title">
                          <span>
                            INDICATOR METADATA
                          </span>

                          <Hash size={12} />
                        </div>

                        <div className="at-ioc-metadata-grid">
                          <div>
                            <span>
                              ID
                            </span>

                            <code>
                              {
                                selectedIoc.id
                              }
                            </code>
                          </div>

                          <div>
                            <span>
                              TYPE
                            </span>

                            <code>
                              {
                                selectedIoc.type
                              }
                            </code>
                          </div>

                          <div>
                            <span>
                              SEVERITY
                            </span>

                            <strong>
                              {
                                selectedIoc.severity
                              }
                            </strong>
                          </div>
                        </div>
                      </section>

                      {/* Actions */}

                      <section className="at-ioc-inspector-block">
                        <div className="at-ioc-block-title">
                          <span>
                            ANALYST ACTIONS
                          </span>

                          <Target size={12} />
                        </div>

                        <div className="at-ioc-action-list">
                          <button
                            type="button"
                            className="at-ioc-action"
                            onClick={() =>
                              onNavigate(
                                'analysis',
                              )
                            }
                          >
                            <span className="at-ioc-action-icon">
                              <Target
                                size={12}
                              />
                            </span>

                            <span>
                              <strong>
                                Hunt in analysis
                              </strong>

                              <small>
                                Pivot into host
                                analysis for
                                investigation.
                              </small>
                            </span>

                            <ArrowUpRight
                              size={12}
                            />
                          </button>

                          <button
                            type="button"
                            className="at-ioc-action"
                            onClick={() =>
                              onNavigate(
                                'investigate',
                              )
                            }
                          >
                            <span className="at-ioc-action-icon">
                              <Network
                                size={12}
                              />
                            </span>

                            <span>
                              <strong>
                                Pivot to investigation
                              </strong>

                              <small>
                                Continue investigation
                                in the relationship
                                workspace.
                              </small>
                            </span>

                            <ArrowUpRight
                              size={12}
                            />
                          </button>
                        </div>
                      </section>
                    </div>
                  )}

                {inspectorTab ===
                  'Timeline' && (
                    <div className="at-ioc-empty-state">
                      <Activity
                        size={22}
                      />

                      <strong>
                        No timeline events
                      </strong>

                      <span>
                        No timeline events are attached
                        to this indicator in the current
                        application data.
                      </span>
                    </div>
                  )}

                {inspectorTab ===
                  'Relationships' && (
                    <div className="at-ioc-empty-state">
                      <Network
                        size={22}
                      />

                      <strong>
                        No relationships
                      </strong>

                      <span>
                        No related entities are attached
                        to this indicator in the current
                        application data.
                      </span>
                    </div>
                  )}
              </div>

              {/* ---------------------------------------------------------- */
              /* Footer                                                       */
              /* ---------------------------------------------------------- */}

              <div className="at-ioc-inspector-footer">
                {canExportIoc && (<button
                  type="button"
                  className="at-btn at-btn-secondary"
                  onClick={
                    exportSelectedIoc
                  }
                >
                  <Download size={12} />
                  Export IOC
                </button>)}

                <button
                  type="button"
                  className="at-btn at-btn-primary"
                  onClick={() =>
                    onNavigate(
                      'investigate',
                    )
                  }
                >
                  <ArrowUpRight
                    size={12}
                  />
                  Investigate
                </button>
              </div>
            </>
          )}
        </aside>
      </div>
        </div>
      </div>
    </div>
  );
}
