import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowUpDown,
  BarChart2,
  Briefcase,
  Bug,
  Cable,
  Calendar,
  CheckCircle2,
  Cpu,
  Database,
  Eye,
  Filter,
  Flame,
  FolderPlus,
  Globe,
  Info,
  Loader2,
  Lock,
  Network,
  Play,
  RefreshCw,
  RotateCw,
  Save,
  ServerCog,
  Settings2,
  ShieldAlert,
  Sparkles,
  Tag,
  Target,
  Trash2,
  X,
  XCircle,
  CheckSquare,
  ChevronDown,
  Clock,
  Cloud,
  Download,
  ExternalLink,
  Plus,
  Search,
  Terminal,
} from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts';
import {
  AssetQueryParams,
  Asset,
  openasm,
  OpenAsmHealthResponse,
  Target as AsmTarget,
  TargetQueryParams,
  TlsAsset,
  Vulnerability,
  VulnerabilityQueryParams,
  Workspace,
  WorkspaceQueryParams,
  OpenAsmApiError,
  StatisticsTimelinePoint,
  AssetLocation,
  IssuesTimelinePoint,
  AssetGroupTab,
  AsmWorker,
  AsmRiskAssessment,
} from '../../api/services/openasmClient';
import { DashboardAssetLocationsMap } from '../recon/DashboardAssetLocationsMap';
import { InventoryAllServicesTable, InventoryGroupedTable } from '../recon/InventoryServiceTables';
import { VulnerabilityDetailModal, vulnSeverityBadgeClass } from '../recon/VulnerabilityDetailModal';
import { TargetRiskModal } from '../recon/TargetRiskModal';
import { IntegrationsView } from './IntegrationsView';
import { useAuth } from '../../contexts/AuthContext';

const INVENTORY_SUBTAB_LABELS: Record<AssetGroupTab, string> = {
  all: 'All Services',
  ip: 'IP Addresses',
  port: 'Ports',
  tech: 'Technologies',
  host: 'Hosts',
  'status-code': 'Status Code',
  tls: 'TLS',
};

function formatRelativeAgo(iso: string | undefined): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return String(iso);
  const sec = Math.round((t - Date.now()) / 1000);
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  const a = Math.abs(sec);
  if (a < 60) return rtf.format(sec, 'second');
  if (a < 3600) return rtf.format(Math.round(sec / 60), 'minute');
  if (a < 86400) return rtf.format(Math.round(sec / 3600), 'hour');
  if (a < 2592000) return rtf.format(Math.round(sec / 86400), 'day');
  return new Date(iso).toISOString().slice(0, 10);
}

type DiscoveryTargetKind = 'DOMAIN' | 'CIDR' | 'IP';

/**
 * Returns a bare hostname for DOMAIN targets (no scheme, path, query, port, or trailing slashes).
 * Discovery API expects plain domains.
 */
function normalizeDiscoveryDomainInput(raw: string): string {
  let s = raw.trim().replace(/^\/+/, '');
  if (!s) return '';
  const withScheme = /^[a-z][\w+.-]*:/i.test(s) ? s : `https://${s}`;
  try {
    const { hostname } = new URL(withScheme);
    if (!hostname) return s.split(/[/?:#]/)[0].replace(/^[^@]*@/, '').replace(/:\d+$/, '').toLowerCase().trim();
    return hostname.replace(/\.$/, '').toLowerCase();
  } catch {
    return s
      .replace(/^[a-z][\w+.-]*:\/\//i, '')
      .split(/[/?:#]/)[0]
      .replace(/^[^@]*@/, '')
      .replace(/:\d+$/, '')
      .replace(/\.+$/, '')
      .toLowerCase()
      .trim();
  }
}

function normalizeDiscoveryTargetValue(raw: string, type: DiscoveryTargetKind): string {
  const t = raw.trim();
  if (!t) return '';
  if (type === 'DOMAIN') return normalizeDiscoveryDomainInput(t);
  return t.replace(/\s+/g, '');
}

type InventoryFacetState = {
  ipAddresses: string[];
  ports: string[];
  techs: string[];
  statusCodes: string[];
  hosts: string[];
  tlsHosts: string[];
};

const EMPTY_INVENTORY_FACETS: InventoryFacetState = {
  ipAddresses: [],
  ports: [],
  techs: [],
  statusCodes: [],
  hosts: [],
  tlsHosts: [],
};

type InventoryFacetMenu = keyof InventoryFacetState;

const FACET_MENU_LABEL: Record<InventoryFacetMenu, string> = {
  ipAddresses: 'IP',
  ports: 'Port',
  techs: 'Technology',
  statusCodes: 'Status Code',
  hosts: 'Host',
  tlsHosts: 'TLS Host',
};

const FACET_GROUP: Record<InventoryFacetMenu, AssetGroupTab> = {
  ipAddresses: 'ip',
  ports: 'port',
  techs: 'tech',
  statusCodes: 'status-code',
  hosts: 'host',
  tlsHosts: 'tls',
};

function facetRowPickValue(group: AssetGroupTab, row: Record<string, unknown>): string | null {
  if (group === 'ip') return row.ip != null ? String(row.ip) : null;
  if (group === 'port') return row.port != null ? String(row.port) : null;
  if (group === 'tech') {
    const tech = row.technology as Record<string, unknown> | undefined;
    if (tech?.name != null) return String(tech.name);
    if (row.name != null) return String(row.name);
    return null;
  }
  if (group === 'status-code') {
    if (row.statusCode != null) return String(row.statusCode);
    if (row.status_code != null) return String(row.status_code);
    return null;
  }
  if (group === 'host') return row.host != null ? String(row.host) : null;
  if (group === 'tls') {
    const sni = row.sni != null ? String(row.sni) : '';
    const host = row.host != null ? String(row.host) : '';
    return sni || host || null;
  }
  return null;
}

function buildFacetPickerParams(
  menu: InventoryFacetMenu,
  targetId: string,
  valueDebounced: string,
  facets: InventoryFacetState,
  search: string,
): AssetQueryParams {
  const group = FACET_GROUP[menu];
  const base: AssetQueryParams = {
    targetIds: targetId,
    page: 1,
    limit: 100,
    value: valueDebounced || undefined,
  };
  if (group === 'ip') {
    base.sortBy = 'value';
    base.sortOrder = 'ASC';
  }
  if (menu !== 'ipAddresses' && facets.ipAddresses.length) base.ipAddresses = [...facets.ipAddresses];
  if (['techs', 'statusCodes', 'hosts', 'tlsHosts'].includes(menu) && facets.ports.length) base.ports = [...facets.ports];
  if (['statusCodes', 'hosts', 'tlsHosts'].includes(menu) && facets.techs.length) base.techs = [...facets.techs];
  if (['hosts', 'tlsHosts'].includes(menu) && facets.statusCodes.length) base.statusCodes = [...facets.statusCodes];
  if (menu === 'tlsHosts' && facets.hosts.length) base.hosts = [...facets.hosts];
  if (menu === 'tlsHosts' && search.trim()) base.search = search.trim();
  return base;
}

function buildWorkspaceFacetPickerParams(
  menu: InventoryFacetMenu,
  valueDebounced: string,
  facets: InventoryFacetState,
  search: string,
): AssetQueryParams {
  const group = FACET_GROUP[menu];
  const base: AssetQueryParams = {
    page: 1,
    limit: 100,
    value: valueDebounced || undefined,
  };
  if (group === 'ip') {
    base.sortBy = 'value';
    base.sortOrder = 'ASC';
  }
  if (menu !== 'ipAddresses' && facets.ipAddresses.length) base.ipAddresses = [...facets.ipAddresses];
  if (['techs', 'statusCodes', 'hosts', 'tlsHosts'].includes(menu) && facets.ports.length) base.ports = [...facets.ports];
  if (['statusCodes', 'hosts', 'tlsHosts'].includes(menu) && facets.techs.length) base.techs = [...facets.techs];
  if (['hosts', 'tlsHosts'].includes(menu) && facets.statusCodes.length) base.statusCodes = [...facets.statusCodes];
  if (menu === 'tlsHosts' && facets.hosts.length) base.hosts = [...facets.hosts];
  if (menu === 'tlsHosts' && search.trim()) base.search = search.trim();
  return base;
}

/** Discovery / scan still running — keep polling the targets list. */
function targetScanNeedsPolling(status: unknown): boolean {
  const s = String(status ?? '').toLowerCase().replace(/_/g, '-');
  return ['in-progress', 'running', 'discovering', 'pending', 'queued', 'starting', 'processing'].includes(s);
}

function normalizeTargetStatus(status: unknown): string {
  return String(status ?? 'unknown').toLowerCase().replace(/_/g, '-');
}

function targetListStatusPresentation(status: unknown): { label: string; pillClass: string } {
  const s = normalizeTargetStatus(status);
  if (s === 'completed') {
    return { label: 'Completed', pillClass: 'border-emerald-500/45 text-emerald-300 bg-emerald-950/35' };
  }
  if (['in-progress', 'running', 'discovering', 'processing'].includes(s)) {
    return { label: 'In progress', pillClass: 'border-neutral-500/45 text-white bg-neutral-950/35' };
  }
  if (s === 'failed') {
    return { label: 'Failed', pillClass: 'border-red-500/45 text-red-300 bg-red-950/35' };
  }
  return { label: status ? String(status) : 'Unknown', pillClass: 'border-neutral-600 text-[#AAA] bg-neutral-950/40' };
}

const SCAN_SCHEDULE_OPTIONS: { label: string; cron: string }[] = [
  { label: 'Disabled', cron: '' },
  { label: 'Daily', cron: '0 0 * * *' },
  { label: 'Every 3 days', cron: '0 0 */3 * *' },
  { label: 'Weekly', cron: '0 0 * * 0' },
  { label: 'Every 2 weeks', cron: '0 0 1,15 * *' },
  { label: 'Monthly', cron: '0 0 1 * *' },
];

function workerSeenOnline(lastSeenAt: string | undefined): boolean {
  if (!lastSeenAt) return false;
  const t = new Date(lastSeenAt).getTime();
  if (Number.isNaN(t)) return false;
  return Date.now() - t < 180_000;
}

type TabId = 'dashboard' | 'targets' | 'assets' | 'vulnerabilities' | 'workers' | 'workspaces' | 'connectors';

const TAB_CONFIG: { id: TabId; label: string; icon: React.ElementType }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart2 },
  { id: 'targets', label: 'Targets', icon: Target },
  { id: 'assets', label: 'Assets', icon: Database },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { id: 'workers', label: 'Workers', icon: Cpu },
  { id: 'workspaces', label: 'Workspaces', icon: ServerCog },
];

export const XyberahReconView: React.FC = () => {
  const { permissions, can, permissionsLoaded } = useAuth();
  const hasOsmAccess = permissions.some((p) => p.startsWith('osm.'));
  const hasIntegrationsAccess = permissions.some((p) => p.startsWith('integrations.'));
  const canManageTargets = can('osm.targets.manage');

  const visibleTabs = useMemo(() => {
    const tabs = [...TAB_CONFIG];
    if (hasIntegrationsAccess) {
      tabs.push({ id: 'connectors', label: 'SIEM Connectors', icon: Cable });
    }
    return tabs;
  }, [hasIntegrationsAccess]);

  const parseRouteState = () => {
    const pathMatch = window.location.pathname.match(/\/targets\/([^/?#]+)/);
    const search = new URLSearchParams(window.location.search);
    return {
      routeTargetId: pathMatch?.[1] ? decodeURIComponent(pathMatch[1]) : null,
      routeTargetTab: (search.get('targetTab') === 'vulnerabilities' ? 'vulnerabilities' : 'inventory') as 'inventory' | 'vulnerabilities',
      routeAnimation: search.get('animation') === 'true',
    };
  };
  const initialRoute = parseRouteState();
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [loading, setLoading] = useState(false);
  const [workspaceLoading, setWorkspaceLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [assessImmediately, setAssessImmediately] = useState(false);
  const [riskModalOpen, setRiskModalOpen] = useState(false);
  const [riskModalTarget, setRiskModalTarget] = useState<AsmTarget | null>(null);
  const [riskModalAssessment, setRiskModalAssessment] = useState<AsmRiskAssessment | null>(null);
  const [riskModalLoading, setRiskModalLoading] = useState(false);

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<string>('');
  const [integrationDefaultWorkspaceId, setIntegrationDefaultWorkspaceId] = useState<string>('');

  const [targets, setTargets] = useState<AsmTarget[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetsMeta, setAssetsMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [assetGroupTab, setAssetGroupTab] = useState<AssetGroupTab>('all');
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [assetDetail, setAssetDetail] = useState<Asset | null>(null);
  const [assetDetailLoading, setAssetDetailLoading] = useState(false);
  const [assetTagsText, setAssetTagsText] = useState('');
  const [assetEnabled, setAssetEnabled] = useState<boolean | null>(null);
  const [aiDomain, setAiDomain] = useState('');
  const [aiTags, setAiTags] = useState<string[]>([]);
  const [assetGroupName, setAssetGroupName] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [vulnMeta, setVulnMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [vulnStats, setVulnStats] = useState<Record<string, number>>({});
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);
  const [vulnDetail, setVulnDetail] = useState<Vulnerability | null>(null);
  const [vulnDetailLoading, setVulnDetailLoading] = useState(false);
  const [statistics, setStatistics] = useState<Record<string, unknown> | null>(null);
  const [metadata, setMetadata] = useState<Record<string, unknown> | null>(null);
  const [health, setHealth] = useState<OpenAsmHealthResponse | null>(null);
  const [timeline, setTimeline] = useState<StatisticsTimelinePoint[]>([]);
  const [issuesTimeline, setIssuesTimeline] = useState<IssuesTimelinePoint[]>([]);
  const [assetLocations, setAssetLocations] = useState<AssetLocation[]>([]);
  const [tlsAssets, setTlsAssets] = useState<TlsAsset[]>([]);
  const [tlsMeta, setTlsMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [topAssetsVuln, setTopAssetsVuln] = useState<Record<string, unknown>[]>([]);
  const [topTagsAssets, setTopTagsAssets] = useState<Record<string, unknown>[]>([]);

  const [targetValue, setTargetValue] = useState('');
  const [targetType, setTargetType] = useState<'DOMAIN' | 'CIDR' | 'IP'>('DOMAIN');
  const [bulkTargetsText, setBulkTargetsText] = useState('');
  const [workspaceName, setWorkspaceName] = useState('');
  const [workspaceDescription, setWorkspaceDescription] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);
  const [targetDetail, setTargetDetail] = useState<AsmTarget | null>(null);
  const [targetDetailLoading, setTargetDetailLoading] = useState(false);
  const [targetDetailTab, setTargetDetailTab] = useState<'inventory' | 'vulnerabilities'>(initialRoute.routeTargetTab);
  const [discoveringAnimation, setDiscoveringAnimation] = useState<boolean>(initialRoute.routeAnimation);
  const [scheduleValue, setScheduleValue] = useState('');
  const [targetInventoryGroup, setTargetInventoryGroup] = useState<AssetGroupTab>('all');
  const [targetInventory, setTargetInventory] = useState<Asset[]>([]);
  const [targetInventoryMeta, setTargetInventoryMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [targetInventoryParams, setTargetInventoryParams] = useState<AssetQueryParams>({
    page: 1,
    limit: 10,
    sortBy: 'createdAt',
    sortOrder: 'DESC',
    value: '',
  });
  const [inventoryFacets, setInventoryFacets] = useState<InventoryFacetState>(() => ({ ...EMPTY_INVENTORY_FACETS }));
  const [openInventoryFacet, setOpenInventoryFacet] = useState<InventoryFacetMenu | null>(null);
  const [inventoryFacetSearch, setInventoryFacetSearch] = useState('');
  const [debouncedInventoryFacetSearch, setDebouncedInventoryFacetSearch] = useState('');
  const [inventoryFacetRows, setInventoryFacetRows] = useState<Asset[]>([]);
  const [inventoryFacetLoading, setInventoryFacetLoading] = useState(false);
  const [discoveryModalOpen, setDiscoveryModalOpen] = useState(false);
  const [discoveryModalError, setDiscoveryModalError] = useState<string | null>(null);
  const inventoryFacetReqId = React.useRef(0);
  const inventoryFacetBarRef = React.useRef<HTMLDivElement>(null);
  const assetsFacetReqId = React.useRef(0);
  const assetsFacetBarRef = React.useRef<HTMLDivElement>(null);
  const [debouncedInventoryValue, setDebouncedInventoryValue] = useState('');
  const [debouncedAssetValue, setDebouncedAssetValue] = useState('');
  const [assetsFacets, setAssetsFacets] = useState<InventoryFacetState>(() => ({ ...EMPTY_INVENTORY_FACETS }));
  const [openAssetsFacet, setOpenAssetsFacet] = useState<InventoryFacetMenu | null>(null);
  const [assetsFacetSearch, setAssetsFacetSearch] = useState('');
  const [debouncedAssetsFacetSearch, setDebouncedAssetsFacetSearch] = useState('');
  const [assetsFacetRows, setAssetsFacetRows] = useState<Asset[]>([]);
  const [assetsFacetLoading, setAssetsFacetLoading] = useState(false);
  const [assetsListRefreshing, setAssetsListRefreshing] = useState(false);
  const [healthLoading, setHealthLoading] = useState(false);
  const [targetsMeta, setTargetsMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [targetParams, setTargetParams] = useState<TargetQueryParams>({
    page: 1,
    limit: 10,
    sortBy: 'createdAt',
    sortOrder: 'DESC',
    value: '',
    search: '',
    type: '',
    status: '',
  });
  const [debouncedTargetListValue, setDebouncedTargetListValue] = useState('');
  useEffect(() => {
    const v = targetInventoryParams.value ?? '';
    const tid = window.setTimeout(() => setDebouncedInventoryValue(v), 320);
    return () => window.clearTimeout(tid);
  }, [targetInventoryParams.value]);

  useEffect(() => {
    const tid = window.setTimeout(() => setDebouncedInventoryFacetSearch(inventoryFacetSearch), 220);
    return () => window.clearTimeout(tid);
  }, [inventoryFacetSearch]);

  useEffect(() => {
    const tid = window.setTimeout(() => setDebouncedTargetListValue(targetParams.value ?? ''), 320);
    return () => window.clearTimeout(tid);
  }, [targetParams.value]);

  useEffect(() => {
    const tid = window.setTimeout(() => setDebouncedAssetsFacetSearch(assetsFacetSearch), 220);
    return () => window.clearTimeout(tid);
  }, [assetsFacetSearch]);

  const targetInventoryFetchParams = useMemo(
    () => ({ ...targetInventoryParams, value: debouncedInventoryValue }),
    [targetInventoryParams, debouncedInventoryValue],
  );
  const [targetVulnerabilities, setTargetVulnerabilities] = useState<Vulnerability[]>([]);
  const [targetVulnMeta, setTargetVulnMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [targetVulnStats, setTargetVulnStats] = useState<Record<string, number>>({});
  const [targetVulnParams, setTargetVulnParams] = useState<VulnerabilityQueryParams>({
    page: 1,
    limit: 10,
    sortBy: 'severity',
    sortOrder: 'DESC',
    status: 'open',
    severity: '',
    search: '',
    createdFrom: '',
    createdTo: '',
  });
  const [screenshotModalUrl, setScreenshotModalUrl] = useState<string | null>(null);
  const [assetParams, setAssetParams] = useState<AssetQueryParams>({
    page: 1,
    limit: 50,
    sortBy: 'createdAt',
    sortOrder: 'DESC',
    type: '',
    search: '',
    value: '',
    targetIds: '',
    ipAddresses: '',
    ports: '',
    hosts: '',
    techs: '',
    statusCodes: '',
    tlsHosts: '',
  });

  useEffect(() => {
    const tid = window.setTimeout(() => setDebouncedAssetValue(assetParams.value ?? ''), 320);
    return () => window.clearTimeout(tid);
  }, [assetParams.value]);

  const [vulnParams, setVulnParams] = useState<VulnerabilityQueryParams>({
    page: 1,
    limit: 10,
    sortBy: 'severity',
    sortOrder: 'DESC',
    status: 'open',
    severity: '',
    search: '',
    createdFrom: '',
    createdTo: '',
  });
  const [workspaceParams, setWorkspaceParams] = useState<WorkspaceQueryParams>({
    page: 1,
    limit: 100,
    isArchived: false,
  });
  const tabsRequiringWorkspace: TabId[] = ['dashboard', 'targets', 'assets', 'vulnerabilities', 'workers'];

  const [targetsRefreshing, setTargetsRefreshing] = useState(false);
  const [targetSettingsOpen, setTargetSettingsOpen] = useState(false);
  const [workers, setWorkers] = useState<AsmWorker[]>([]);
  const [workersMeta, setWorkersMeta] = useState<{ total?: number; page?: number; limit?: number; pageCount?: number; hasNextPage?: boolean }>({});
  const [workersRefreshing, setWorkersRefreshing] = useState(false);
  const [workerParams] = useState({ page: 1, limit: 100, sortBy: 'createdAt', sortOrder: 'DESC' as const });
  const [debouncedTargetVulnSearch, setDebouncedTargetVulnSearch] = useState('');
  const [debouncedGlobalVulnSearch, setDebouncedGlobalVulnSearch] = useState('');
  const [vulnModalDismissLoading, setVulnModalDismissLoading] = useState(false);
  const [vulnListRefreshing, setVulnListRefreshing] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setWorkspaceLoading(true);
      setError(null);
      try {
        const [activeRes, listRes] = await Promise.all([
          openasm.getActiveWorkspace().catch(() => null as { workspaceId: string } | null),
          openasm.listWorkspaces({ page: 1, limit: 100, isArchived: false }),
        ]);
        if (cancelled) return;
        const list = listRes.data ?? [];
        setWorkspaces(list);
        const activeId = activeRes?.workspaceId ?? '';
        setIntegrationDefaultWorkspaceId(activeId);
        const inList = activeId && list.some((w) => w.id === activeId);
        const pick = inList ? activeId : list[0]?.id ?? '';
        setSelectedWorkspaceId(pick);
        if (!pick && list.length === 0) {
          setError('No workspaces available. Create one or run bootstrap from the backend.');
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : 'Failed to load workspaces');
        }
      } finally {
        if (!cancelled) setWorkspaceLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleOpenRiskModal = useCallback(async (t: AsmTarget) => {
    setRiskModalTarget(t);
    setRiskModalOpen(true);
    setRiskModalLoading(true);
    setRiskModalAssessment((t.assessment as AsmRiskAssessment | null) || null);
    try {
      const res = await openasm.getTargetRisk(t.id, selectedWorkspaceId);
      setRiskModalAssessment(res.assessment || null);
      if (res.target) {
        setRiskModalTarget(res.target);
      }
    } catch (err) {
      console.error('Failed to load target risk', err);
    } finally {
      setRiskModalLoading(false);
    }
  }, [selectedWorkspaceId]);

  const setTargetRoute = useCallback((targetId: string | null, tab?: 'inventory' | 'vulnerabilities', animation?: boolean) => {
    const nextTab = tab ?? targetDetailTab;
    const url = new URL(window.location.href);
    if (targetId) {
      url.pathname = `/targets/${encodeURIComponent(targetId)}`;
      url.searchParams.set('targetTab', nextTab);
      if (animation) url.searchParams.set('animation', 'true');
      else url.searchParams.delete('animation');
    } else {
      url.pathname = '/';
      url.searchParams.delete('targetTab');
      url.searchParams.delete('animation');
    }
    window.history.pushState({}, '', url.toString());
  }, [targetDetailTab]);

  useEffect(() => {
    if (!initialRoute.routeTargetId) return;
    setSelectedTargetId(initialRoute.routeTargetId);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const formatApiError = useCallback((error: unknown): string => {
    const e = error as OpenAsmApiError;
    const status = e?.response?.status;
    const data = e?.response?.data;
    if (status === 402 || data?.code === 'PLAN_INACTIVE') {
      return 'Plan Inactive: Your subscription does not have active attack surface scanning. Please upgrade your plan to run scans.';
    }
    if (status === 429 || data?.code === 'RESCAN_TOO_SOON') {
      return (typeof data?.message === 'string' ? data.message : null) || 'This target was scanned recently. Scans are limited to once per 10 minutes. Please wait before rescanning.';
    }
    if (status === 400 && (data?.reason === 'target_limit_reached' || data?.limit)) {
      return `Target limit reached (${data?.limit || 25} max). Your account has reached the maximum target cap. Delete existing targets or upgrade your plan.`;
    }
    if (status === 403) {
      return (typeof data?.message === 'string' ? data.message : null) || 'Access denied: Missing required permission for this action.';
    }
    if (status === 502 || status === 503) {
      return 'Scanner service upstream unavailable. Please retry shortly.';
    }
    if (status === 400 && data?.issues?.length) {
      return data.issues.map((i) => `${i.field ?? 'field'}: ${i.message ?? 'invalid value'}`).join(' | ');
    }
    if (typeof data?.message === 'string') return data.message;
    if (Array.isArray(data?.message)) return data.message.join(' | ');
    if (data?.error) return data.error;
    if (e instanceof Error) return e.message;
    return 'Request failed';
  }, []);

  const loadDashboard = useCallback(async (workspaceId: string) => {
    const [metaRes, statsRes, timelineRes, issuesTimelineRes, locationsRes, tlsRes, topAssetsRes, topTagsRes] = await Promise.all([
      openasm.getMetadata().catch(() => null),
      openasm.getStatistics(workspaceId),
      openasm.getStatisticsTimeline(workspaceId),
      openasm.getIssuesTimeline(workspaceId).catch(() => ({ data: [] })),
      openasm.getAssetLocations(workspaceId),
      openasm.getTlsAssets({ page: 1, limit: 10, sortBy: 'createdAt', sortOrder: 'DESC' }, workspaceId),
      openasm.getTopAssetsVulnerabilities(workspaceId),
      openasm.getTopTagsAssets(workspaceId),
    ]);
    setMetadata(metaRes);
    setStatistics(statsRes);
    setTimeline(timelineRes.data ?? []);
    setIssuesTimeline(issuesTimelineRes.data ?? []);
    setAssetLocations(Array.isArray(locationsRes) ? locationsRes : []);
    setTlsAssets(tlsRes.data ?? []);
    setTlsMeta({
      total: tlsRes.total,
      page: tlsRes.page,
      limit: tlsRes.limit,
      pageCount: tlsRes.pageCount,
      hasNextPage: tlsRes.hasNextPage,
    });
    setTopAssetsVuln(Array.isArray(topAssetsRes) ? topAssetsRes : []);
    setTopTagsAssets(Array.isArray(topTagsRes) ? topTagsRes : []);
  }, []);

  const loadTargets = useCallback(async (workspaceId: string) => {
    const result = await openasm.listTargets(
      {
        page: targetParams.page,
        limit: targetParams.limit,
        sortBy: targetParams.sortBy,
        sortOrder: targetParams.sortOrder,
        type: targetParams.type,
        status: targetParams.status,
        search: targetParams.search,
        value: debouncedTargetListValue,
      },
      workspaceId,
    );
    setTargets(result.data ?? []);
    setTargetsMeta({
      total: result.total,
      page: result.page,
      limit: result.limit,
      pageCount: result.pageCount,
      hasNextPage: result.hasNextPage,
    });
  }, [
    targetParams.page,
    targetParams.limit,
    targetParams.sortBy,
    targetParams.sortOrder,
    targetParams.type,
    targetParams.status,
    targetParams.search,
    debouncedTargetListValue,
  ]);

  const refreshTargetsSilently = useCallback(async (workspaceId: string) => {
    try {
      const result = await openasm.listTargets(
        {
          page: targetParams.page,
          limit: targetParams.limit,
          sortBy: targetParams.sortBy,
          sortOrder: targetParams.sortOrder,
          type: targetParams.type,
          status: targetParams.status,
          search: targetParams.search,
          value: debouncedTargetListValue,
        },
        workspaceId,
      );
      setTargets(result.data ?? []);
      setTargetsMeta({
        total: result.total,
        page: result.page,
        limit: result.limit,
        pageCount: result.pageCount,
        hasNextPage: result.hasNextPage,
      });
    } catch {
      /* keep last good data */
    }
  }, [
    targetParams.page,
    targetParams.limit,
    targetParams.sortBy,
    targetParams.sortOrder,
    targetParams.type,
    targetParams.status,
    targetParams.search,
    debouncedTargetListValue,
  ]);

  const loadAssets = useCallback(
    async (workspaceId: string) => {
      let sortBy = assetParams.sortBy;
      let sortOrder = assetParams.sortOrder;
      if (assetGroupTab === 'ip') {
        sortBy = 'value';
        sortOrder = 'ASC';
      }
      const params: AssetQueryParams = {
        page: assetParams.page,
        limit: assetParams.limit,
        sortBy,
        sortOrder,
        type: assetParams.type || undefined,
        search: assetParams.search || undefined,
        value: debouncedAssetValue || undefined,
      };
      if (assetsFacets.ipAddresses.length) params.ipAddresses = [...assetsFacets.ipAddresses];
      if (assetsFacets.ports.length) params.ports = [...assetsFacets.ports];
      if (assetsFacets.techs.length) params.techs = [...assetsFacets.techs];
      if (assetsFacets.statusCodes.length) params.statusCodes = [...assetsFacets.statusCodes];
      if (assetsFacets.hosts.length) params.hosts = [...assetsFacets.hosts];
      if (assetsFacets.tlsHosts.length) params.tlsHosts = [...assetsFacets.tlsHosts];
      const result = await openasm.listAssetsByGroup(assetGroupTab, params, workspaceId);
      setAssets(result.data ?? []);
      setAssetsMeta({
        total: result.total,
        page: result.page,
        limit: result.limit,
        pageCount: result.pageCount,
        hasNextPage: result.hasNextPage,
      });
    },
    [assetGroupTab, assetParams, assetsFacets, debouncedAssetValue],
  );

  const loadVulnerabilities = useCallback(async (workspaceId: string) => {
    const [list, stats] = await Promise.all([
      openasm.listVulnerabilities(
        { ...vulnParams, search: debouncedGlobalVulnSearch || undefined },
        workspaceId,
      ),
      openasm.getVulnerabilityStatistics(workspaceId),
    ]);
    setVulnerabilities(list.data ?? []);
    setVulnMeta({
      total: list.total,
      page: list.page,
      limit: list.limit,
      pageCount: list.pageCount,
      hasNextPage: list.hasNextPage,
    });
    const map: Record<string, number> = {};
    for (const item of stats.data ?? []) map[item.severity] = item.count;
    setVulnStats(map);
  }, [vulnParams, debouncedGlobalVulnSearch]);

  const loadTargetDetail = useCallback(async (workspaceId: string, targetId: string) => {
    const detail = await openasm.getTargetById(targetId, workspaceId);
    setTargetDetail(detail);
    setScheduleValue(String(detail.scanSchedule ?? ''));
    const status = normalizeTargetStatus(detail.status);
    setDiscoveringAnimation(['in-progress', 'running', 'discovering', 'processing'].includes(status));
  }, []);

  const loadTargetInventory = useCallback(
    async (workspaceId: string, targetId: string) => {
      const base = targetInventoryFetchParams;
      let sortBy = base.sortBy;
      let sortOrder = base.sortOrder;
      if (targetInventoryGroup === 'ip') {
        sortBy = 'value';
        sortOrder = 'ASC';
      }
      const params: AssetQueryParams = {
        page: base.page,
        limit: base.limit,
        sortBy,
        sortOrder,
        value: base.value || undefined,
        targetIds: targetId,
      };
      if (inventoryFacets.ipAddresses.length) params.ipAddresses = [...inventoryFacets.ipAddresses];
      if (inventoryFacets.ports.length) params.ports = [...inventoryFacets.ports];
      if (inventoryFacets.techs.length) params.techs = [...inventoryFacets.techs];
      if (inventoryFacets.statusCodes.length) params.statusCodes = [...inventoryFacets.statusCodes];
      if (inventoryFacets.hosts.length) params.hosts = [...inventoryFacets.hosts];
      if (inventoryFacets.tlsHosts.length) params.tlsHosts = [...inventoryFacets.tlsHosts];
      const result = await openasm.listAssetsByGroup(targetInventoryGroup, params, workspaceId);
      setTargetInventory(result.data ?? []);
      setTargetInventoryMeta({
        total: result.total,
        page: result.page,
        limit: result.limit,
        pageCount: result.pageCount,
        hasNextPage: result.hasNextPage,
      });
    },
    [targetInventoryGroup, targetInventoryFetchParams, inventoryFacets],
  );

  const loadTargetVulnerabilities = useCallback(async (workspaceId: string, targetId: string) => {
    const [list, stats] = await Promise.all([
      openasm.listVulnerabilities(
        { ...targetVulnParams, search: debouncedTargetVulnSearch || undefined, targetIds: targetId },
        workspaceId,
      ),
      openasm.getVulnerabilityStatistics(workspaceId, { targetIds: targetId }),
    ]);
    setTargetVulnerabilities(list.data ?? []);
    setTargetVulnMeta({
      total: list.total, page: list.page, limit: list.limit, pageCount: list.pageCount, hasNextPage: list.hasNextPage,
    });
    const map: Record<string, number> = {};
    for (const item of stats.data ?? []) map[item.severity] = item.count;
    setTargetVulnStats(map);
  }, [targetVulnParams, debouncedTargetVulnSearch]);

  const loadWorkers = useCallback(
    async (workspaceId: string) => {
      const r = await openasm.listWorkers(workerParams, workspaceId);
      setWorkers(r.data ?? []);
      setWorkersMeta({
        total: r.total,
        page: r.page,
        limit: r.limit,
        pageCount: r.pageCount,
        hasNextPage: r.hasNextPage,
      });
    },
    [workerParams],
  );

  const loadTab = useCallback(
    async (tab: TabId, workspaceId: string | undefined) => {
      setLoading(true);
      setError(null);
      try {
        if (tab === 'workspaces') {
          setWorkspaces((await openasm.listWorkspaces({ page: 1, limit: 100, isArchived: false })).data ?? []);
          return;
        }
        if (!workspaceId) {
          setError('Select a workspace to load this view.');
          return;
        }
        switch (tab) {
          case 'dashboard':
            await loadDashboard(workspaceId);
            break;
          case 'targets':
            break;
          case 'assets':
            break;
          case 'vulnerabilities':
            break;
          case 'workers':
            break;
        }
      } catch (e) {
        setError(formatApiError(e));
      } finally {
        setLoading(false);
      }
    },
    [formatApiError, loadDashboard],
  );

  useEffect(() => {
    if (workspaceLoading) return;
    if (tabsRequiringWorkspace.includes(activeTab) && !selectedWorkspaceId) return;
    loadTab(activeTab, selectedWorkspaceId || undefined);
  }, [activeTab, selectedWorkspaceId, workspaceLoading, loadTab]);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedTargetVulnSearch(targetVulnParams.search ?? ''), 380);
    return () => window.clearTimeout(t);
  }, [targetVulnParams.search]);

  useEffect(() => {
    const t = window.setTimeout(() => setDebouncedGlobalVulnSearch(vulnParams.search ?? ''), 380);
    return () => window.clearTimeout(t);
  }, [vulnParams.search]);

  useEffect(() => {
    if (activeTab !== 'targets' || !selectedWorkspaceId || workspaceLoading) return;
    let cancelled = false;
    setTargetsRefreshing(true);
    loadTargets(selectedWorkspaceId)
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setTargetsRefreshing(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    activeTab,
    selectedWorkspaceId,
    workspaceLoading,
    loadTargets,
    targetParams.page,
    targetParams.limit,
    targetParams.sortBy,
    targetParams.sortOrder,
    targetParams.type,
    targetParams.status,
    targetParams.search,
    debouncedTargetListValue,
  ]);

  useEffect(() => {
    if (activeTab !== 'workers' || !selectedWorkspaceId || workspaceLoading) return;
    let cancelled = false;
    setWorkersRefreshing(true);
    loadWorkers(selectedWorkspaceId)
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setWorkersRefreshing(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTab, selectedWorkspaceId, workspaceLoading, loadWorkers]);

  useEffect(() => {
    if (activeTab !== 'assets' || !selectedWorkspaceId || workspaceLoading) return;
    let cancelled = false;
    setAssetsListRefreshing(true);
    loadAssets(selectedWorkspaceId)
      .catch((e) => {
        if (!cancelled) setError(formatApiError(e));
      })
      .finally(() => {
        if (!cancelled) setAssetsListRefreshing(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    activeTab,
    selectedWorkspaceId,
    workspaceLoading,
    loadAssets,
    assetGroupTab,
    assetParams.page,
    assetParams.limit,
    assetParams.sortBy,
    assetParams.sortOrder,
    assetParams.type,
    assetParams.search,
    debouncedAssetValue,
    assetsFacets,
    formatApiError,
  ]);

  useEffect(() => {
    if (activeTab !== 'vulnerabilities' || !selectedWorkspaceId || workspaceLoading) return;
    let cancelled = false;
    setVulnListRefreshing(true);
    loadVulnerabilities(selectedWorkspaceId)
      .catch((e) => {
        if (!cancelled) setError(formatApiError(e));
      })
      .finally(() => {
        if (!cancelled) setVulnListRefreshing(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    activeTab,
    selectedWorkspaceId,
    workspaceLoading,
    loadVulnerabilities,
    debouncedGlobalVulnSearch,
    vulnParams.page,
    vulnParams.limit,
    vulnParams.severity,
    vulnParams.status,
    vulnParams.sortBy,
    vulnParams.sortOrder,
    vulnParams.createdFrom,
    vulnParams.createdTo,
    formatApiError,
  ]);

  // Polling intentionally disabled for now.
  // Dashboard (5s) and Targets (3s) auto-refresh can be re-enabled later.
  // Assets polling intentionally disabled for now.
  useEffect(() => {
    if (activeTab !== 'vulnerabilities' || !selectedWorkspaceId) return;
    const id = window.setInterval(() => {
      loadVulnerabilities(selectedWorkspaceId).catch(() => undefined);
    }, 7000);
    return () => window.clearInterval(id);
  }, [activeTab, selectedWorkspaceId, loadVulnerabilities]);

  useEffect(() => {
    if (!openInventoryFacet || !selectedWorkspaceId || !selectedTargetId || targetDetailTab !== 'inventory') {
      setInventoryFacetRows([]);
      setInventoryFacetLoading(false);
      return;
    }
    const reqId = ++inventoryFacetReqId.current;
    setInventoryFacetLoading(true);
    const params = buildFacetPickerParams(
      openInventoryFacet,
      selectedTargetId,
      debouncedInventoryValue,
      inventoryFacets,
      debouncedInventoryFacetSearch,
    );
    const group = FACET_GROUP[openInventoryFacet];
    openasm
      .listAssetsByGroup(group, params, selectedWorkspaceId)
      .then((res) => {
        if (inventoryFacetReqId.current !== reqId) return;
        setInventoryFacetRows(res.data ?? []);
      })
      .catch(() => {
        if (inventoryFacetReqId.current !== reqId) return;
        setInventoryFacetRows([]);
      })
      .finally(() => {
        if (inventoryFacetReqId.current === reqId) setInventoryFacetLoading(false);
      });
  }, [
    openInventoryFacet,
    selectedWorkspaceId,
    selectedTargetId,
    targetDetailTab,
    debouncedInventoryValue,
    inventoryFacets,
    debouncedInventoryFacetSearch,
  ]);

  useEffect(() => {
    if (!openAssetsFacet || !selectedWorkspaceId || activeTab !== 'assets') {
      setAssetsFacetRows([]);
      setAssetsFacetLoading(false);
      return;
    }
    const reqId = ++assetsFacetReqId.current;
    setAssetsFacetLoading(true);
    const params = buildWorkspaceFacetPickerParams(
      openAssetsFacet,
      debouncedAssetValue,
      assetsFacets,
      debouncedAssetsFacetSearch,
    );
    const group = FACET_GROUP[openAssetsFacet];
    openasm
      .listAssetsByGroup(group, params, selectedWorkspaceId)
      .then((res) => {
        if (assetsFacetReqId.current !== reqId) return;
        setAssetsFacetRows(res.data ?? []);
      })
      .catch(() => {
        if (assetsFacetReqId.current !== reqId) return;
        setAssetsFacetRows([]);
      })
      .finally(() => {
        if (assetsFacetReqId.current === reqId) setAssetsFacetLoading(false);
      });
  }, [
    openAssetsFacet,
    selectedWorkspaceId,
    activeTab,
    debouncedAssetValue,
    assetsFacets,
    debouncedAssetsFacetSearch,
  ]);

  useEffect(() => {
    if (!openInventoryFacet && !openAssetsFacet) return;
    const onDown = (e: MouseEvent) => {
      const inv = inventoryFacetBarRef.current;
      const ast = assetsFacetBarRef.current;
      if (openInventoryFacet && inv && !inv.contains(e.target as Node)) setOpenInventoryFacet(null);
      if (openAssetsFacet && ast && !ast.contains(e.target as Node)) setOpenAssetsFacet(null);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [openInventoryFacet, openAssetsFacet]);

  useEffect(() => {
    setInventoryFacetSearch('');
  }, [openInventoryFacet]);

  useEffect(() => {
    setAssetsFacetSearch('');
  }, [openAssetsFacet]);

  useEffect(() => {
    if (activeTab !== 'targets' || !selectedWorkspaceId || workspaceLoading) return;
    const needsPoll = targets.some((t) => targetScanNeedsPolling(t.status));
    if (!needsPoll) return;
    const id = window.setInterval(() => {
      refreshTargetsSilently(selectedWorkspaceId);
    }, 7000);
    return () => window.clearInterval(id);
  }, [activeTab, selectedWorkspaceId, workspaceLoading, targets, refreshTargetsSilently]);

  useEffect(() => {
    if (!selectedWorkspaceId || !selectedTargetId) return;
    setTargetRoute(selectedTargetId, targetDetailTab);
  }, [selectedWorkspaceId, selectedTargetId, targetDetailTab, setTargetRoute]);

  useEffect(() => {
    if (!selectedWorkspaceId || !selectedTargetId) return;
    loadTargetDetail(selectedWorkspaceId, selectedTargetId).catch(() => undefined);
  }, [selectedWorkspaceId, selectedTargetId, loadTargetDetail]);

  useEffect(() => {
    if (!selectedWorkspaceId || !selectedTargetId) return;
    if (targetDetailTab === 'inventory') {
      loadTargetInventory(selectedWorkspaceId, selectedTargetId).catch(() => undefined);
      return;
    }
    loadTargetVulnerabilities(selectedWorkspaceId, selectedTargetId).catch(() => undefined);
  }, [
    selectedWorkspaceId,
    selectedTargetId,
    targetDetailTab,
    loadTargetInventory,
    loadTargetVulnerabilities,
    targetInventoryFetchParams,
    targetInventoryGroup,
    inventoryFacets,
    targetVulnParams,
    debouncedTargetVulnSearch,
  ]);

  useEffect(() => {
    if (!selectedWorkspaceId || !selectedTargetId) return;
    const detailPoll = window.setInterval(() => {
      loadTargetDetail(selectedWorkspaceId, selectedTargetId).catch(() => undefined);
    }, 5000);
    const vulnPoll = window.setInterval(() => {
      loadTargetVulnerabilities(selectedWorkspaceId, selectedTargetId).catch(() => undefined);
    }, 5000);
    const st = normalizeTargetStatus(targetDetail?.status);
    const inventoryMs = ['in-progress', 'running', 'discovering', 'processing'].includes(st) ? 1000 : 30000;
    const inventoryPoll = window.setInterval(() => {
      loadTargetInventory(selectedWorkspaceId, selectedTargetId).catch(() => undefined);
    }, inventoryMs);
    return () => {
      window.clearInterval(detailPoll);
      window.clearInterval(vulnPoll);
      window.clearInterval(inventoryPoll);
    };
  }, [selectedWorkspaceId, selectedTargetId, targetDetail?.status, loadTargetDetail, loadTargetInventory, loadTargetVulnerabilities]);

  const toggleInventoryFacetValue = useCallback((menu: InventoryFacetMenu, raw: string) => {
    const v = raw.trim();
    if (!v) return;
    setInventoryFacets((prev) => {
      const cur = [...prev[menu]];
      const i = cur.indexOf(v);
      if (i >= 0) cur.splice(i, 1);
      else cur.push(v);
      return { ...prev, [menu]: cur };
    });
    setTargetInventoryParams((p) => ({ ...p, page: 1 }));
  }, []);

  const clearInventoryFacetMenu = useCallback((menu: InventoryFacetMenu) => {
    setInventoryFacets((prev) => ({ ...prev, [menu]: [] }));
    setTargetInventoryParams((p) => ({ ...p, page: 1 }));
  }, []);

  const resetAllInventoryFilters = useCallback(() => {
    setInventoryFacets({ ...EMPTY_INVENTORY_FACETS });
    setTargetInventoryParams((p) => ({ ...p, page: 1, value: '' }));
    setOpenInventoryFacet(null);
  }, []);

  const toggleAssetsFacetValue = useCallback((menu: InventoryFacetMenu, raw: string) => {
    const v = raw.trim();
    if (!v) return;
    setAssetsFacets((prev) => {
      const cur = [...prev[menu]];
      const i = cur.indexOf(v);
      if (i >= 0) cur.splice(i, 1);
      else cur.push(v);
      return { ...prev, [menu]: cur };
    });
    setAssetParams((p) => ({ ...p, page: 1 }));
  }, []);

  const clearAssetsFacetMenu = useCallback((menu: InventoryFacetMenu) => {
    setAssetsFacets((prev) => ({ ...prev, [menu]: [] }));
    setAssetParams((p) => ({ ...p, page: 1 }));
  }, []);

  const resetAllAssetsFacets = useCallback(() => {
    setAssetsFacets({ ...EMPTY_INVENTORY_FACETS });
    setAssetParams((p) => ({ ...p, page: 1, value: '' }));
    setOpenAssetsFacet(null);
  }, []);

  const buildWorkspaceExportParams = useCallback((): AssetQueryParams => {
    const p: AssetQueryParams = {
      page: assetParams.page,
      limit: assetParams.limit,
      sortBy: assetParams.sortBy,
      sortOrder: assetParams.sortOrder,
      value: debouncedAssetValue || undefined,
      type: assetParams.type || undefined,
      search: assetParams.search || undefined,
    };
    if (assetsFacets.ipAddresses.length) p.ipAddresses = [...assetsFacets.ipAddresses];
    if (assetsFacets.ports.length) p.ports = [...assetsFacets.ports];
    if (assetsFacets.techs.length) p.techs = [...assetsFacets.techs];
    if (assetsFacets.statusCodes.length) p.statusCodes = [...assetsFacets.statusCodes];
    if (assetsFacets.hosts.length) p.hosts = [...assetsFacets.hosts];
    if (assetsFacets.tlsHosts.length) p.tlsHosts = [...assetsFacets.tlsHosts];
    return p;
  }, [assetParams, debouncedAssetValue, assetsFacets]);

  const buildInventoryExportParams = useCallback((): AssetQueryParams => {
    const base = targetInventoryFetchParams;
    const p: AssetQueryParams = {
      page: base.page,
      limit: base.limit,
      sortBy: base.sortBy,
      sortOrder: base.sortOrder,
      value: base.value || undefined,
      targetIds: selectedTargetId ?? '',
    };
    if (inventoryFacets.ipAddresses.length) p.ipAddresses = [...inventoryFacets.ipAddresses];
    if (inventoryFacets.ports.length) p.ports = [...inventoryFacets.ports];
    if (inventoryFacets.techs.length) p.techs = [...inventoryFacets.techs];
    if (inventoryFacets.statusCodes.length) p.statusCodes = [...inventoryFacets.statusCodes];
    if (inventoryFacets.hosts.length) p.hosts = [...inventoryFacets.hosts];
    if (inventoryFacets.tlsHosts.length) p.tlsHosts = [...inventoryFacets.tlsHosts];
    return p;
  }, [targetInventoryFetchParams, inventoryFacets, selectedTargetId]);

  const handleExportTargetsCsv = useCallback(() => {
    const headers = ['id', 'value', 'type', 'status', 'totalAssetServices', 'lastDiscoveredAt'];
    const esc = (c: unknown) => {
      const s = String(c ?? '').replace(/"/g, '""');
      return `"${s}"`;
    };
    const rows = targets.map((t) =>
      [t.id, t.value, t.type, t.status ?? '', t.totalAssetServices ?? 0, t.lastDiscoveredAt ?? ''].map(esc).join(','),
    );
    const blob = new Blob([[headers.map(esc).join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `targets-${selectedWorkspaceId?.slice(0, 8) ?? 'export'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [targets, selectedWorkspaceId]);

  const refreshHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      const h = await openasm.getHealth();
      setHealth(h);
    } catch {
      setHealth({ status: 'unreachable' });
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshHealth();
    const id = window.setInterval(() => void refreshHealth(), 30_000);
    return () => window.clearInterval(id);
  }, [refreshHealth]);

  const handleRefresh = () => {
    if (workspaceLoading) return;
    void refreshHealth();
    if (activeTab === 'workspaces') {
      void loadTab('workspaces', undefined);
      return;
    }
    if (tabsRequiringWorkspace.includes(activeTab) && !selectedWorkspaceId) return;
    if (activeTab === 'assets' && selectedWorkspaceId) {
      setAssetsListRefreshing(true);
      loadAssets(selectedWorkspaceId)
        .catch((e) => setError(formatApiError(e)))
        .finally(() => setAssetsListRefreshing(false));
      return;
    }
    void loadTab(activeTab, selectedWorkspaceId || undefined);
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetValue.trim() || !selectedWorkspaceId) return;
    const value = normalizeDiscoveryTargetValue(targetValue, targetType);
    if (!value) return;
    setSubmitting(true);
    setError(null);
    setDiscoveryModalError(null);
    try {
      if (assessImmediately) {
        const res = await openasm.submitAndAssess({ value, type: targetType }, selectedWorkspaceId);
        setTargetValue('');
        await loadTargets(selectedWorkspaceId);
        setNotice('Target created and scan queued.');
        setDiscoveryModalError(null);
        setDiscoveryModalOpen(false);
        if (res.target) {
          void handleOpenRiskModal(res.target);
        }
      } else {
        await openasm.createTarget({ value, type: targetType }, selectedWorkspaceId);
        setTargetValue('');
        await loadTargets(selectedWorkspaceId);
        setNotice('Target created successfully.');
        setDiscoveryModalError(null);
        setDiscoveryModalOpen(false);
      }
    } catch (e) {
      setDiscoveryModalError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleBulkCreateTargets = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedWorkspaceId) return;
    const targets = bulkTargetsText
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [valueRaw, typeRaw] = line.split(',').map((x) => x.trim());
        const type = (typeRaw?.toUpperCase() as 'DOMAIN' | 'CIDR' | 'IP' | undefined) ?? undefined;
        const resolved: DiscoveryTargetKind =
          type && ['DOMAIN', 'CIDR', 'IP'].includes(type) ? type : 'DOMAIN';
        const value = normalizeDiscoveryTargetValue(valueRaw ?? '', resolved);
        return { value, type: type && ['DOMAIN', 'CIDR', 'IP'].includes(type) ? type : undefined };
      })
      .filter((t) => t.value.length > 0);
    if (targets.length === 0) return;
    setSubmitting(true);
    setError(null);
    setNotice(null);
    setDiscoveryModalError(null);
    try {
      const result = await openasm.createTargetsBulk({ targets }, selectedWorkspaceId);
      await loadTargets(selectedWorkspaceId);
      setBulkTargetsText('');
      const limitSkipped = result.skipped?.find((s) => s.reason === 'target_limit_reached');
      if (limitSkipped) {
        setNotice(`Added ${result.createdCount ?? 0} targets. ${result.skippedCount ?? 0} skipped (Target limit reached: ${limitSkipped.limit || 25} max).`);
      } else {
        setNotice(`Targets processed: ${result.createdCount ?? 0} added, ${result.skippedCount ?? 0} skipped.`);
      }
      setDiscoveryModalError(null);
      setDiscoveryModalOpen(false);
    } catch (e) {
      setDiscoveryModalError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenTargetDetail = async (targetId: string) => {
    if (!selectedWorkspaceId) return;
    setTargetDetailLoading(true);
    setSelectedTargetId(targetId);
    setTargetVulnParams((prev) => ({ ...prev, page: 1 }));
    setTargetInventoryParams((prev) => ({ ...prev, page: 1 }));
    setInventoryFacets({ ...EMPTY_INVENTORY_FACETS });
    setOpenInventoryFacet(null);
    setTargetRoute(targetId, targetDetailTab);
    setError(null);
    setNotice(null);
    try {
      await Promise.all([
        loadTargetDetail(selectedWorkspaceId, targetId),
        openasm.getMetadata().then(setMetadata).catch(() => undefined),
      ]);
      await Promise.all([
        loadTargetInventory(selectedWorkspaceId, targetId),
        loadTargetVulnerabilities(selectedWorkspaceId, targetId),
      ]);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setTargetDetailLoading(false);
    }
  };

  const handleScanNow = async () => {
    if (!selectedWorkspaceId || !targetDetail?.id) return;
    setSubmitting(true);
    try {
      const result = await openasm.triggerVulnerabilityScan(targetDetail.id, selectedWorkspaceId);
      setNotice(result.message ?? 'Scan started.');
      await loadTargets(selectedWorkspaceId);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRescan = async () => {
    if (!selectedWorkspaceId || !targetDetail?.id) return;
    setSubmitting(true);
    try {
      const result = await openasm.rescanTarget(targetDetail.id, selectedWorkspaceId);
      setNotice(result.message ?? 'Re-scan triggered.');
      await Promise.all([
        loadTargets(selectedWorkspaceId),
        loadTargetDetail(selectedWorkspaceId, targetDetail.id),
      ]);
      setTargetRoute(targetDetail.id, targetDetailTab, true);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleUpdateSchedule = async () => {
    if (!selectedWorkspaceId || !targetDetail?.id) return;
    setSubmitting(true);
    try {
      const updated = await openasm.updateTarget(targetDetail.id, { scanSchedule: scheduleValue }, selectedWorkspaceId);
      setTargetDetail(updated);
      setNotice('Schedule updated.');
      setTargetSettingsOpen(false);
      await loadTargets(selectedWorkspaceId);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteTarget = async () => {
    if (!selectedWorkspaceId || !targetDetail?.id) return;
    if (!window.confirm(`Delete target "${targetDetail.value}" from workspace?`)) return;
    setSubmitting(true);
    try {
      const result = await openasm.deleteTargetFromWorkspace(targetDetail.id, selectedWorkspaceId);
      setNotice(result.message ?? 'Target deleted from workspace.');
      setSelectedTargetId(null);
      setTargetDetail(null);
      setTargetRoute(null);
      await loadTargets(selectedWorkspaceId);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenAssetDetail = async (assetId: string) => {
    if (!selectedWorkspaceId) return;
    setSelectedAssetId(assetId);
    setAssetDetailLoading(true);
    setError(null);
    try {
      const detail = await openasm.getAssetById(assetId, selectedWorkspaceId);
      setAssetDetail(detail);
      const tags = Array.isArray((detail as Record<string, unknown>).tags)
        ? ((detail as Record<string, unknown>).tags as unknown[]).map((t) => String(t)).join(', ')
        : '';
      setAssetTagsText(tags);
      if (typeof (detail as Record<string, unknown>).enabled === 'boolean') {
        setAssetEnabled(Boolean((detail as Record<string, unknown>).enabled));
      } else {
        setAssetEnabled(null);
      }
      setAiDomain(String((detail as Record<string, unknown>).host ?? (detail as Record<string, unknown>).value ?? ''));
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setAssetDetailLoading(false);
    }
  };

  const refreshAssetDetailAndList = async () => {
    if (!selectedWorkspaceId || !selectedAssetId) return;
    const [detail] = await Promise.all([
      openasm.getAssetById(selectedAssetId, selectedWorkspaceId),
      loadAssets(selectedWorkspaceId),
    ]);
    setAssetDetail(detail);
  };

  const handleSaveAssetTags = async () => {
    if (!selectedWorkspaceId || !selectedAssetId) return;
    setSubmitting(true);
    try {
      const tags = assetTagsText
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);
      await openasm.updateAsset(selectedAssetId, { tags }, selectedWorkspaceId);
      await refreshAssetDetailAndList();
      setNotice('Asset tags updated.');
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleToggleAssetEnabled = async () => {
    if (!selectedWorkspaceId || !selectedAssetId || assetEnabled === null) return;
    const optimistic = !assetEnabled;
    setAssetEnabled(optimistic);
    try {
      await openasm.switchAsset({ assetId: selectedAssetId, enabled: optimistic }, selectedWorkspaceId);
      await refreshAssetDetailAndList();
      setNotice(`Asset ${optimistic ? 'enabled' : 'disabled'}.`);
    } catch (e) {
      setAssetEnabled(!optimistic);
      setError(formatApiError(e));
    }
  };

  const handleGenerateAiTags = async () => {
    if (!selectedWorkspaceId || !aiDomain.trim()) return;
    setSubmitting(true);
    try {
      const res = await openasm.generateAssetTags({ domain: aiDomain.trim() }, selectedWorkspaceId);
      setAiTags(res.tags ?? []);
      if ((res.tags ?? []).length > 0) {
        setAssetTagsText((res.tags ?? []).join(', '));
      }
      setNotice('AI tag suggestions generated.');
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleCreateAssetGroup = async () => {
    if (!selectedWorkspaceId || !assetGroupName.trim()) return;
    setSubmitting(true);
    try {
      const res = await openasm.createAssetGroup({ name: assetGroupName.trim() }, selectedWorkspaceId);
      setAssetGroupName('');
      setNotice(`Asset group created: ${res.name ?? 'success'}`);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenVulnerabilityDetail = async (id: string) => {
    if (!selectedWorkspaceId) return;
    setSelectedVulnId(id);
    setVulnDetailLoading(true);
    setError(null);
    try {
      const detail = await openasm.getVulnerabilityById(id, selectedWorkspaceId);
      setVulnDetail(detail);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setVulnDetailLoading(false);
    }
  };

  const handleVulnModalDismiss = async (id: string, reason: string) => {
    if (!selectedWorkspaceId) return;
    setVulnModalDismissLoading(true);
    setError(null);
    try {
      await openasm.dismissVulnerabilities({ ids: [id], reason, comment: undefined }, selectedWorkspaceId);
      setSelectedVulnId(null);
      setVulnDetail(null);
      setNotice('Vulnerability dismissed.');
      await loadVulnerabilities(selectedWorkspaceId);
      if (selectedTargetId) await loadTargetVulnerabilities(selectedWorkspaceId, selectedTargetId);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setVulnModalDismissLoading(false);
    }
  };

  const handleCreateWorkspace = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!workspaceName.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await openasm.createWorkspace({
        name: workspaceName.trim(),
        description: workspaceDescription.trim() || undefined,
      });
      setWorkspaceName('');
      setWorkspaceDescription('');
      const listRes = await openasm.listWorkspaces({ page: 1, limit: 100, isArchived: false });
      setWorkspaces(listRes.data ?? []);
    } catch (e) {
      setError(formatApiError(e));
    } finally {
      setSubmitting(false);
    }
  };

  const workspaceLabel = (w: Workspace) => {
    const bits = [w.targetCount != null ? `${w.targetCount} targets` : null, w.role].filter(Boolean);
    return bits.length ? `${w.name} (${bits.join(' · ')})` : w.name;
  };

  const kpi = {
    assets: Number(statistics?.assets ?? 0),
    targets: Number(statistics?.targets ?? 0),
    vuls: Number(statistics?.vuls ?? 0),
    score: Number(statistics?.score ?? 0),
    criticalVuls: Number(statistics?.criticalVuls ?? 0),
    highVuls: Number(statistics?.highVuls ?? 0),
    mediumVuls: Number(statistics?.mediumVuls ?? 0),
    lowVuls: Number(statistics?.lowVuls ?? 0),
    infoVuls: Number(statistics?.infoVuls ?? 0),
    techs: Number(statistics?.techs ?? 0),
    ports: Number(statistics?.ports ?? 0),
    services: Number(statistics?.services ?? 0),
  };

  const timelineChartData = timeline.map((row, idx) => ({
    x: row.createdAt ? new Date(row.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : `${idx + 1}`,
    assets: Number(row.assets ?? 0),
    targets: Number(row.targets ?? 0),
    vuls: Number(row.vuls ?? 0),
    score: Number(row.score ?? 0),
  }));

  const issuesChartData = issuesTimeline.map((row, idx) => ({
    x: row.date ?? row.time ?? `${idx + 1}`,
    count: Number(row.count ?? row.total ?? 0),
  }));

  const resolveAssetMediaUrl = (path: string | null): string | null => {
    if (!path) return null;
    if (/^https?:\/\//i.test(path)) return path;
    const meta = metadata as Record<string, unknown> | null;
    const base = String(meta?.openasmBaseUrl ?? meta?.openasmOrigin ?? meta?.assetBaseUrl ?? '').trim();
    if (!base) return path;
    const normalizedBase = base.endsWith('/') ? base.slice(0, -1) : base;
    let normalizedPath = path.startsWith('/') ? path : `/${path}`;
    // OASM serves tool logos at /api/static/... while API returns /static/...
    if (normalizedPath.startsWith('/static/')) {
      normalizedPath = `/api${normalizedPath}`;
    }
    return `${normalizedBase}${normalizedPath}`;
  };

  if (permissionsLoaded && !hasOsmAccess) {
    return (
      <div className="h-full flex items-center justify-center p-6 bg-cyber-grid">
        <div className="max-w-md w-full rounded-2xl border border-red-500/30 bg-[#0d131f] p-8 text-center shadow-2xl">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400">
            <Lock size={28} />
          </div>
          <h2 className="text-xl font-bold text-white mb-2 font-cyber">Access Denied</h2>
          <p className="text-sm text-neutral-400 mb-6">
            You do not have the required Attack Surface Management (<code className="text-red-400 font-mono">osm.*</code>) permissions to view this screen.
          </p>
          <div className="text-xs text-neutral-500 font-mono border-t border-neutral-800 pt-4">
            Contact your organization administrator to request access.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-cyber-grid relative">
      <div className="p-4 border-b border-[#222] bg-[#111]/40 backdrop-blur-sm flex flex-col md:flex-row gap-4 justify-between items-center shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-neutral-900/20 rounded-lg border border-neutral-500/30 text-white">
            <Target size={20} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white font-cyber">
              ANTI.AI <span className="text-white">RECON</span>
            </h2>
            <p className="text-xs text-[#888] font-mono">Reconnaissance via ANTI.AI</p>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <label className="flex items-center gap-2 text-xs text-[#AAA] font-mono">
            <span className="text-[#888] shrink-0">Workspace</span>
            <select
              value={selectedWorkspaceId}
              onChange={(e) => setSelectedWorkspaceId(e.target.value)}
              disabled={workspaceLoading || workspaces.length === 0}
              className="min-w-[200px] max-w-[min(100vw-8rem,320px)] px-2 py-1.5 rounded bg-[#111]/40 border border-[#333] text-white text-xs font-mono focus:border-neutral-500/50 focus:outline-none"
            >
              {workspaces.length === 0 ? (
                <option value="">No workspaces</option>
              ) : (
                workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {workspaceLabel(w)}
                  </option>
                ))
              )}
            </select>
          </label>
          <button
            type="button"
            onClick={handleRefresh}
            disabled={loading || workspaceLoading}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 hover:bg-red-500/20 transition-colors text-xs font-mono font-bold disabled:opacity-50"
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            Refresh
          </button>
          <span
            className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-mono font-bold ${
              healthLoading && !health
                ? 'border-neutral-600 text-[#AAA] bg-[#111]/40'
                : String(health?.status ?? '').toLowerCase() === 'healthy'
                  ? 'border-emerald-500/50 text-emerald-200 bg-emerald-950/40'
                  : String(health?.status ?? '').toLowerCase() === 'degraded'
                    ? 'border-neutral-500/50 text-white bg-neutral-950/35'
                    : 'border-red-500/50 text-red-200 bg-red-950/35'
            }`}
            title={
              health
                ? [
                    `status: ${health.status ?? '—'}`,
                    health.upstream && typeof health.upstream.reachable === 'boolean'
                      ? `upstream: ${health.upstream.reachable ? 'reachable' : 'unreachable'}`
                      : '',
                    health.session && typeof (health.session as { authenticated?: boolean }).authenticated === 'boolean'
                      ? `session: ${(health.session as { authenticated?: boolean }).authenticated ? 'authenticated' : 'not authenticated'}`
                      : '',
                  ]
                    .filter(Boolean)
                    .join('\n')
                : 'OpenASM integration health'
            }
          >
            {healthLoading && !health ? <Loader2 size={14} className="animate-spin shrink-0" /> : null}
            ANTI.AI Recon:{' '}
            {healthLoading && !health
              ? '…'
              : String(health?.status ?? 'unknown')
                  .toLowerCase()
                  .replace(/^\w/, (c) => c.toUpperCase())}
          </span>
          {selectedWorkspaceId && (
            <span className="text-xs text-[#888] font-mono">
              X-Workspace-Id: <span className="text-red-400">{selectedWorkspaceId}</span>
            </span>
          )}
        </div>
      </div>

      {error && !discoveryModalOpen && (
        <div className="mx-4 mt-4 p-3 rounded-lg bg-red-900/20 border border-red-500/30 flex items-center gap-3">
          <AlertTriangle className="text-red-400 shrink-0" size={20} />
          <span className="text-sm text-red-200 font-mono flex-1">{error}</span>
          <button type="button" onClick={() => setError(null)} className="p-1 text-red-400 hover:text-white">
            <XCircle size={18} />
          </button>
        </div>
      )}
      {notice && (
        <div className="mx-4 mt-4 p-3 rounded-lg bg-neutral-900/20 border border-neutral-500/30 flex items-center gap-3">
          <span className="text-sm text-white font-mono flex-1">{notice}</span>
          <button type="button" onClick={() => setNotice(null)} className="p-1 text-white hover:text-white">
            <XCircle size={18} />
          </button>
        </div>
      )}

      <div className="px-4 pt-4 flex gap-2 flex-wrap border-b border-[#222]">
        {TAB_CONFIG.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold font-mono transition-colors border-b-2 ${
              activeTab === id
                ? 'bg-neutral-500/10 border-neutral-500 text-white'
                : 'border-transparent text-[#888] hover:text-neutral-300 hover:bg-white/5'
            }`}
          >
            <Icon size={14} />
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto custom-scrollbar p-4">
        {workspaceLoading ||
        (loading &&
          activeTab !== 'workspaces' &&
          activeTab !== 'targets' &&
          activeTab !== 'assets' &&
          activeTab !== 'workers' &&
          activeTab !== 'vulnerabilities') ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 size={32} className="animate-spin text-white" />
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && selectedWorkspaceId && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <div className="text-xs text-white font-mono mb-1">TARGETS</div>
                    <div className="text-2xl text-white font-bold">{kpi.targets}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <div className="text-xs text-white font-mono mb-1">ASSETS</div>
                    <div className="text-2xl text-white font-bold">{kpi.assets}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <div className="text-xs text-red-400 font-mono mb-1">VULNERABILITIES</div>
                    <div className="text-2xl text-white font-bold">{kpi.vuls}</div>
                  </div>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">Score</h3>
                    <div className="flex items-center justify-center py-4">
                      <div className="w-40 h-40 rounded-full border-[10px] border-neutral-400 flex items-center justify-center">
                        <div className="text-center">
                          <div className="text-sm text-neutral-300 font-mono">Score</div>
                          <div className="text-4xl text-white font-bold">{kpi.score}</div>
                        </div>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Total<br /><span className="text-white text-lg">{kpi.vuls}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Critical<br /><span className="text-red-400 text-lg">{kpi.criticalVuls}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">High<br /><span className="text-white text-lg">{kpi.highVuls}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Medium<br /><span className="text-white text-lg">{kpi.mediumVuls}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Low<br /><span className="text-red-400 text-lg">{kpi.lowVuls}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Info<br /><span className="text-[#AAA] text-lg">{kpi.infoVuls}</span></div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono mt-2">
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Techs<br /><span className="text-white text-lg">{kpi.techs}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Ports<br /><span className="text-white text-lg">{kpi.ports}</span></div>
                      <div className="p-2 bg-[#111]/40 rounded border border-[#222]">Services<br /><span className="text-white text-lg">{kpi.services}</span></div>
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">Timeline</h3>
                    <div className="h-72">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={timelineChartData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="x" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                          <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                          <ReTooltip />
                          <Area dataKey="assets" stroke="#10b981" fill="#10b98133" />
                          <Area dataKey="targets" stroke="#38bdf8" fill="#38bdf833" />
                          <Area dataKey="vuls" stroke="#f43f5e" fill="#f43f5e33" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">Issues Timeline</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={issuesChartData}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                          <XAxis dataKey="x" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                          <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                          <ReTooltip />
                          <Area dataKey="count" stroke="#f59e0b" fill="#f59e0b33" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222] lg:col-span-2">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">Asset Locations</h3>
                    <div className="rounded-lg border border-[#222] bg-[#111]/40 h-72 relative overflow-hidden">
                      {assetLocations.length === 0 ? (
                        <div className="flex h-full items-center justify-center text-xs text-[#888] font-mono">No geo data</div>
                      ) : (
                        <DashboardAssetLocationsMap locations={assetLocations} />
                      )}
                    </div>
                    <div className="mt-2 text-xs text-[#888] font-mono">{assetLocations.length} locations</div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">TLS Expiration</h3>
                    <div className="overflow-x-auto max-h-64">
                      <table className="w-full text-xs font-mono">
                        <thead className="text-[#AAA]">
                          <tr>
                            <th className="text-left py-2 pr-2">Host</th>
                            <th className="text-left py-2 pr-2">CN</th>
                            <th className="text-left py-2 pr-2">Not After</th>
                            <th className="text-left py-2 pr-2">TLS</th>
                            <th className="text-left py-2">Cipher</th>
                          </tr>
                        </thead>
                        <tbody className="text-neutral-300">
                          {tlsAssets.map((row, idx) => (
                            <tr key={`${row.host ?? 'host'}-${idx}`} className="border-t border-[#222]">
                              <td className="py-2 pr-2">{row.host ?? '—'}</td>
                              <td className="py-2 pr-2">{row.subject_cn ?? '—'}</td>
                              <td className="py-2 pr-2">{row.not_after ?? '—'}</td>
                              <td className="py-2 pr-2">{row.tls_version ?? '—'}</td>
                              <td className="py-2">{row.cipher ?? '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="mt-2 text-xs text-[#888] font-mono">
                      total={tlsMeta.total ?? 0} page={tlsMeta.page ?? 1}/{tlsMeta.pageCount ?? 1}
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222]">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">Top Assets Vulnerabilities</h3>
                    <div className="overflow-x-auto max-h-64">
                      <table className="w-full text-xs font-mono">
                        <thead className="text-[#AAA]">
                          <tr>
                            <th className="text-left py-2 pr-2">Asset</th>
                            <th className="text-right py-2 pr-2">Critical</th>
                            <th className="text-right py-2 pr-2">High</th>
                            <th className="text-right py-2 pr-2">Medium</th>
                            <th className="text-right py-2 pr-2">Low</th>
                            <th className="text-right py-2">Total</th>
                          </tr>
                        </thead>
                        <tbody className="text-neutral-300">
                          {topAssetsVuln.map((row, idx) => (
                            <tr key={`${String(row.id ?? idx)}-${idx}`} className="border-t border-[#222]">
                              <td className="py-2 pr-2">{String(row.value ?? '—')}</td>
                              <td className="py-2 pr-2 text-right">{Number(row.critical ?? 0)}</td>
                              <td className="py-2 pr-2 text-right">{Number(row.high ?? 0)}</td>
                              <td className="py-2 pr-2 text-right">{Number(row.medium ?? 0)}</td>
                              <td className="py-2 pr-2 text-right">{Number(row.low ?? 0)}</td>
                              <td className="py-2 text-right">{Number(row.total ?? 0)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222] lg:col-span-2">
                    <h3 className="text-sm font-bold text-red-400 font-mono mb-2">Top Tags Assets</h3>
                    {topTagsAssets.length === 0 ? (
                      <div className="text-xs text-[#888] font-mono">No tags available.</div>
                    ) : (
                      <div className="space-y-2">
                        {topTagsAssets.map((tag, idx) => (
                          <div key={`${String(tag.tag ?? idx)}-${idx}`} className="flex items-center gap-3">
                            <div className="w-48 text-xs text-neutral-300 font-mono truncate">{String(tag.tag ?? 'unknown')}</div>
                            <div className="flex-1 h-2 rounded bg-[#151515] overflow-hidden">
                              <div
                                className="h-2 bg-[#151515]"
                                style={{ width: `${Math.min(100, Number(tag.count ?? 0) * 5)}%` }}
                              />
                            </div>
                            <div className="w-12 text-right text-xs text-[#AAA] font-mono">{Number(tag.count ?? 0)}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
            {activeTab === 'dashboard' && !selectedWorkspaceId && (
              <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                Select or create a workspace to view the dashboard.
              </div>
            )}

            {activeTab === 'targets' && selectedWorkspaceId && (
              <div className="space-y-4">
                <div className="flex flex-col gap-3 rounded-2xl border border-[#222] bg-[#070b12] p-4">
                  <div className="flex flex-wrap items-center gap-3 justify-between">
                    <h3 className="text-xl font-bold text-white tracking-tight">Targets</h3>
                    {targets.some((t) => targetScanNeedsPolling(t.status)) && (
                      <span className="inline-flex items-center gap-2 text-[11px] text-white/90 font-mono">
                        <Loader2 size={12} className="animate-spin" />
                        Auto-refreshing while discovery runs
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap items-center gap-2 md:gap-3">
                    <div className="relative flex min-w-[200px] flex-1 items-center">
                      <Search size={16} className="pointer-events-none absolute left-3 text-[#888]" />
                      <input
                        type="text"
                        value={targetParams.value ?? ''}
                        onChange={(e) => setTargetParams((prev) => ({ ...prev, value: e.target.value, page: 1 }))}
                        placeholder="Search"
                        className="w-full rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-2.5 pl-10 pr-3 text-sm text-white placeholder:text-[#888] focus:border-neutral-600/50 focus:outline-none"
                      />
                    </div>
                    <div className="relative">
                      <span className="pointer-events-none absolute left-3 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-neutral-500" />
                      <select
                        value={targetParams.type ?? ''}
                        onChange={(e) => setTargetParams((prev) => ({ ...prev, page: 1, type: e.target.value as '' | 'DOMAIN' | 'CIDR' | 'IP' }))}
                        className="appearance-none rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-2.5 pl-8 pr-9 text-sm text-white focus:border-neutral-600/50 focus:outline-none"
                      >
                        <option value="">All types</option>
                        <option value="DOMAIN">DOMAIN</option>
                        <option value="CIDR">CIDR</option>
                        <option value="IP">IP</option>
                      </select>
                      <ChevronDown size={16} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[#888]" />
                    </div>
                    <div className="relative">
                      <span className="pointer-events-none absolute left-3 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-neutral-500" />
                      <select
                        value={targetParams.status ?? ''}
                        onChange={(e) => setTargetParams((prev) => ({ ...prev, page: 1, status: e.target.value }))}
                        className="appearance-none rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-2.5 pl-8 pr-9 text-sm text-white focus:border-neutral-600/50 focus:outline-none"
                      >
                        <option value="">All statuses</option>
                        <option value="completed">completed</option>
                        <option value="in_progress">in progress</option>
                        <option value="running">running</option>
                        <option value="failed">failed</option>
                        <option value="open">open</option>
                      </select>
                      <ChevronDown size={16} className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[#888]" />
                    </div>
                    <button
                      type="button"
                      onClick={handleExportTargetsCsv}
                      className="inline-flex items-center gap-2 rounded-xl border border-neutral-600 bg-[#111] px-4 py-2.5 text-sm font-medium text-white hover:bg-[#151515]"
                    >
                      <Download size={16} />
                      Export
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDiscoveryModalError(null);
                        setError(null);
                        setDiscoveryModalOpen(true);
                      }}
                      className="inline-flex items-center gap-2 rounded-xl border border-neutral-500/40 bg-neutral-950/40 px-4 py-2.5 text-sm font-semibold text-white hover:bg-[#111]"
                    >
                      <Target size={16} />
                      Start discovery
                    </button>
                  </div>
                </div>

                {discoveryModalOpen && (
                  <div className="fixed inset-0 z-[70] flex items-center justify-center bg-[#111]/75 p-4" role="presentation">
                    <div
                      role="dialog"
                      aria-modal="true"
                      aria-labelledby="recon-discovery-modal-title"
                      className="max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-[#333] bg-[#0b1220] p-6 shadow-2xl"
                    >
                      <div className="mb-4 flex items-center justify-between">
                        <h4 id="recon-discovery-modal-title" className="text-lg font-bold text-white">
                          Start discovery
                        </h4>
                        <button
                          type="button"
                          onClick={() => {
                            setDiscoveryModalError(null);
                            setError(null);
                            setDiscoveryModalOpen(false);
                          }}
                          className="rounded-lg p-1 text-[#AAA] hover:bg-[#151515] hover:text-white"
                        >
                          <XCircle size={20} />
                        </button>
                      </div>
                      {(discoveryModalError || error) && (
                        <div className="mb-4 rounded-lg border border-red-500/40 bg-red-950/50 p-3">
                          <div className="flex items-start gap-2">
                            <AlertTriangle className="mt-0.5 shrink-0 text-red-400" size={18} />
                            <p className="flex-1 text-xs font-mono text-red-100 whitespace-pre-wrap break-words">
                              {discoveryModalError ?? error}
                            </p>
                            <button
                              type="button"
                              onClick={() => {
                                setDiscoveryModalError(null);
                                setError(null);
                              }}
                              className="shrink-0 rounded p-0.5 text-red-300 hover:bg-red-900/50 hover:text-white"
                              aria-label="Dismiss error"
                            >
                              <XCircle size={16} />
                            </button>
                          </div>
                        </div>
                      )}
                      <form onSubmit={handleAddTarget} className="space-y-3 border-b border-[#222] pb-5">
                        <div className="flex items-center justify-between">
                          <p className="text-xs font-mono text-[#AAA]">Add single target</p>
                          <span className="text-[11px] font-mono text-neutral-400">
                            Account limit: <strong className="text-white">{targets.length}</strong> / 25
                          </span>
                        </div>
                        <input
                          type="text"
                          value={targetValue}
                          onChange={(e) => setTargetValue(e.target.value)}
                          placeholder="example.com (URLs are cleaned to hostname)"
                          className="w-full rounded-xl border border-[#333] bg-[#111]/40 px-3 py-2.5 text-sm text-white focus:border-neutral-500/50 focus:outline-none"
                        />
                        <div className="flex flex-wrap gap-2">
                          <select
                            value={targetType}
                            onChange={(e) => setTargetType(e.target.value as 'DOMAIN' | 'CIDR' | 'IP')}
                            className="flex-1 min-w-[120px] rounded-xl border border-[#333] bg-[#111]/40 px-3 py-2 text-sm text-white"
                          >
                            <option value="DOMAIN">DOMAIN</option>
                            <option value="CIDR">CIDR</option>
                            <option value="IP">IP</option>
                          </select>
                          <button
                            type="submit"
                            disabled={submitting || !targetValue.trim()}
                            className="rounded-xl bg-neutral-600 px-4 py-2 text-sm font-bold text-white hover:bg-neutral-500 disabled:opacity-50"
                          >
                            {submitting ? 'Adding...' : 'Add target'}
                          </button>
                        </div>
                        <label className="flex items-center gap-2 cursor-pointer pt-1 text-xs text-neutral-300">
                          <input
                            type="checkbox"
                            checked={assessImmediately}
                            onChange={(e) => setAssessImmediately(e.target.checked)}
                            className="rounded border-[#333] bg-neutral-900 text-sky-500 focus:ring-0"
                          />
                          <span>Queue vulnerability scan & risk assessment immediately</span>
                        </label>
                      </form>
                      <form onSubmit={handleBulkCreateTargets} className="mt-5 space-y-3">
                        <div className="flex items-center justify-between">
                          <p className="text-xs font-mono text-[#AAA]">
                            Bulk (one per line, optional <span className="text-[#888]">value,type</span>).
                          </p>
                          <span className="text-[11px] font-mono text-neutral-400">
                            Max 25 total
                          </span>
                        </div>
                        <textarea
                          value={bulkTargetsText}
                          onChange={(e) => setBulkTargetsText(e.target.value)}
                          placeholder={'example.com,DOMAIN\nhttps://api.example.com/foo\n1.2.3.0/24,CIDR'}
                          rows={5}
                          className="w-full rounded-xl border border-[#333] bg-[#111]/40 px-3 py-2 text-sm text-white font-mono focus:border-neutral-500/50 focus:outline-none"
                        />
                        <button
                          type="submit"
                          disabled={submitting || !bulkTargetsText.trim()}
                          className="w-full rounded-xl bg-neutral-700 py-2.5 text-sm font-bold text-white hover:bg-neutral-600 disabled:opacity-50"
                        >
                          {submitting ? 'Submitting...' : 'Submit bulk targets'}
                        </button>
                      </form>
                    </div>
                  </div>
                )}

                <div className="overflow-x-auto rounded-xl border border-[#222]/80 bg-[#070b12]">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#222] text-left text-[11px] font-semibold uppercase tracking-wider text-[#888]">
                        <th className="p-3 pl-4">Target</th>
                        <th className="p-3">Type</th>
                        <th className="p-3">Services</th>
                        <th className="p-3">Risk Assessment</th>
                        <th className="p-3">Last discovery</th>
                        <th className="p-3">Scan status</th>
                        <th className="p-3 pr-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="text-neutral-200">
                      {targetsRefreshing ? (
                        Array.from({ length: Math.min(10, Number(targetParams.limit ?? 10)) }).map((_, i) => (
                          <tr key={`tgt-sk-${i}`} className="border-t border-[#222]/80">
                            <td className="p-3 pl-4">
                              <div className="h-5 w-48 max-w-full animate-pulse rounded-md bg-[#151515]/70" />
                            </td>
                            <td className="p-3">
                              <div className="h-7 w-20 animate-pulse rounded-full bg-[#151515]/70" />
                            </td>
                            <td className="p-3">
                              <div className="h-5 w-24 animate-pulse rounded bg-[#151515]/70" />
                            </td>
                            <td className="p-3">
                              <div className="h-6 w-24 animate-pulse rounded-full bg-[#151515]/70" />
                            </td>
                            <td className="p-3">
                              <div className="h-5 w-28 animate-pulse rounded bg-[#151515]/70" />
                            </td>
                            <td className="p-3">
                              <div className="h-8 w-28 animate-pulse rounded-full bg-[#151515]/70" />
                            </td>
                            <td className="p-3 pr-4 text-right">
                              <div className="ml-auto h-8 w-24 animate-pulse rounded-lg bg-[#151515]/70" />
                            </td>
                          </tr>
                        ))
                      ) : targets.length === 0 ? (
                        <tr>
                          <td colSpan={7} className="p-10 text-center text-sm text-[#888]">
                            No targets found.
                          </td>
                        </tr>
                      ) : (
                        targets.map((t) => {
                          const sp = targetListStatusPresentation(t.status);
                          const s = normalizeTargetStatus(t.status);
                          const polling = targetScanNeedsPolling(t.status);
                          const statusIcon =
                            s === 'completed' ? (
                              <CheckCircle2 size={14} className="shrink-0 text-emerald-400/90" />
                            ) : polling ? (
                              <Loader2 size={14} className="shrink-0 animate-spin text-white" />
                            ) : s === 'failed' ? (
                              <XCircle size={14} className="shrink-0 text-red-400" />
                            ) : (
                              <AlertTriangle size={14} className="shrink-0 text-[#888]" />
                            );
                          const n = Number(t.totalAssetServices ?? 0);
                          const assessment = t.assessment as AsmRiskAssessment | undefined;
                          return (
                            <tr key={t.id} className="border-t border-[#222]/80 transition-colors hover:bg-white/[0.04]">
                              <td className="p-3 pl-4 align-middle font-semibold text-white">{t.value}</td>
                              <td className="p-3 align-middle">
                                <span className="inline-flex items-center rounded-full border border-sky-500/35 bg-sky-950/30 px-2.5 py-1 text-[11px] font-medium text-sky-300">
                                  {t.type}
                                </span>
                              </td>
                              <td className="p-3 align-middle">
                                <span className="font-semibold tabular-nums text-white">{n}</span>
                                <span className="text-[13px] font-normal text-[#888]"> services</span>
                              </td>
                              <td className="p-3 align-middle">
                                {assessment?.threatScore != null ? (
                                  (() => {
                                    const score = assessment.threatScore;
                                    const lvl = (assessment.riskLevel || 'LOW').toUpperCase();
                                    const badgeClass =
                                      lvl === 'CRITICAL'
                                        ? 'border-red-500/40 text-red-300 bg-red-950/40 hover:bg-red-900/50'
                                        : lvl === 'HIGH'
                                        ? 'border-orange-500/40 text-orange-300 bg-orange-950/40 hover:bg-orange-900/50'
                                        : lvl === 'MEDIUM'
                                        ? 'border-amber-500/40 text-amber-300 bg-amber-950/40 hover:bg-amber-900/50'
                                        : 'border-emerald-500/40 text-emerald-300 bg-emerald-950/40 hover:bg-emerald-900/50';
                                    return (
                                      <button
                                        type="button"
                                        onClick={() => void handleOpenRiskModal(t)}
                                        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-mono font-bold transition ${badgeClass}`}
                                        title="Click to view full risk assessment"
                                      >
                                        <span>{score}/100</span>
                                        <span className="text-[10px] font-semibold tracking-wider opacity-80">{lvl}</span>
                                      </button>
                                    );
                                  })()
                                ) : (
                                  <button
                                    type="button"
                                    onClick={() => void handleOpenRiskModal(t)}
                                    className="inline-flex items-center gap-1 rounded-md border border-neutral-700/60 bg-neutral-900/40 px-2 py-1 text-xs text-neutral-400 hover:border-neutral-500 hover:text-white"
                                    title="View or assess target risk"
                                  >
                                    <ShieldAlert size={12} className="text-neutral-500" />
                                    <span>Assess</span>
                                  </button>
                                )}
                              </td>
                              <td className="p-3 align-middle text-[13px] text-[#AAA]">
                                {formatRelativeAgo(typeof t.lastDiscoveredAt === 'string' ? t.lastDiscoveredAt : undefined)}
                              </td>
                              <td className="p-3 align-middle">
                                <span
                                  className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1.5 text-[11px] font-medium ${sp.pillClass}`}
                                >
                                  {statusIcon}
                                  {sp.label}
                                </span>
                              </td>
                              <td className="p-3 pr-4 text-right align-middle">
                                <div className="inline-flex items-center justify-end gap-1.5">
                                  <button
                                    type="button"
                                    onClick={() => void handleOpenRiskModal(t)}
                                    className="rounded-lg border border-red-500/30 bg-red-950/20 px-2.5 py-1.5 text-xs font-medium text-red-200 hover:border-red-500/50 hover:bg-red-950/40"
                                    title="View threat score and risk breakdown"
                                  >
                                    Risk
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleOpenTargetDetail(String(t.id))}
                                    className="rounded-lg border border-neutral-600 bg-[#151515]/80 px-2.5 py-1.5 text-xs font-medium text-white hover:border-neutral-500 hover:bg-[#1C1C1C]"
                                  >
                                    Details
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
                <div className="flex items-center justify-between text-xs text-[#888] font-mono">
                  <div>
                    total={targetsMeta.total ?? 0} page={targetsMeta.page ?? 1}/{targetsMeta.pageCount ?? 1} limit={targetsMeta.limit ?? 10}
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={(targetParams.page ?? 1) <= 1}
                      onClick={() => setTargetParams((prev) => ({ ...prev, page: Math.max(1, Number(prev.page ?? 1) - 1) }))}
                      className="px-2 py-1 rounded bg-[#1C1C1C] hover:bg-neutral-600 text-white disabled:opacity-40"
                    >
                      Prev
                    </button>
                    <button
                      type="button"
                      disabled={!targetsMeta.hasNextPage}
                      onClick={() => setTargetParams((prev) => ({ ...prev, page: Number(prev.page ?? 1) + 1 }))}
                      className="px-2 py-1 rounded bg-[#1C1C1C] hover:bg-neutral-600 text-white disabled:opacity-40"
                    >
                      Next
                    </button>
                  </div>
                </div>

                {selectedTargetId && (
                  <div className="fixed top-0 right-0 z-40 flex h-screen w-full max-w-[920px] flex-col overflow-hidden border-l border-[#222] bg-[#0b1220] shadow-2xl">
                    <div className="z-10 shrink-0 space-y-3 border-b border-[#222] bg-[#0b1220]/95 p-4 backdrop-blur">
                      <div className="flex items-center justify-between gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedTargetId(null);
                            setTargetDetail(null);
                            setTargetRoute(null);
                            setTargetSettingsOpen(false);
                          }}
                          className="rounded bg-[#151515] px-2 py-1 text-xs font-mono text-white hover:bg-[#1C1C1C]"
                        >
                          Back
                        </button>
                        <div className="flex items-center gap-2">
                          {targetDetail ? (
                            <>
                              <button
                                type="button"
                                onClick={() => void handleOpenRiskModal(targetDetail)}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/40 bg-red-950/30 px-3 py-2 text-xs font-medium text-red-200 hover:bg-red-900/40"
                              >
                                <ShieldAlert size={14} />
                                Risk Assessment
                              </button>
                              <button
                                type="button"
                                onClick={() => setTargetSettingsOpen(true)}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-neutral-600 bg-[#111] px-3 py-2 text-xs font-medium text-neutral-200 hover:bg-[#151515]"
                              >
                                <Settings2 size={14} />
                                Target settings
                              </button>
                            </>
                          ) : null}
                          <button
                            type="button"
                            onClick={() => {
                              setSelectedTargetId(null);
                              setTargetDetail(null);
                              setTargetRoute(null);
                              setTargetSettingsOpen(false);
                            }}
                            className="rounded-lg p-2 text-[#AAA] hover:bg-[#151515] hover:text-white"
                            aria-label="Close panel"
                          >
                            <X size={18} />
                          </button>
                        </div>
                      </div>
                      {discoveringAnimation && (
                        <div className="animate-pulse rounded border border-neutral-700/40 bg-[#111] px-3 py-2 font-mono text-xs text-white">
                          Discovering target... inventory auto-refresh is accelerated.
                        </div>
                      )}
                      {targetDetailLoading ? (
                        <div className="font-mono text-sm text-[#888]">Loading target detail...</div>
                      ) : targetDetail ? (
                        <div className="space-y-1">
                          <div className="text-lg font-bold text-white">{targetDetail.value}</div>
                          <div className="flex flex-wrap items-center gap-3 font-mono text-xs text-[#AAA]">
                            <span>Type: {targetDetail.type}</span>
                            {(() => {
                              const sp = targetListStatusPresentation(targetDetail.status);
                              const s = normalizeTargetStatus(targetDetail.status);
                              const polling = targetScanNeedsPolling(targetDetail.status);
                              const icon =
                                s === 'completed' ? (
                                  <CheckCircle2 size={12} className="shrink-0 opacity-90" />
                                ) : polling ? (
                                  <Loader2 size={12} className="shrink-0 animate-spin" />
                                ) : s === 'failed' ? (
                                  <XCircle size={12} className="shrink-0" />
                                ) : (
                                  <AlertTriangle size={12} className="shrink-0 opacity-80" />
                                );
                              return (
                                <span
                                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium ${sp.pillClass}`}
                                >
                                  {icon}
                                  {sp.label}
                                </span>
                              );
                            })()}
                            <span>Last discovered: {String(targetDetail.lastDiscoveredAt ?? '—')}</span>
                          </div>
                        </div>
                      ) : (
                        <div className="font-mono text-sm text-[#888]">Unable to load target detail.</div>
                      )}
                      <div className="flex gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => setTargetDetailTab('inventory')}
                          className={`rounded border px-3 py-1.5 font-mono text-xs ${
                            targetDetailTab === 'inventory'
                              ? 'border-neutral-500/40 bg-neutral-600/20 text-white'
                              : 'border-[#333] bg-[#111]/30 text-[#AAA]'
                          }`}
                        >
                          Inventory
                        </button>
                        <button
                          type="button"
                          onClick={() => setTargetDetailTab('vulnerabilities')}
                          className={`rounded border px-3 py-1.5 font-mono text-xs ${
                            targetDetailTab === 'vulnerabilities'
                              ? 'border-neutral-500/40 bg-neutral-600/20 text-white'
                              : 'border-[#333] bg-[#111]/30 text-[#AAA]'
                          }`}
                        >
                          Vulnerabilities
                        </button>
                      </div>
                    </div>

                    {targetSettingsOpen && targetDetail ? (
                      <div
                        className="fixed inset-0 z-[60] flex items-center justify-center bg-[#111]/70 p-4 backdrop-blur-sm"
                        onClick={() => setTargetSettingsOpen(false)}
                      >
                        <div
                          className="w-full max-w-md rounded-2xl border border-[#222] bg-[#0c1220] p-6 shadow-2xl"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <div className="mb-6 flex items-start justify-between gap-3">
                            <h2 className="text-lg font-semibold text-white">{targetDetail.value}</h2>
                            <button
                              type="button"
                              onClick={() => setTargetSettingsOpen(false)}
                              className="rounded-lg p-1 text-[#AAA] hover:bg-[#151515] hover:text-white"
                            >
                              <X size={20} />
                            </button>
                          </div>
                          <div className="mb-6 flex gap-4">
                            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-neutral-600/25">
                              <Clock size={22} className="text-white" />
                            </div>
                            <div className="min-w-0 flex-1 space-y-2">
                              <div className="font-semibold text-white">Scan schedule</div>
                              <select
                                value={scheduleValue}
                                onChange={(e) => setScheduleValue(e.target.value)}
                                className="w-full appearance-none rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-2.5 pl-3 pr-8 text-sm text-white focus:border-neutral-500/50 focus:outline-none"
                              >
                                {[
                                  ...SCAN_SCHEDULE_OPTIONS,
                                  ...(scheduleValue && !SCAN_SCHEDULE_OPTIONS.some((o) => o.cron === scheduleValue)
                                    ? [{ label: `Custom (${scheduleValue})`, cron: scheduleValue }]
                                    : []),
                                ].map((o) => (
                                  <option key={`${o.label}-${o.cron}`} value={o.cron}>
                                    {o.label}
                                  </option>
                                ))}
                              </select>
                              <p className="text-[11px] text-[#888]">Uses cron on the backend. Choose a preset or keep a custom expression from the API.</p>
                              <button
                                type="button"
                                onClick={handleUpdateSchedule}
                                disabled={submitting}
                                className="inline-flex items-center gap-1.5 rounded-xl bg-neutral-600 px-4 py-2 text-sm font-semibold text-white hover:bg-neutral-500 disabled:opacity-50"
                              >
                                <Save size={14} />
                                Save schedule
                              </button>
                            </div>
                          </div>
                          <div className="mb-8 flex gap-4 border-t border-[#222] pt-6">
                            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-sky-600/25">
                              <RotateCw size={22} className="text-sky-200" />
                            </div>
                            <div className="min-w-0 flex-1 space-y-1">
                              <div className="font-semibold text-white">Re-discover target</div>
                              <p className="text-sm text-[#888]">Scan the target again for changes.</p>
                              <button
                                type="button"
                                onClick={async () => {
                                  await handleRescan();
                                }}
                                disabled={submitting}
                                className="mt-2 rounded-xl border border-sky-500/40 bg-sky-950/40 px-4 py-2 text-sm font-medium text-sky-200 hover:bg-sky-900/40 disabled:opacity-50"
                              >
                                Run re-discovery
                              </button>
                            </div>
                          </div>
                          <div className="flex justify-center border-t border-[#222] pt-6">
                            <button
                              type="button"
                              onClick={handleDeleteTarget}
                              disabled={submitting}
                              className="inline-flex items-center gap-2 rounded-xl border border-neutral-600 bg-[#111]/30 px-5 py-2.5 text-sm font-medium text-red-400 hover:border-red-500/40 hover:bg-red-950/20 disabled:opacity-50"
                            >
                              <Trash2 size={16} />
                              Delete target
                            </button>
                          </div>
                        </div>
                      </div>
                    ) : null}

                    <div className="custom-scrollbar min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
                      {targetDetailTab === 'inventory' && (
                        <>
                          <div className="flex flex-wrap gap-2">
                            {(['all', 'ip', 'port', 'tech', 'status-code', 'host', 'tls'] as AssetGroupTab[]).map((tab) => (
                              <button
                                key={tab}
                                type="button"
                                onClick={() => {
                                  setTargetInventoryGroup(tab);
                                  setTargetInventoryParams((prev) => ({ ...prev, page: 1 }));
                                }}
                                className={`px-2 py-1 rounded text-xs font-mono border ${
                                  targetInventoryGroup === tab ? 'bg-neutral-600/20 border-neutral-500/40 text-white' : 'bg-[#111]/30 border-[#333] text-[#AAA]'
                                }`}
                              >
                                {INVENTORY_SUBTAB_LABELS[tab]}
                              </button>
                            ))}
                          </div>
                          <div className="space-y-3 rounded-xl border border-[#222] bg-[#111]/20 p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <div className="relative min-w-[200px] flex-1">
                                <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#888]" />
                                <input
                                  type="text"
                                  value={targetInventoryParams.value ?? ''}
                                  onChange={(e) => setTargetInventoryParams((prev) => ({ ...prev, value: e.target.value, page: 1 }))}
                                  placeholder="Filter (value)"
                                  className="w-full rounded-xl border border-dashed border-neutral-600 bg-[#111]/40 py-2 pl-9 pr-3 text-xs text-white font-mono placeholder:text-[#888]"
                                />
                              </div>
                              <button
                                type="button"
                                onClick={async () => {
                                  if (!selectedWorkspaceId || !selectedTargetId) return;
                                  try {
                                    const res = await openasm.exportAssetServices(buildInventoryExportParams(), selectedWorkspaceId);
                                    const blobUrl = window.URL.createObjectURL(res.data);
                                    const cd = String(res.headers?.['content-disposition'] ?? '');
                                    const nameMatch = cd.match(/filename="?([^"]+)"?/i);
                                    const filename = nameMatch?.[1] ?? `target-${selectedTargetId}-services.csv`;
                                    const a = document.createElement('a');
                                    a.href = blobUrl;
                                    a.download = filename;
                                    document.body.appendChild(a);
                                    a.click();
                                    a.remove();
                                    window.URL.revokeObjectURL(blobUrl);
                                  } catch (e) {
                                    const msg = formatApiError(e);
                                    setError(
                                      (e as OpenAsmApiError)?.response?.status === 403
                                        ? `${msg} Export may require workspace owner in Open-ASM.`
                                        : msg,
                                    );
                                  }
                                }}
                                className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-neutral-600 bg-[#151515]/80 px-3 py-2 text-xs font-mono text-white hover:bg-[#1C1C1C]"
                              >
                                <Download size={14} />
                                Export CSV
                              </button>
                              <button
                                type="button"
                                onClick={resetAllInventoryFilters}
                                className="rounded-xl border border-[#333] px-3 py-2 text-xs font-mono text-[#AAA] hover:bg-[#151515] hover:text-white"
                              >
                                Reset all
                              </button>
                            </div>
                            <div ref={inventoryFacetBarRef} className="flex flex-wrap gap-2">
                              {(Object.keys(FACET_MENU_LABEL) as InventoryFacetMenu[]).map((menu) => (
                                <div key={menu} className="relative">
                                  <button
                                    type="button"
                                    onClick={() => setOpenInventoryFacet((o) => (o === menu ? null : menu))}
                                    className={`inline-flex items-center gap-2 rounded-xl border border-dashed px-3 py-2 text-xs font-medium transition-colors ${
                                      openInventoryFacet === menu
                                        ? 'border-neutral-500/50 bg-neutral-950/30 text-white'
                                        : 'border-neutral-600 bg-[#111]/30 text-neutral-300 hover:border-neutral-500'
                                    }`}
                                  >
                                    <Plus size={14} className="shrink-0 opacity-80" />
                                    {FACET_MENU_LABEL[menu]}
                                    {inventoryFacets[menu].length > 0 ? (
                                      <span className="rounded-md border border-neutral-600 bg-[#111] px-1.5 py-0.5 font-mono text-[10px] text-neutral-200">
                                        {inventoryFacets[menu].length}
                                      </span>
                                    ) : null}
                                  </button>
                                  {openInventoryFacet === menu && (
                                    <div className="absolute left-0 top-full z-[55] mt-1 w-[min(100vw-2rem,22rem)] rounded-xl border border-[#333] bg-[#0c1220] shadow-2xl">
                                      <div className="flex items-center gap-2 border-b border-[#222] p-2">
                                        <Search size={14} className="shrink-0 text-[#888]" />
                                        <input
                                          value={inventoryFacetSearch}
                                          onChange={(e) => setInventoryFacetSearch(e.target.value)}
                                          placeholder={FACET_MENU_LABEL[menu]}
                                          className="min-w-0 flex-1 bg-transparent text-sm text-white outline-none placeholder:text-neutral-600"
                                        />
                                      </div>
                                      <div className="max-h-56 overflow-y-auto p-1">
                                        {inventoryFacetLoading ? (
                                          <div className="flex justify-center py-6">
                                            <Loader2 size={20} className="animate-spin text-red-500" />
                                          </div>
                                        ) : inventoryFacetRows.length === 0 ? (
                                          <div className="px-2 py-4 text-center text-xs text-[#888]">No options</div>
                                        ) : (
                                          inventoryFacetRows.map((row, i) => {
                                            const r = row as Record<string, unknown>;
                                            const val = facetRowPickValue(FACET_GROUP[menu], r);
                                            if (!val) return null;
                                            const selected = inventoryFacets[menu].includes(val);
                                            return (
                                              <button
                                                key={`${val}-${i}`}
                                                type="button"
                                                onClick={() => toggleInventoryFacetValue(menu, val)}
                                                className={`flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-sm ${
                                                  selected ? 'bg-[#1C1C1C]/80 text-white' : 'text-neutral-300 hover:bg-[#151515]/80'
                                                }`}
                                              >
                                                {selected ? <CheckCircle2 size={15} className="shrink-0 text-red-400" /> : <span className="w-[15px] shrink-0" />}
                                                <span className="min-w-0 flex-1 truncate font-mono text-[12px]">{val}</span>
                                                {r.assetCount != null && (
                                                  <span className="shrink-0 text-[11px] text-[#888]">{String(r.assetCount)}</span>
                                                )}
                                              </button>
                                            );
                                          })
                                        )}
                                      </div>
                                      <button
                                        type="button"
                                        onClick={() => clearInventoryFacetMenu(menu)}
                                        className="w-full border-t border-[#222] py-2 text-center text-xs text-[#AAA] hover:bg-[#111] hover:text-white"
                                      >
                                        Clear filters
                                      </button>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                          {targetInventory.length === 0 ? (
                            <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                              No inventory found for this target.
                            </div>
                          ) : targetInventoryGroup === 'all' ? (
                            <InventoryAllServicesTable
                              items={targetInventory}
                              resolveAssetMediaUrl={resolveAssetMediaUrl}
                              onScreenshotClick={(u) => setScreenshotModalUrl(u)}
                            />
                          ) : (
                            <InventoryGroupedTable
                              group={targetInventoryGroup}
                              items={targetInventory}
                              resolveAssetMediaUrl={resolveAssetMediaUrl}
                            />
                          )}
                          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-[#888] font-mono">
                            <div>
                              total={targetInventoryMeta.total ?? 0} page={targetInventoryMeta.page ?? 1}/{targetInventoryMeta.pageCount ?? 1}{' '}
                              limit={targetInventoryMeta.limit ?? 10}
                            </div>
                            <div className="flex flex-wrap items-center gap-2">
                              <label className="flex items-center gap-2 text-[11px] text-[#AAA]">
                                <span>Rows</span>
                                <select
                                  value={String(targetInventoryParams.limit ?? 10)}
                                  onChange={(e) =>
                                    setTargetInventoryParams((prev) => ({
                                      ...prev,
                                      limit: Number(e.target.value),
                                      page: 1,
                                    }))
                                  }
                                  className="rounded-lg border border-[#333] bg-[#111]/50 px-2 py-1 text-neutral-200"
                                >
                                  <option value={10}>10</option>
                                  <option value={25}>25</option>
                                  <option value={50}>50</option>
                                </select>
                              </label>
                              <button
                                type="button"
                                disabled={(targetInventoryParams.page ?? 1) <= 1}
                                onClick={() => setTargetInventoryParams((prev) => ({ ...prev, page: Math.max(1, Number(prev.page ?? 1) - 1) }))}
                                className="rounded-lg bg-[#1C1C1C] px-3 py-1.5 text-white hover:bg-neutral-600 disabled:opacity-40"
                              >
                                Previous
                              </button>
                              <span className="rounded border border-[#333] bg-[#111]/40 px-2 py-1 text-neutral-300">
                                {targetInventoryMeta.page ?? 1}
                              </span>
                              <button
                                type="button"
                                disabled={!targetInventoryMeta.hasNextPage}
                                onClick={() => setTargetInventoryParams((prev) => ({ ...prev, page: Number(prev.page ?? 1) + 1 }))}
                                className="rounded-lg bg-[#1C1C1C] px-3 py-1.5 text-white hover:bg-neutral-600 disabled:opacity-40"
                              >
                                Next
                              </button>
                            </div>
                          </div>
                        </>
                      )}

                      {targetDetailTab === 'vulnerabilities' && (
                        <>
                          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                            <h3 className="text-sm font-semibold text-neutral-300">Vulnerabilities</h3>
                            <button
                              type="button"
                              onClick={handleScanNow}
                              disabled={submitting || normalizeTargetStatus(targetDetail?.status) !== 'completed'}
                              className="inline-flex items-center gap-2 rounded-xl border border-neutral-500/40 bg-neutral-950/40 px-4 py-2 text-sm font-semibold text-white hover:bg-[#111] disabled:opacity-50"
                            >
                              <Play size={16} />
                              Scan vulnerabilities
                            </button>
                          </div>
                          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
                            {(
                              [
                                ['critical', Flame, 'text-red-400'],
                                ['high', AlertTriangle, 'text-white'],
                                ['medium', Bug, 'text-white'],
                                ['low', Eye, 'text-sky-400'],
                                ['info', Info, 'text-neutral-200'],
                              ] as const
                            ).map(([sev, Icon, accent]) => (
                              <div
                                key={sev}
                                className="relative overflow-hidden rounded-xl border border-[#222]/90 bg-[#111827]/90 p-4"
                              >
                                <div className="flex items-start justify-between gap-2">
                                  <span className={`text-[11px] font-bold uppercase tracking-wide ${accent}`}>{sev}</span>
                                  <Icon size={18} className={`shrink-0 ${accent}`} />
                                </div>
                                <div className="mt-3 text-3xl font-bold tabular-nums text-white">{targetVulnStats[sev] ?? 0}</div>
                              </div>
                            ))}
                          </div>
                          <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                            <div className="relative min-w-0 flex-1 lg:max-w-xl">
                              <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#888]" />
                              <input
                                type="text"
                                value={targetVulnParams.search ?? ''}
                                onChange={(e) => setTargetVulnParams((prev) => ({ ...prev, search: e.target.value, page: 1 }))}
                                placeholder="Search"
                                className="w-full rounded-xl border border-[#333] bg-[#111]/50 py-2.5 pl-10 pr-3 text-sm text-white placeholder:text-[#888]"
                              />
                            </div>
                            <div className="flex flex-wrap items-center justify-end gap-2">
                              <div className="relative">
                                <select
                                  value={targetVulnParams.status ?? 'open'}
                                  onChange={(e) => setTargetVulnParams((prev) => ({ ...prev, status: e.target.value, page: 1 }))}
                                  className="appearance-none rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-2.5 pl-3 pr-9 text-sm text-white"
                                >
                                  <option value="open">Open</option>
                                  <option value="dismissed">Dismissed</option>
                                  <option value="resolved">Resolved</option>
                                  <option value="">All status</option>
                                </select>
                                <ChevronDown size={16} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-[#888]" />
                              </div>
                              <div className="relative inline-flex items-center gap-2 rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-1 pl-2 pr-2">
                                <Filter size={14} className="shrink-0 text-[#888]" />
                                <select
                                  value={targetVulnParams.severity ?? ''}
                                  onChange={(e) => setTargetVulnParams((prev) => ({ ...prev, severity: e.target.value, page: 1 }))}
                                  className="appearance-none bg-transparent py-2 pr-6 text-sm text-white outline-none"
                                >
                                  <option value="">Severity</option>
                                  <option value="critical">Critical</option>
                                  <option value="high">High</option>
                                  <option value="medium">Medium</option>
                                  <option value="low">Low</option>
                                  <option value="info">Info</option>
                                </select>
                                <ChevronDown size={14} className="pointer-events-none absolute right-1 top-1/2 -translate-y-1/2 text-[#888]" />
                              </div>
                              <div className="inline-flex items-center gap-2 rounded-xl border border-neutral-600 bg-[#111]/40 px-3 py-2">
                                <Calendar size={14} className="shrink-0 text-[#888]" />
                                <span className="text-xs text-[#888]">Date</span>
                                <input
                                  type="date"
                                  value={targetVulnParams.createdFrom ?? ''}
                                  onChange={(e) => setTargetVulnParams((prev) => ({ ...prev, createdFrom: e.target.value, page: 1 }))}
                                  className="rounded border border-[#333] bg-[#111]/50 px-2 py-1 text-xs text-white"
                                />
                                <input
                                  type="date"
                                  value={targetVulnParams.createdTo ?? ''}
                                  onChange={(e) => setTargetVulnParams((prev) => ({ ...prev, createdTo: e.target.value, page: 1 }))}
                                  className="rounded border border-[#333] bg-[#111]/50 px-2 py-1 text-xs text-white"
                                />
                              </div>
                            </div>
                          </div>
                          <div className="overflow-x-auto rounded-xl border border-[#222]">
                            <table className="w-full min-w-[960px] text-left text-xs">
                              <thead className="border-b border-[#222] bg-[#111]/40 text-[11px] font-semibold uppercase tracking-wide text-[#888]">
                                <tr>
                                  <th className="p-3 pl-4">
                                    <button
                                      type="button"
                                      className="inline-flex items-center gap-1 text-[#AAA] hover:text-white"
                                      onClick={() =>
                                        setTargetVulnParams((p) => ({
                                          ...p,
                                          sortBy: 'severity',
                                          sortOrder: p.sortOrder === 'DESC' ? 'ASC' : 'DESC',
                                          page: 1,
                                        }))
                                      }
                                    >
                                      Severity
                                      <ArrowUpDown size={12} />
                                    </button>
                                  </th>
                                  <th className="p-3">Details</th>
                                  <th className="p-3">Affected URL</th>
                                  <th className="p-3">CVSS</th>
                                  <th className="p-3">Tags</th>
                                  <th className="p-3">Created</th>
                                  <th className="p-3">Scanned by</th>
                                  <th className="p-3 pr-4">Status</th>
                                  <th className="p-3 pr-4 text-right"> </th>
                                </tr>
                              </thead>
                              <tbody className="text-neutral-200">
                                {targetVulnerabilities.map((v) => {
                                  const row = v as Record<string, unknown>;
                                  const id = String(v.id);
                                  const name = String(row.name ?? row.title ?? '—');
                                  const sev = String(v.severity ?? 'unknown');
                                  const url = String(row.affectedUrl ?? '');
                                  const cv = row.cvssScore;
                                  const cvssLabel = cv != null && String(cv) !== '' ? String(cv) : 'Not matched';
                                  const tags = Array.isArray(row.tags) ? (row.tags as string[]) : [];
                                  const tool = row.tool as Record<string, unknown> | undefined;
                                  const tname = tool ? String(tool.name ?? '') : '';
                                  const tlogo = tool && typeof tool.logoUrl === 'string' ? tool.logoUrl : '';
                                  const logoSrc = resolveAssetMediaUrl(tlogo || null);
                                  const created = row.createdAt ? new Date(String(row.createdAt)).toLocaleDateString() : '—';
                                  const st = String(v.status ?? 'open');
                                  return (
                                    <tr key={id} className="border-t border-[#222]/80 hover:bg-white/[0.03]">
                                      <td className="p-3 pl-4 align-middle">
                                        <span
                                          className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-semibold capitalize ${vulnSeverityBadgeClass(sev)}`}
                                        >
                                          {sev}
                                        </span>
                                      </td>
                                      <td className="max-w-[220px] p-3 align-middle">
                                        <div className="flex items-center gap-1.5">
                                          <span className="font-semibold text-white">{name}</span>
                                          <button
                                            type="button"
                                            onClick={() => handleOpenVulnerabilityDetail(id)}
                                            className="shrink-0 text-[#888] hover:text-red-400"
                                            title="Details"
                                          >
                                            <Info size={14} />
                                          </button>
                                        </div>
                                      </td>
                                      <td className="max-w-[200px] p-3 align-middle">
                                        {url ? (
                                          <a
                                            href={url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex items-center gap-1 break-all text-sky-400 hover:text-sky-300"
                                          >
                                            {url}
                                            <ExternalLink size={12} className="shrink-0" />
                                          </a>
                                        ) : (
                                          '—'
                                        )}
                                      </td>
                                      <td className="p-3 align-middle font-mono text-[#AAA]">{cvssLabel}</td>
                                      <td className="p-3 align-middle">
                                        <div className="flex flex-wrap gap-1">
                                          {tags.slice(0, 3).map((t) => (
                                            <span
                                              key={t}
                                              className="rounded-md border border-[#333] bg-[#111]/40 px-2 py-0.5 text-[10px] text-neutral-300"
                                            >
                                              {t}
                                            </span>
                                          ))}
                                          {tags.length > 3 ? (
                                            <span className="rounded-md border border-[#333] px-2 py-0.5 text-[10px] text-[#888]">
                                              +{tags.length - 3}
                                            </span>
                                          ) : null}
                                        </div>
                                      </td>
                                      <td className="p-3 align-middle text-neutral-300">{created}</td>
                                      <td className="p-3 align-middle">
                                        <div className="flex items-center gap-2">
                                          {logoSrc ? (
                                            <img src={logoSrc} alt="" className="h-8 w-8 rounded-lg border border-[#333] bg-white/5 object-contain p-0.5" />
                                          ) : (
                                            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#333] bg-[#111] text-[10px] text-neutral-600">
                                              ?
                                            </div>
                                          )}
                                          <span className="text-neutral-200">{tname || '—'}</span>
                                        </div>
                                      </td>
                                      <td className="p-3 align-middle">
                                        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/50 bg-emerald-950/25 px-2.5 py-1 text-[10px] font-medium text-emerald-300">
                                          <CheckCircle2 size={12} />
                                          {st}
                                        </span>
                                      </td>
                                      <td className="p-3 pr-4 text-right align-middle">
                                        <button
                                          type="button"
                                          onClick={() => handleOpenVulnerabilityDetail(id)}
                                          className="rounded-lg border border-neutral-600 bg-[#151515] px-3 py-1.5 text-xs text-white hover:bg-[#1C1C1C]"
                                        >
                                          Details
                                        </button>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-[#888] font-mono">
                            <span>
                              total={targetVulnMeta.total ?? 0} page={targetVulnMeta.page ?? 1}/{targetVulnMeta.pageCount ?? 1}
                            </span>
                            <div className="flex gap-2">
                              <button
                                type="button"
                                disabled={(targetVulnParams.page ?? 1) <= 1}
                                onClick={() => setTargetVulnParams((p) => ({ ...p, page: Math.max(1, Number(p.page ?? 1) - 1) }))}
                                className="rounded bg-[#1C1C1C] px-2 py-1 text-white disabled:opacity-40"
                              >
                                Prev
                              </button>
                              <button
                                type="button"
                                disabled={!targetVulnMeta.hasNextPage}
                                onClick={() => setTargetVulnParams((p) => ({ ...p, page: Number(p.page ?? 1) + 1 }))}
                                className="rounded bg-[#1C1C1C] px-2 py-1 text-white disabled:opacity-40"
                              >
                                Next
                              </button>
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
            {activeTab === 'targets' && !selectedWorkspaceId && (
              <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                Select a workspace to manage targets.
              </div>
            )}

            {activeTab === 'assets' && selectedWorkspaceId && (
              <div className={`space-y-4 ${assetsListRefreshing ? 'opacity-70' : ''}`}>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h3 className="text-xl font-bold text-white">Assets</h3>
                  {assetsListRefreshing ? (
                    <span className="inline-flex items-center gap-2 text-xs text-[#888]">
                      <Loader2 size={14} className="animate-spin" />
                      Loading…
                    </span>
                  ) : null}
                </div>
                <div className="flex flex-wrap gap-2 border-b border-[#222] pb-3">
                  {(['all', 'ip', 'port', 'tech', 'status-code', 'host', 'tls'] as AssetGroupTab[]).map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      onClick={() => {
                        setAssetGroupTab(tab);
                        setAssetParams((prev) => ({ ...prev, page: 1 }));
                      }}
                      className={`rounded-xl border px-3 py-2 text-xs font-semibold transition-colors ${
                        assetGroupTab === tab
                          ? 'bg-neutral-600/20 border-neutral-500/40 text-white'
                          : 'bg-[#111]/30 border-[#333] text-[#AAA] hover:text-white'
                      }`}
                    >
                      {INVENTORY_SUBTAB_LABELS[tab]}
                    </button>
                  ))}
                </div>
                <div className="flex flex-col gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative min-w-[min(100%,240px)] flex-1">
                      <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#888]" />
                      <input
                        type="text"
                        value={assetParams.value ?? ''}
                        onChange={(e) => setAssetParams((prev) => ({ ...prev, value: e.target.value, page: 1 }))}
                        placeholder="Filter value"
                        className="w-full rounded-xl border border-dashed border-neutral-600 bg-[#111]/40 py-2 pl-9 pr-3 text-xs text-white font-mono placeholder:text-[#888]"
                      />
                    </div>
                    <input
                      type="text"
                      value={assetParams.search ?? ''}
                      onChange={(e) => setAssetParams((prev) => ({ ...prev, search: e.target.value, page: 1 }))}
                      placeholder="Search"
                      className="min-w-[160px] rounded-xl border border-[#333] bg-[#111]/40 px-3 py-2 text-xs text-white font-mono"
                    />
                    <input
                      type="text"
                      value={assetParams.type ?? ''}
                      onChange={(e) => setAssetParams((prev) => ({ ...prev, type: e.target.value, page: 1 }))}
                      placeholder="Type (optional)"
                      className="w-40 rounded-xl border border-[#333] bg-[#111]/40 px-3 py-2 text-xs text-white font-mono"
                    />
                    <button
                      type="button"
                      onClick={async () => {
                        if (!selectedWorkspaceId) return;
                        try {
                          const res = await openasm.exportAssetServices(buildWorkspaceExportParams(), selectedWorkspaceId);
                          const blobUrl = window.URL.createObjectURL(res.data);
                          const cd = String(res.headers?.['content-disposition'] ?? '');
                          const nameMatch = cd.match(/filename="?([^"]+)"?/i);
                          const filename = nameMatch?.[1] ?? `workspace-${selectedWorkspaceId.slice(0, 8)}-services.csv`;
                          const a = document.createElement('a');
                          a.href = blobUrl;
                          a.download = filename;
                          document.body.appendChild(a);
                          a.click();
                          a.remove();
                          window.URL.revokeObjectURL(blobUrl);
                        } catch (e) {
                          const msg = formatApiError(e);
                          setError(
                            (e as OpenAsmApiError)?.response?.status === 403
                              ? `${msg} Export may require workspace owner in Open-ASM.`
                              : msg,
                          );
                        }
                      }}
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-neutral-600 bg-[#151515]/80 px-3 py-2 text-xs font-mono text-white hover:bg-[#1C1C1C]"
                    >
                      <Download size={14} />
                      Export
                    </button>
                    <button
                      type="button"
                      onClick={resetAllAssetsFacets}
                      className="rounded-xl border border-[#333] px-3 py-2 text-xs font-mono text-[#AAA] hover:bg-[#151515] hover:text-white"
                    >
                      Reset all
                    </button>
                  </div>
                  <div ref={assetsFacetBarRef} className="flex flex-wrap gap-2">
                    {(Object.keys(FACET_MENU_LABEL) as InventoryFacetMenu[]).map((menu) => (
                      <div key={menu} className="relative">
                        <button
                          type="button"
                          onClick={() => setOpenAssetsFacet((o) => (o === menu ? null : menu))}
                          className={`inline-flex items-center gap-2 rounded-xl border border-dashed px-3 py-2 text-xs font-medium transition-colors ${
                            openAssetsFacet === menu
                              ? 'border-neutral-500/50 bg-neutral-950/30 text-white'
                              : 'border-neutral-600 bg-[#111]/30 text-neutral-300 hover:border-neutral-500'
                          }`}
                        >
                          <Plus size={14} className="shrink-0 opacity-80" />
                          {FACET_MENU_LABEL[menu]}
                          {assetsFacets[menu].length > 0 ? (
                            <span className="rounded-md border border-neutral-600 bg-[#111] px-1.5 py-0.5 font-mono text-[10px] text-neutral-200">
                              {assetsFacets[menu].length}
                            </span>
                          ) : null}
                        </button>
                        {openAssetsFacet === menu && (
                          <div className="absolute left-0 top-full z-[55] mt-1 w-[min(100vw-2rem,22rem)] rounded-xl border border-[#333] bg-[#0c1220] shadow-2xl">
                            <div className="flex items-center gap-2 border-b border-[#222] p-2">
                              <Search size={14} className="shrink-0 text-[#888]" />
                              <input
                                value={assetsFacetSearch}
                                onChange={(e) => setAssetsFacetSearch(e.target.value)}
                                placeholder={FACET_MENU_LABEL[menu]}
                                className="min-w-0 flex-1 bg-transparent text-sm text-white outline-none placeholder:text-neutral-600"
                              />
                            </div>
                            <div className="max-h-56 overflow-y-auto p-1">
                              {assetsFacetLoading ? (
                                <div className="flex justify-center py-6">
                                  <Loader2 size={20} className="animate-spin text-red-500" />
                                </div>
                              ) : assetsFacetRows.length === 0 ? (
                                <div className="px-2 py-4 text-center text-xs text-[#888]">No options</div>
                              ) : (
                                assetsFacetRows.map((row, i) => {
                                  const r = row as Record<string, unknown>;
                                  const val = facetRowPickValue(FACET_GROUP[menu], r);
                                  if (!val) return null;
                                  const selected = assetsFacets[menu].includes(val);
                                  return (
                                    <button
                                      key={`${val}-${i}`}
                                      type="button"
                                      onClick={() => toggleAssetsFacetValue(menu, val)}
                                      className={`flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-sm ${
                                        selected ? 'bg-[#1C1C1C]/80 text-white' : 'text-neutral-300 hover:bg-[#151515]/80'
                                      }`}
                                    >
                                      {selected ? <CheckCircle2 size={15} className="shrink-0 text-red-400" /> : <span className="w-[15px] shrink-0" />}
                                      <span className="min-w-0 flex-1 truncate font-mono text-[12px]">{val}</span>
                                      {r.assetCount != null && (
                                        <span className="shrink-0 text-[11px] text-[#888]">{String(r.assetCount)}</span>
                                      )}
                                    </button>
                                  );
                                })
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => clearAssetsFacetMenu(menu)}
                              className="w-full border-t border-[#222] py-2 text-center text-xs text-[#AAA] hover:bg-[#111] hover:text-white"
                            >
                              Clear filters
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
                {assets.length === 0 ? (
                  <div className="rounded-xl border border-[#222] bg-[#111] p-8 text-center text-sm text-[#888]">
                    No assets found.
                  </div>
                ) : assetGroupTab === 'all' ? (
                  <InventoryAllServicesTable
                    items={assets}
                    resolveAssetMediaUrl={resolveAssetMediaUrl}
                    onScreenshotClick={(u) => setScreenshotModalUrl(u)}
                    onOpenAssetDetail={(id) => handleOpenAssetDetail(id)}
                  />
                ) : (
                  <InventoryGroupedTable
                    group={assetGroupTab}
                    items={assets}
                    resolveAssetMediaUrl={resolveAssetMediaUrl}
                  />
                )}
                <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-[#888] font-mono">
                  <div>
                    {`total=${assetsMeta.total ?? 0} page=${assetsMeta.page ?? 1}/${assetsMeta.pageCount ?? 1} limit=${assetsMeta.limit ?? 50}`}
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <label className="flex items-center gap-2 text-[11px] text-[#AAA]">
                      <span>Rows</span>
                      <select
                        value={String(assetParams.limit ?? 50)}
                        onChange={(e) =>
                          setAssetParams((prev) => ({
                            ...prev,
                            limit: Number(e.target.value),
                            page: 1,
                          }))
                        }
                        className="rounded-lg border border-[#333] bg-[#111]/50 px-2 py-1 text-neutral-200"
                      >
                        <option value={10}>10</option>
                        <option value={25}>25</option>
                        <option value={50}>50</option>
                      </select>
                    </label>
                    <button
                      type="button"
                      disabled={(assetParams.page ?? 1) <= 1}
                      onClick={() => setAssetParams((prev) => ({ ...prev, page: Math.max(1, Number(prev.page ?? 1) - 1) }))}
                      className="rounded-lg bg-[#1C1C1C] px-3 py-1.5 text-white hover:bg-neutral-600 disabled:opacity-40"
                    >
                      Previous
                    </button>
                    <span className="rounded border border-[#333] bg-[#111]/40 px-2 py-1 text-neutral-300">{assetsMeta.page ?? 1}</span>
                    <button
                      type="button"
                      disabled={!assetsMeta.hasNextPage}
                      onClick={() => setAssetParams((prev) => ({ ...prev, page: Number(prev.page ?? 1) + 1 }))}
                      className="rounded-lg bg-[#1C1C1C] px-3 py-1.5 text-white hover:bg-neutral-600 disabled:opacity-40"
                    >
                      Next
                    </button>
                  </div>
                </div>
                {selectedAssetId && (
                  <div className="p-4 rounded-xl bg-[#111] border border-[#222] space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm text-red-400 font-mono font-bold">Asset Detail</h3>
                      <button
                        type="button"
                        onClick={() => { setSelectedAssetId(null); setAssetDetail(null); }}
                        className="px-2 py-1 rounded bg-[#1C1C1C] hover:bg-neutral-600 text-white text-xs"
                      >
                        Close
                      </button>
                    </div>
                    {assetDetailLoading ? (
                      <div className="text-[#888] text-sm font-mono">Loading asset detail...</div>
                    ) : assetDetail ? (
                      <>
                        <pre className="text-xs font-mono text-neutral-300 overflow-x-auto whitespace-pre-wrap break-words max-h-56 overflow-y-auto">
                          {JSON.stringify(assetDetail, null, 2)}
                        </pre>
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                          <div className="p-3 rounded border border-[#222] bg-[#111]/30 space-y-2">
                            <div className="text-xs text-[#AAA] font-mono font-bold flex items-center gap-1"><Tag size={12} /> Tags</div>
                            <input
                              type="text"
                              value={assetTagsText}
                              onChange={(e) => setAssetTagsText(e.target.value)}
                              placeholder="comma,separated,tags"
                              className="w-full px-3 py-2 rounded bg-[#111]/40 border border-[#333] text-white text-xs font-mono"
                            />
                            <button type="button" onClick={handleSaveAssetTags} disabled={submitting} className="px-3 py-2 rounded bg-neutral-700 hover:bg-neutral-600 text-white text-xs font-mono flex items-center gap-1">
                              <Save size={12} /> Save Tags
                            </button>
                          </div>
                          <div className="p-3 rounded border border-[#222] bg-[#111]/30 space-y-2">
                            <div className="text-xs text-[#AAA] font-mono font-bold flex items-center gap-1"><Sparkles size={12} /> AI Tag Suggestions</div>
                            <input
                              type="text"
                              value={aiDomain}
                              onChange={(e) => setAiDomain(e.target.value)}
                              placeholder="domain for suggestions"
                              className="w-full px-3 py-2 rounded bg-[#111]/40 border border-[#333] text-white text-xs font-mono"
                            />
                            <button type="button" onClick={handleGenerateAiTags} disabled={submitting || !aiDomain.trim()} className="px-3 py-2 rounded bg-neutral-700 hover:bg-neutral-600 text-white text-xs font-mono">
                              Generate Tags
                            </button>
                            {aiTags.length > 0 && (
                              <div className="text-xs text-neutral-300 font-mono">{aiTags.join(', ')}</div>
                            )}
                          </div>
                          <div className="p-3 rounded border border-[#222] bg-[#111]/30 space-y-2">
                            <div className="text-xs text-[#AAA] font-mono font-bold">Enabled Toggle</div>
                            <button
                              type="button"
                              onClick={handleToggleAssetEnabled}
                              disabled={submitting || assetEnabled === null}
                              className={`px-3 py-2 rounded text-xs font-mono text-white ${assetEnabled ? 'bg-neutral-700 hover:bg-neutral-600' : 'bg-[#1C1C1C] hover:bg-neutral-600'} disabled:opacity-50`}
                            >
                              {assetEnabled ? 'Disable Asset' : 'Enable Asset'}
                            </button>
                          </div>
                          <div className="p-3 rounded border border-[#222] bg-[#111]/30 space-y-2">
                            <div className="text-xs text-[#AAA] font-mono font-bold flex items-center gap-1"><FolderPlus size={12} /> Create Asset Group</div>
                            <input
                              type="text"
                              value={assetGroupName}
                              onChange={(e) => setAssetGroupName(e.target.value)}
                              placeholder="group name"
                              className="w-full px-3 py-2 rounded bg-[#111]/40 border border-[#333] text-white text-xs font-mono"
                            />
                            <button type="button" onClick={handleCreateAssetGroup} disabled={submitting || !assetGroupName.trim()} className="px-3 py-2 rounded bg-neutral-700 hover:bg-neutral-600 text-white text-xs font-mono">
                              Create Group
                            </button>
                          </div>
                        </div>
                      </>
                    ) : (
                      <div className="text-[#888] text-sm font-mono">Unable to load asset detail.</div>
                    )}
                  </div>
                )}
              </div>
            )}
            {activeTab === 'assets' && !selectedWorkspaceId && (
              <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                Select a workspace to list assets.
              </div>
            )}

            {activeTab === 'vulnerabilities' && selectedWorkspaceId && (
              <div className={`space-y-4 ${vulnListRefreshing ? 'opacity-70' : ''}`}>
                <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                  {(
                    [
                      ['critical', Flame, 'text-red-400'],
                      ['high', AlertTriangle, 'text-white'],
                      ['medium', Bug, 'text-white'],
                      ['low', Eye, 'text-sky-400'],
                      ['info', Info, 'text-neutral-200'],
                    ] as const
                  ).map(([sev, Icon, accent]) => (
                    <div key={sev} className="relative overflow-hidden rounded-xl border border-[#222]/90 bg-[#111827]/90 p-4">
                      <div className="flex items-start justify-between gap-2">
                        <span className={`text-[11px] font-bold uppercase tracking-wide ${accent}`}>{sev}</span>
                        <Icon size={18} className={`shrink-0 ${accent}`} />
                      </div>
                      <div className="mt-3 text-3xl font-bold tabular-nums text-white">{vulnStats[sev] ?? 0}</div>
                    </div>
                  ))}
                </div>
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="relative min-w-0 flex-1 lg:max-w-xl">
                    <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#888]" />
                    <input
                      type="text"
                      value={vulnParams.search ?? ''}
                      onChange={(e) => setVulnParams((prev) => ({ ...prev, search: e.target.value, page: 1 }))}
                      placeholder="Search"
                      className="w-full rounded-xl border border-[#333] bg-[#111]/50 py-2.5 pl-10 pr-3 text-sm text-white placeholder:text-[#888]"
                    />
                  </div>
                  <div className="flex flex-wrap items-center justify-end gap-2">
                    <div className="relative">
                      <select
                        value={vulnParams.status ?? 'open'}
                        onChange={(e) => setVulnParams((prev) => ({ ...prev, status: e.target.value, page: 1 }))}
                        className="appearance-none rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-2.5 pl-3 pr-9 text-sm text-white"
                      >
                        <option value="open">Open</option>
                        <option value="dismissed">Dismissed</option>
                        <option value="resolved">Resolved</option>
                        <option value="">All status</option>
                      </select>
                      <ChevronDown size={16} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-[#888]" />
                    </div>
                    <div className="relative inline-flex items-center gap-2 rounded-xl border border-dashed border-neutral-600 bg-[#111]/50 py-1 pl-2 pr-2">
                      <Filter size={14} className="shrink-0 text-[#888]" />
                      <select
                        value={vulnParams.severity ?? ''}
                        onChange={(e) => setVulnParams((prev) => ({ ...prev, severity: e.target.value, page: 1 }))}
                        className="appearance-none bg-transparent py-2 pr-6 text-sm text-white outline-none"
                      >
                        <option value="">Severity</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                      </select>
                      <ChevronDown size={14} className="pointer-events-none absolute right-1 top-1/2 -translate-y-1/2 text-[#888]" />
                    </div>
                    <div className="inline-flex items-center gap-2 rounded-xl border border-neutral-600 bg-[#111]/40 px-3 py-2">
                      <Calendar size={14} className="shrink-0 text-[#888]" />
                      <span className="text-xs text-[#888]">Date</span>
                      <input
                        type="date"
                        value={vulnParams.createdFrom ?? ''}
                        onChange={(e) => setVulnParams((prev) => ({ ...prev, createdFrom: e.target.value, page: 1 }))}
                        className="rounded border border-[#333] bg-[#111]/50 px-2 py-1 text-xs text-white"
                      />
                      <input
                        type="date"
                        value={vulnParams.createdTo ?? ''}
                        onChange={(e) => setVulnParams((prev) => ({ ...prev, createdTo: e.target.value, page: 1 }))}
                        className="rounded border border-[#333] bg-[#111]/50 px-2 py-1 text-xs text-white"
                      />
                    </div>
                  </div>
                </div>
                {vulnerabilities.length === 0 ? (
                  <div className="rounded-xl border border-[#222] bg-[#111] p-8 text-center text-sm text-[#888]">
                    No vulnerabilities found.
                  </div>
                ) : (
                  <div className="overflow-x-auto rounded-xl border border-[#222]">
                    <table className="w-full min-w-[960px] text-left text-xs">
                      <thead className="border-b border-[#222] bg-[#111]/40 text-[11px] font-semibold uppercase tracking-wide text-[#888]">
                        <tr>
                          <th className="p-3 pl-4">
                            <button
                              type="button"
                              className="inline-flex items-center gap-1 text-[#AAA] hover:text-white"
                              onClick={() =>
                                setVulnParams((p) => ({
                                  ...p,
                                  sortBy: 'severity',
                                  sortOrder: p.sortOrder === 'DESC' ? 'ASC' : 'DESC',
                                  page: 1,
                                }))
                              }
                            >
                              Severity
                              <ArrowUpDown size={12} />
                            </button>
                          </th>
                          <th className="p-3">Details</th>
                          <th className="p-3">Affected URL</th>
                          <th className="p-3">CVSS</th>
                          <th className="p-3">Tags</th>
                          <th className="p-3">Created</th>
                          <th className="p-3">Scanned by</th>
                          <th className="p-3">Status</th>
                          <th className="p-3 pr-4 text-right"> </th>
                        </tr>
                      </thead>
                      <tbody className="text-neutral-200">
                        {vulnerabilities.map((v) => {
                          const row = v as Record<string, unknown>;
                          const id = String(v.id);
                          const name = String(row.name ?? row.title ?? '—');
                          const sev = String(v.severity ?? 'unknown');
                          const url = String(row.affectedUrl ?? '');
                          const cv = row.cvssScore;
                          const cvssLabel = cv != null && String(cv) !== '' ? String(cv) : 'Not matched';
                          const tags = Array.isArray(row.tags) ? (row.tags as string[]) : [];
                          const tool = row.tool as Record<string, unknown> | undefined;
                          const tname = tool ? String(tool.name ?? '') : '';
                          const tlogo = tool && typeof tool.logoUrl === 'string' ? tool.logoUrl : '';
                          const logoSrc = resolveAssetMediaUrl(tlogo || null);
                          const created = row.createdAt ? new Date(String(row.createdAt)).toLocaleDateString() : '—';
                          const st = String(v.status ?? 'open');
                          return (
                            <tr key={id} className="border-t border-[#222]/80 hover:bg-white/[0.03]">
                              <td className="p-3 pl-4 align-middle">
                                <span
                                  className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-semibold capitalize ${vulnSeverityBadgeClass(sev)}`}
                                >
                                  {sev}
                                </span>
                              </td>
                              <td className="max-w-[220px] p-3 align-middle">
                                <div className="flex items-center gap-1.5">
                                  <span className="font-semibold text-white">{name}</span>
                                  <button
                                    type="button"
                                    onClick={() => handleOpenVulnerabilityDetail(id)}
                                    className="shrink-0 text-[#888] hover:text-red-400"
                                  >
                                    <Info size={14} />
                                  </button>
                                </div>
                              </td>
                              <td className="max-w-[200px] p-3 align-middle">
                                {url ? (
                                  <a
                                    href={url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="inline-flex items-center gap-1 break-all text-sky-400 hover:text-sky-300"
                                  >
                                    {url}
                                    <ExternalLink size={12} className="shrink-0" />
                                  </a>
                                ) : (
                                  '—'
                                )}
                              </td>
                              <td className="p-3 align-middle font-mono text-[#AAA]">{cvssLabel}</td>
                              <td className="p-3 align-middle">
                                <div className="flex flex-wrap gap-1">
                                  {tags.slice(0, 3).map((t) => (
                                    <span
                                      key={t}
                                      className="rounded-md border border-[#333] bg-[#111]/40 px-2 py-0.5 text-[10px] text-neutral-300"
                                    >
                                      {t}
                                    </span>
                                  ))}
                                  {tags.length > 3 ? (
                                    <span className="rounded-md border border-[#333] px-2 py-0.5 text-[10px] text-[#888]">
                                      +{tags.length - 3}
                                    </span>
                                  ) : null}
                                </div>
                              </td>
                              <td className="p-3 align-middle text-neutral-300">{created}</td>
                              <td className="p-3 align-middle">
                                <div className="flex items-center gap-2">
                                  {logoSrc ? (
                                    <img src={logoSrc} alt="" className="h-8 w-8 rounded-lg border border-[#333] bg-white/5 object-contain p-0.5" />
                                  ) : (
                                    <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#333] bg-[#111] text-[10px] text-neutral-600">
                                      ?
                                    </div>
                                  )}
                                  <span className="text-neutral-200">{tname || '—'}</span>
                                </div>
                              </td>
                              <td className="p-3 align-middle">
                                <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/50 bg-emerald-950/25 px-2.5 py-1 text-[10px] font-medium text-emerald-300">
                                  <CheckCircle2 size={12} />
                                  {st}
                                </span>
                              </td>
                              <td className="p-3 pr-4 text-right align-middle">
                                <button
                                  type="button"
                                  onClick={() => handleOpenVulnerabilityDetail(id)}
                                  className="rounded-lg border border-neutral-600 bg-[#151515] px-3 py-1.5 text-xs text-white hover:bg-[#1C1C1C]"
                                >
                                  Details
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-[#888] font-mono">
                  <span>
                    {`total=${vulnMeta.total ?? 0} page=${vulnMeta.page ?? 1}/${vulnMeta.pageCount ?? 1}`}
                  </span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={(vulnParams.page ?? 1) <= 1}
                      onClick={() => setVulnParams((prev) => ({ ...prev, page: Math.max(1, Number(prev.page ?? 1) - 1) }))}
                      className="rounded bg-[#1C1C1C] px-2 py-1 text-white disabled:opacity-40"
                    >
                      Prev
                    </button>
                    <button
                      type="button"
                      disabled={!vulnMeta.hasNextPage}
                      onClick={() => setVulnParams((prev) => ({ ...prev, page: Number(prev.page ?? 1) + 1 }))}
                      className="rounded bg-[#1C1C1C] px-2 py-1 text-white disabled:opacity-40"
                    >
                      Next
                    </button>
                  </div>
                </div>
              </div>
            )}
            {activeTab === 'vulnerabilities' && !selectedWorkspaceId && (
              <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                Select a workspace to list vulnerabilities.
              </div>
            )}

            {activeTab === 'workers' && selectedWorkspaceId && (
              <div className="space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <h3 className="text-xl font-bold text-white">Workers</h3>
                  {workersRefreshing ? (
                    <span className="inline-flex items-center gap-2 text-xs text-[#888]">
                      <Loader2 size={14} className="animate-spin" />
                      Loading…
                    </span>
                  ) : null}
                </div>
                {workers.length === 0 && !workersRefreshing ? (
                  <div className="rounded-xl border border-[#222] bg-[#111] p-8 text-center text-sm text-[#888]">
                    No workers returned. If this persists, ensure <code className="text-white">GET /asm/workers</code> is implemented on
                    the ANTI.AI backend proxy.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                    {workers.map((w) => {
                      const wr = w as Record<string, unknown>;
                      const id = String(w.id ?? '');
                      const shortId = id.slice(0, 8);
                      const tools = Array.isArray(w.tools) ? (w.tools as Record<string, unknown>[]) : [];
                      const jobs = Number(w.currentJobsCount ?? 0);
                      const online = workerSeenOnline(typeof w.lastSeenAt === 'string' ? w.lastSeenAt : undefined);
                      const scope = String(w.scope ?? '');
                      const scopeLabel = scope === 'cloud' ? 'Global' : scope || '—';
                      return (
                        <div
                          key={id || Math.random()}
                          className="space-y-4 rounded-2xl border border-[#222] bg-[#111827]/90 p-5"
                        >
                          <div className="flex items-center justify-between gap-2 text-xs">
                            <span className="rounded-md border border-[#333] bg-[#111]/40 px-2 py-1 text-[#AAA]">Scope</span>
                            <span className="rounded-full border border-neutral-600 bg-[#111]/30 px-3 py-1 font-medium text-white">{scopeLabel}</span>
                          </div>
                          <div className="flex items-start justify-between gap-2">
                            <span className="rounded-md border border-[#333] bg-[#111]/40 px-2 py-1 text-xs text-[#AAA]">Tools</span>
                            <div className="flex flex-wrap justify-end gap-1.5">
                              {tools.map((t, ti) => {
                                const nm = String(t.name ?? '?');
                                const letter = nm.charAt(0).toUpperCase();
                                const logo = typeof t.logoUrl === 'string' ? t.logoUrl : '';
                                const src = resolveAssetMediaUrl(logo || null);
                                return src ? (
                                  <img
                                    key={`${id}-t-${ti}`}
                                    src={src}
                                    alt=""
                                    title={nm}
                                    className="h-8 w-8 rounded-full border border-[#333] bg-[#111] object-contain p-0.5"
                                  />
                                ) : (
                                  <span
                                    key={`${id}-t-${ti}`}
                                    title={nm}
                                    className="flex h-8 w-8 items-center justify-center rounded-full border border-[#333] bg-[#111] text-xs font-bold text-white"
                                  >
                                    {letter}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                          <div className="flex items-center justify-between gap-2 border-t border-[#222] pt-3">
                            <span className="font-mono text-sm text-neutral-300">{shortId}</span>
                            {jobs > 0 ? (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-600/25 px-3 py-1.5 text-xs font-semibold text-emerald-300">
                                <Loader2 size={12} className="animate-spin" />
                                Running
                              </span>
                            ) : (
                              <span className="rounded-full border border-[#333] bg-[#111]/40 px-3 py-1.5 text-xs text-[#888]">Idle</span>
                            )}
                          </div>
                          <div className="flex items-center justify-between text-xs">
                            <span className="rounded-md border border-[#333] bg-[#111]/40 px-2 py-1 text-[#AAA]">Status</span>
                            <span className={online ? 'inline-flex items-center gap-1.5 text-emerald-400' : 'text-[#888]'}>
                              <span className={`inline-block h-2 w-2 rounded-full ${online ? 'bg-emerald-400' : 'bg-neutral-600'}`} />
                              {online ? 'Online' : 'Offline'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between text-xs">
                            <span className="rounded-md border border-[#333] bg-[#111]/40 px-2 py-1 text-[#AAA]">Created at</span>
                            <span className="text-[#888]">{formatRelativeAgo(typeof w.createdAt === 'string' ? w.createdAt : undefined)}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
                <div className="font-mono text-xs text-[#888]">
                  total={workersMeta.total ?? 0} page={workersMeta.page ?? 1}/{workersMeta.pageCount ?? 1}
                </div>
              </div>
            )}
            {activeTab === 'workers' && !selectedWorkspaceId && (
              <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                Select a workspace to view workers.
              </div>
            )}

            {activeTab === 'workspaces' && (
              <div className="space-y-4">
                <form
                  onSubmit={handleCreateWorkspace}
                  className="p-4 rounded-xl bg-[#111] border border-[#222] flex flex-wrap gap-2"
                >
                  <input
                    type="text"
                    value={workspaceName}
                    onChange={(e) => setWorkspaceName(e.target.value)}
                    placeholder="Workspace name"
                    className="flex-1 min-w-[200px] px-3 py-2 rounded-lg bg-[#111]/40 border border-[#333] text-white text-sm font-mono focus:border-neutral-500/50 focus:outline-none"
                  />
                  <input
                    type="text"
                    value={workspaceDescription}
                    onChange={(e) => setWorkspaceDescription(e.target.value)}
                    placeholder="Description (optional)"
                    className="flex-1 min-w-[260px] px-3 py-2 rounded-lg bg-[#111]/40 border border-[#333] text-white text-sm font-mono focus:border-neutral-500/50 focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={submitting || !workspaceName.trim()}
                    className="px-4 py-2 rounded-lg bg-neutral-600 hover:bg-neutral-500 text-white text-sm font-mono font-bold disabled:opacity-50"
                  >
                    Create Workspace
                  </button>
                </form>
                <div className="space-y-2">
                  {workspaces.length === 0 ? (
                    <div className="p-8 rounded-xl bg-[#111] border border-[#222] text-center text-[#888] font-mono text-sm">
                      No workspaces found.
                    </div>
                  ) : (
                    workspaces.map((w) => (
                      <div key={w.id} className="p-3 rounded-lg bg-[#111] border border-[#222]">
                        <div className="text-white font-mono font-bold">{w.name}</div>
                        <div className="text-xs text-[#AAA] font-mono">
                          {w.description || 'No description'} | ID: {w.id}
                          {w.targetCount != null && ` | Targets: ${w.targetCount}`}
                          {w.memberCount != null && ` | Members: ${w.memberCount}`}
                          {w.role != null && ` | ${w.role}`}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {activeTab === 'connectors' && (
              <IntegrationsView />
            )}

          </>
        )}
        <VulnerabilityDetailModal
          open={Boolean(selectedVulnId)}
          loading={vulnDetailLoading}
          vuln={vulnDetail ? (vulnDetail as Record<string, unknown>) : null}
          onClose={() => {
            setSelectedVulnId(null);
            setVulnDetail(null);
          }}
          resolveMediaUrl={resolveAssetMediaUrl}
          onDismiss={selectedWorkspaceId ? handleVulnModalDismiss : undefined}
          dismissing={vulnModalDismissLoading}
        />
        <TargetRiskModal
          open={riskModalOpen}
          target={riskModalTarget}
          assessment={riskModalAssessment}
          loading={riskModalLoading}
          onClose={() => {
            setRiskModalOpen(false);
            setRiskModalTarget(null);
            setRiskModalAssessment(null);
          }}
          onRescanSuccess={() => {
            if (selectedWorkspaceId) {
              void loadTargets(selectedWorkspaceId);
            }
          }}
        />
        {screenshotModalUrl && (
          <div
            className="fixed inset-0 z-[80] bg-[#111]/80 flex items-center justify-center p-4"
            onClick={() => setScreenshotModalUrl(null)}
          >
            <div
              className="relative max-w-[95vw] max-h-[95vh] rounded-lg border border-[#333] bg-[#111]/40 p-2"
              onClick={(e) => e.stopPropagation()}
            >
              <button
                type="button"
                onClick={() => setScreenshotModalUrl(null)}
                className="absolute -top-3 -right-3 px-2 py-1 rounded bg-[#151515] hover:bg-[#1C1C1C] text-white text-xs font-mono border border-neutral-600"
              >
                Close
              </button>
              <img
                src={resolveAssetMediaUrl(screenshotModalUrl) ?? ''}
                alt="Asset screenshot"
                className="block max-w-[92vw] max-h-[90vh] object-contain rounded"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

