
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
    AnalyzedHost, 
    ThreatNewsItem, 
    CveFeedItem, 
    MalpediaActor, 
    ExploitEntry, 
    CveEntry, 
    FeodoTrackerEntry, 
    UrlHausEntry, 
    MalwareBazaarEntry, 
    SslBlEntry, 
    Ja3FingerprintEntry, 
    ThreatFoxEntry,
    RansomWatchPost,
    RansomWatchGroup
} from '../../types';
import { AttackMapView, AttackTarget } from './AttackMapView';
import { LiveThreatFeed } from '../widgets/LiveThreatFeed';
import { isPublicDemo } from '../../src/utils/demoMode';
import { ShieldAlert, Activity, Globe, Target, ArrowUp, ArrowDown, Zap, Skull, AlertTriangle, Siren, Bug, Database, Rss, Lock, Flame, Server, MonitorPlay, Wifi, Users, Layout, BarChart3, AlertCircle, Clock, Network, Share2, Layers } from 'lucide-react';

interface BigScreenViewProps {
    results: AnalyzedHost[];
    newsItems: ThreatNewsItem[];
    cveItems: CveFeedItem[];
    cveData: CveEntry[];
    actors: MalpediaActor[];
    exploitData?: ExploitEntry[];
    urlHausItems?: UrlHausEntry[];
    feodoItems?: FeodoTrackerEntry[];
    malwareBazaarItems?: MalwareBazaarEntry[];
    threatFoxItems?: ThreatFoxEntry[];
    sslBlItems?: SslBlEntry[];
    ja3Items?: Ja3FingerprintEntry[];
    ransomwarePosts?: RansomWatchPost[];
    ransomwareGroups?: RansomWatchGroup[];
    onExit?: () => void;
    onRefresh?: () => void;
    productName?: string;
    logoUrl?: string;
}

// --- HELPER FUNCTIONS ---

const getTagStyle = (category: string) => {
    switch(category?.toUpperCase()) {
        case 'RANSOMWARE': return 'bg-red-950/60 text-red-400 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]';
        case 'VULNERABILITY': return 'bg-neutral-900/60 text-neutral-300 border-neutral-500/50';
        case 'APT': return 'bg-neutral-900/60 text-red-400 border-neutral-500/50 shadow-[0_0_10px_rgba(255,255,255,0.1)]';
        case 'PHISHING': return 'bg-neutral-900/60 text-red-400 border-neutral-500/50';
        case 'BREACH': return 'bg-neutral-900/60 text-white border-neutral-500/50';
        case 'MALWARE': return 'bg-neutral-950/60 text-white border-neutral-500/50';
        case 'CYBERCRIME': return 'bg-neutral-950/60 text-red-400 border-neutral-500/50';
        default: return 'bg-[#151515] text-[#AAA] border-neutral-600';
    }
};

const getCriticality = (item: ThreatNewsItem) => {
    const text = (item.title + item.description).toLowerCase();
    if (text.includes('critical') || text.includes('0-day') || text.includes('zero-day') || text.includes('ransomware') || text.includes('active exploitation')) {
        return 'CRITICAL';
    }
    if (text.includes('high') || text.includes('cve-') || text.includes('exploit')) {
        return 'HIGH';
    }
    return 'INFO';
};

// --- TILE COMPONENTS ---

const NewsTicker = ({ items }: { items: ThreatNewsItem[] }) => {
    const displayItems = useMemo(() => {
        if (items.length === 0) return [];
        const base = items.slice(0, 20);
        return [...base, ...base, ...base, ...base]; 
    }, [items]);

    if (items.length === 0) return null;

    return (
        <div className="at-soc-news-ticker">
            <div className="absolute left-0 bg-[#111] px-4 z-20 h-full flex items-center border-r border-red-500/30 shadow-[5px_0_15px_rgba(0,0,0,0.8)]">
                <span className="text-[10px] font-bold text-red-500 uppercase tracking-widest flex items-center gap-2 animate-pulse">
                    <Rss size={12} /> CYBER INTEL
                </span>
            </div>
            <div className="flex animate-marquee whitespace-nowrap hover:[animation-play-state:paused] items-center pl-4" style={{ animationDuration: '160s' }}>
                {displayItems.map((item, i) => (
                    <div key={`${item.link}-${i}`} className="flex items-center mx-8 group cursor-default">
                        <span className="text-[10px] text-[#888] font-mono mr-2 group-hover:text-red-500 transition-colors">
                            [{new Date(item.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}]
                        </span>
                        <span className="text-[11px] text-neutral-300 font-bold uppercase tracking-wide group-hover:text-white transition-colors">
                            {item.title}
                        </span>
                        <span className="ml-8 text-red-900/40 text-[10px] tracking-widest font-mono">///</span>
                    </div>
                ))}
            </div>
            <div className="absolute right-0 top-0 bottom-0 w-32 bg-gradient-to-l from-[#020617] to-transparent z-10 pointer-events-none"></div>
        </div>
    );
};

const StatTile = ({
    label,
    value,
    trend,
    trendVal,
    color = 'text-[#e4e4e7]',
    icon: Icon,
}: any) => (
    <div className="at-soc-stat-tile">
        <div className="at-soc-stat-top">
            <span>{label}</span>

            <span className={`at-soc-stat-icon ${color}`}>
                <Icon size={17} />
            </span>
        </div>

        <div className="at-soc-stat-value">
            {value}
        </div>

        <div className="at-soc-stat-trend">
            <span
                className={
                    trend === 'up'
                        ? 'positive'
                        : 'negative'
                }
            >
                {trend === 'up'
                    ? <ArrowUp size={9} />
                    : <ArrowDown size={9} />}

                {trendVal}%
            </span>

            <span>vs previous hour</span>
        </div>
    </div>
);

const IocStatTile = ({ 
    counts, 
    stats 
}: { 
    counts: { label: string, value: number, tone: string }[],
    stats: { 
        types: {label: string, count: number}[], 
        malware: {label: string, count: number}[], 
        asns: {label: string, count: number}[], 
        reasons: {label: string, count: number}[] 
    } 
}) => {
    const total = counts.reduce((acc, c) => acc + c.value, 0);
    const [tab, setTab] = useState<'OVERVIEW' | 'MALWARE' | 'ASNS'>('OVERVIEW');

    useEffect(() => {
        const interval = setInterval(() => {
            setTab(prev => {
                if (prev === 'OVERVIEW') return 'MALWARE';
                if (prev === 'MALWARE') return 'ASNS';
                return 'OVERVIEW';
            });
        }, 8000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="h-full flex flex-col p-3 bg-transparent relative overflow-hidden">
             <div className="flex justify-between items-start mb-4 border-b border-[#222] pb-2">
                <div>
                    <div className="text-[10px] font-bold text-[#888] uppercase tracking-widest mb-1">Total Indicators</div>
                    <div className="text-2xl font-semibold text-[#d7d9de]">{total.toLocaleString()}</div>
                </div>
                <div className="p-2 rounded-lg bg-[#171a20] border border-[#30343d]">
                    <Database size={17} className="text-[#9da3ac]"/>
                </div>
             </div>

             <div className="flex-1 overflow-hidden relative">
                 <div className={`absolute inset-0 flex flex-col transition-opacity duration-500 ${tab === 'OVERVIEW' ? 'opacity-100 z-10' : 'opacity-0 z-0'}`}>
                    <div className="text-[10px] text-[#888] font-bold mb-2 uppercase flex items-center gap-2"><Globe size={10}/> Feed Sources</div>
                    <div className="grid grid-cols-2 gap-2 overflow-y-auto custom-scrollbar pb-2">
                        {counts.map((c, i) => (
                            <div key={i} className="bg-[#111]/40 border border-[#222] p-2 rounded flex flex-col justify-center">
                                <div className="text-[9px] text-[#888] uppercase font-bold truncate" title={c.label}>{c.label}</div>
                                <div className={`text-sm font-mono font-bold ${
                                    c.tone === 'danger' ? 'text-[#e56d72]' : 
                                    c.tone === 'warning' ? 'text-[#d49b45]' : 
                                    c.tone === 'success' ? 'text-[#7ebc8a]' : 
                                    'text-[#e4e4e7]'
                                }`}>{c.value.toLocaleString()}</div>
                            </div>
                        ))}
                    </div>
                 </div>

                 <div className={`absolute inset-0 flex flex-col transition-opacity duration-500 ${tab === 'MALWARE' ? 'opacity-100 z-10' : 'opacity-0 z-0'}`}>
                    <div className="text-[10px] text-[#888] font-bold mb-2 uppercase flex items-center gap-2"><Bug size={10}/> Active Campaigns</div>
                    <div className="space-y-1 overflow-y-auto custom-scrollbar pb-2">
                        {stats.malware.slice(0, 6).map((m, i) => (
                            <div key={i} className="flex justify-between items-center p-1.5 bg-red-900/10 border border-red-500/20 rounded">
                                <span className="text-[10px] text-red-300 font-mono truncate w-2/3">{m.label}</span>
                                <span className="text-[10px] font-bold text-white">{m.count}</span>
                            </div>
                        ))}
                    </div>
                 </div>

                 <div className={`absolute inset-0 flex flex-col transition-opacity duration-500 ${tab === 'ASNS' ? 'opacity-100 z-10' : 'opacity-0 z-0'}`}>
                    <div className="text-[10px] text-[#888] font-bold mb-2 uppercase flex items-center gap-2"><Server size={10}/> Malicious Infrastructure</div>
                    <div className="space-y-1 overflow-y-auto custom-scrollbar pb-2">
                        {stats.asns.slice(0, 6).map((a, i) => (
                            <div key={i} className="flex justify-between items-center p-1.5 bg-neutral-900/10 border border-neutral-500/20 rounded">
                                <span className="text-[10px] text-neutral-300 font-mono truncate w-2/3">{a.label}</span>
                                <span className="text-[10px] font-bold text-white">{a.count}</span>
                            </div>
                        ))}
                    </div>
                 </div>
             </div>

             <div className="flex justify-center gap-1 mt-2">
                 <div className={`w-1.5 h-1.5 rounded-full transition-colors ${tab === 'OVERVIEW' ? 'bg-red-500' : 'bg-[#1C1C1C]'}`}></div>
                 <div className={`w-1.5 h-1.5 rounded-full transition-colors ${tab === 'MALWARE' ? 'bg-red-500' : 'bg-[#1C1C1C]'}`}></div>
                 <div className={`w-1.5 h-1.5 rounded-full transition-colors ${tab === 'ASNS' ? 'bg-red-500' : 'bg-[#1C1C1C]'}`}></div>
             </div>
        </div>
    );
}

const VulnAnalyticsTile = ({ 
    exploitCount, 
    totalCves, 
    cisaCount, 
    zdiCount, 
    criticalCve 
}: { 
    exploitCount: number, 
    totalCves: number, 
    cisaCount: number, 
    zdiCount: number, 
    criticalCve?: { id: string, description: string } 
}) => (
    <div className="h-full flex flex-col">
        <div className="p-3 border-b border-[#22262d] bg-[#0f1217] flex items-center justify-between flex-shrink-0">
            <h3 className="font-bold text-white flex items-center gap-2 font-cyber tracking-wider text-xs">
                <Target size={14} className="text-[#9da3ac]"/> VULNERABILITY ANALYTICS
            </h3>
        </div>
        <div className="flex-1 p-4 flex flex-col gap-3 overflow-hidden">
            <div className="grid grid-cols-2 gap-3">
                 <div className="bg-red-950/35 rounded-lg p-2 border border-red-500/30 flex flex-col justify-between relative overflow-hidden group">
                    <div className="flex justify-between items-start z-10">
                        <div className="text-[9px] text-red-300 font-bold uppercase">CISA KEV</div>
                        <ShieldAlert size={12} className="text-red-400"/>
                    </div>
                    <div className="text-2xl font-bold text-white z-10">{cisaCount}</div>
                    <div className="absolute right-0 bottom-0 opacity-10 group-hover:opacity-20 transition-opacity">
                        <ShieldAlert size={48} className="text-red-500"/>
                    </div>
                </div>
                
                <div className="bg-neutral-950/25 rounded-lg p-2 border border-neutral-500/30 flex flex-col justify-between relative overflow-hidden group">
                    <div className="flex justify-between items-start z-10">
                        <div className="text-[9px] text-neutral-300 font-bold uppercase">ZDI Upcoming</div>
                        <Bug size={12} className="text-neutral-400"/>
                    </div>
                    <div className="text-2xl font-bold text-white z-10">{zdiCount}</div>
                    <div className="absolute right-0 bottom-0 opacity-10 group-hover:opacity-20 transition-opacity">
                        <Bug size={48} className="text-neutral-500"/>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
                <div className="bg-[#111] rounded-lg p-2 border border-[#222] flex flex-col justify-between">
                    <div className="flex justify-between items-start">
                        <div className="text-[9px] text-[#888] font-bold uppercase">Known Exploits</div>
                        <Zap size={12} className="text-white"/>
                    </div>
                    <div className="text-xl font-mono text-white">{exploitCount}</div>
                </div>
                <div className="bg-[#111] rounded-lg p-2 border border-[#222] flex flex-col justify-between">
                    <div className="flex justify-between items-start">
                        <div className="text-[9px] text-[#888] font-bold uppercase">Total CVEs</div>
                        <Database size={12} className="text-red-500"/>
                    </div>
                    <div className="text-xl font-mono text-white">{totalCves}</div>
                </div>
            </div>

            {criticalCve && (
                <div className="bg-red-900/10 border border-red-500/20 p-2 rounded flex-1 flex flex-col justify-center">
                    <div className="text-[9px] text-red-400 font-bold mb-1 flex items-center gap-1">
                        <Flame size={10}/> LATEST CRITICAL
                    </div>
                    <div className="text-xs text-white font-bold mb-1">{criticalCve.id}</div>
                    <div className="text-[9px] text-[#AAA] line-clamp-2 leading-tight">
                        {criticalCve.description}
                    </div>
                </div>
            )}
        </div>
    </div>
);

type SocTab = 'OPS' | 'LIVE' | 'VULN' | 'IOC' | 'NEWS';

export const BigScreenView: React.FC<BigScreenViewProps> = ({
    results, newsItems, cveItems, cveData, actors, exploitData = [],
    urlHausItems = [], feodoItems = [], malwareBazaarItems = [],
    threatFoxItems = [], sslBlItems = [], ja3Items = [],
    ransomwarePosts = [], ransomwareGroups = [],
    onExit, onRefresh, productName = 'ANTI.AI', logoUrl
}) => {
    const [showGlobalThreats, setShowGlobalThreats] = useState(true);
    const [activeTab, setActiveTab] = useState<SocTab>('OPS');
    const containerRef = useRef<HTMLDivElement>(null);

    const criticalHosts = results.filter(h => h.riskLevel === 'CRITICAL').length;
    const highHosts = results.filter(h => h.riskLevel === 'HIGH').length;
    
    const iocCounts = [
        { label: 'URLHaus', value: urlHausItems.length, tone: 'neutral', color: 'text-neutral-400' },
        { label: 'Feodo C2', value: feodoItems.length, tone: 'danger', color: 'text-red-500' },
        { label: 'ThreatFox', value: threatFoxItems.length, tone: 'warning', color: 'text-amber-500' },
        { label: 'Bazaar', value: malwareBazaarItems.length, tone: 'neutral', color: 'text-neutral-400' },
        { label: 'SSLBL', value: sslBlItems.length, tone: 'neutral', color: 'text-neutral-400' },
        { label: 'JA3', value: ja3Items.length, tone: 'warning', color: 'text-amber-500' }
    ];

    const iocStats = useMemo(() => {
        const malware: Record<string, number> = {};
        const asns: Record<string, number> = {};
        const countries: Record<string, number> = {};
        const types: Record<string, number> = { 'IP': 0, 'URL': 0, 'HASH': 0, 'CERT': 0 };
        
        feodoItems.forEach(i => {
            if(i.malware) malware[i.malware] = (malware[i.malware] || 0) + 1;
            if(i.as_name) asns[i.as_name] = (asns[i.as_name] || 0) + 1;
            if(i.country) countries[i.country] = (countries[i.country] || 0) + 1;
            types['IP']++;
        });
        urlHausItems.forEach(i => {
            if(i.threat) malware[i.threat] = (malware[i.threat] || 0) + 1;
            types['URL']++;
        });
        threatFoxItems.forEach(i => {
            if(i.malware_printable) malware[i.malware_printable] = (malware[i.malware_printable] || 0) + 1;
            if(i.ioc_type.includes('ip')) types['IP']++;
            else if(i.ioc_type.includes('url')) types['URL']++;
            else types['HASH']++;
        });
        malwareBazaarItems.forEach(() => types['HASH']++);
        sslBlItems.forEach(() => types['CERT']++);
        ja3Items.forEach(() => types['CERT']++);

        const sortMap = (map: Record<string, number>) => Object.entries(map).map(([label, count]) => ({label, count})).sort((a,b)=>b.count-a.count);

        return {
            types: sortMap(types), 
            malware: sortMap(malware),
            asns: sortMap(asns),
            countries: sortMap(countries),
            reasons: []
        }
    }, [feodoItems, urlHausItems, threatFoxItems, malwareBazaarItems, sslBlItems, ja3Items]);

    // Aggregate Latest IOCs for Ticker
    const latestIocs = useMemo(() => {
        const items: any[] = [];
        feodoItems.slice(0, 10).forEach(i => items.push({ src: 'FEODO', val: `${i.ip_address}:${i.port}`, type: 'C2', threat: i.malware }));
        urlHausItems.slice(0, 10).forEach(i => items.push({ src: 'URLHAUS', val: i.url, type: 'URL', threat: i.threat }));
        threatFoxItems.slice(0, 10).forEach(i => items.push({ src: 'THREATFOX', val: i.ioc_value, type: i.ioc_type, threat: i.malware_printable }));
        return items;
    }, [feodoItems, urlHausItems, threatFoxItems]);

    const globalThreats = useMemo(() => {
        // Strict Backend Isolation: Only inject synthetic global external targets in public demo mode
        if (!showGlobalThreats || !isPublicDemo()) return [];
        const targets: AttackTarget[] = [];
        feodoItems.forEach(i => {
            if (i.country) {
                targets.push({
                    type: 'GLOBAL',
                    country: i.country,
                    label: i.malware || 'C2 Botnet',
                    subLabel: i.ip_address,
                    risk: 'HIGH'
                });
            }
        });
        ransomwarePosts.forEach(p => {
            if (p.country) {
                targets.push({
                    type: 'RANSOMWARE',
                    country: p.country,
                    label: p.group_name,
                    subLabel: p.post_title,
                    risk: 'CRITICAL'
                });
            }
        });
        return targets;
    }, [feodoItems, ransomwarePosts, showGlobalThreats]);

    const vulnStats = useMemo(() => {
        const total = cveData.length;
        const critical = cveData.filter(c => c.severity === 'CRITICAL').length;
        const high = cveData.filter(c => c.severity === 'HIGH').length;
        const medium = cveData.filter(c => c.severity === 'MEDIUM').length;
        const low = cveData.filter(c => c.severity === 'LOW').length;
        const kev = cveData.filter(c => c.isKev).length;
        const avgScore = total > 0 ? (cveData.reduce((acc, c) => acc + c.cvssScore, 0) / total).toFixed(1) : '0.0';
        
        const cwes: Record<string, number> = {};
        cveData.forEach(c => {
            (c.weaknesses || []).forEach(w => {
                cwes[w] = (cwes[w] || 0) + 1;
            });
        });
        const topCwes = Object.entries(cwes).sort((a,b) => b[1]-a[1]).slice(0, 8).map(([label, count]) => ({label, count}));

        // Vector Stats for Donut
        const vectors: Record<string, number> = { 'NETWORK': 0, 'ADJACENT': 0, 'LOCAL': 0, 'PHYSICAL': 0 };
        cveData.forEach(c => {
            const av = c.vector?.AV?.toUpperCase();
            if (av && vectors[av] !== undefined) vectors[av]++;
            else if (av) vectors['NETWORK']++; 
        });

        // KEV List
        const kevList = cveData.filter(c => c.isKev).slice(0, 20);

        return { total, critical, high, medium, low, kev, avgScore, topCwes, vectors, kevList };
    }, [cveData]);

    const topVendors = useMemo(() => {
        const counts: Record<string, number> = {};
        cveData.forEach(c => {
            if (c.vendor && c.vendor !== 'Unknown') counts[c.vendor] = (counts[c.vendor] || 0) + 1;
        });
        return Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0, 10).map(([label, count]) => ({label, count}));
    }, [cveData]);

    const activeRansomGroups = ransomwareGroups.length;
    const ransomVictims = ransomwarePosts.length;

    const scrollingNews = useMemo(() => {
        return newsItems;
    }, [newsItems]);

    const [time, setTime] = useState(new Date());
    useEffect(() => {
        const t = setInterval(() => setTime(new Date()), 1000);
        return () => clearInterval(t);
    }, []);

    useEffect(() => {
        if(onRefresh) {
            // Set interval to 30 minutes (30 * 60 * 1000)
            const t = setInterval(onRefresh, 30 * 60 * 1000);
            return () => clearInterval(t);
        }
    }, [onRefresh]);

    return (
        <div ref={containerRef} className="at-soc-wall flex-1 min-w-0 min-h-0 w-full h-full bg-[#06080b] text-white overflow-hidden flex flex-col font-sans select-none">
            <div className="at-soc-header">
                <div className="flex items-center gap-3">
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.7)] animate-pulse" />
                    <div>
                        <h2 className="text-sm font-semibold tracking-wider uppercase text-neutral-200">
                            SOC Operations Wall
                        </h2>
                        <div className="text-[11px] text-neutral-500 font-mono hidden sm:block">
                            Live Threat Telemetry & Situational Awareness
                        </div>
                    </div>
                </div>

                <div className="flex items-center bg-[#111] rounded-lg p-1 border border-[#222] gap-1">
                    {[
                        { id: 'OPS', icon: MonitorPlay, label: 'OPS' },
                        { id: 'LIVE', icon: Zap, label: 'LIVE' },
                        { id: 'VULN', icon: Target, label: 'VULN' },
                        { id: 'IOC', icon: Database, label: 'IOC' },
                        { id: 'NEWS', icon: Globe, label: 'INTEL' }
                    ].map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id as SocTab)}
                            className={`px-3 py-1.5 rounded flex items-center gap-2 text-xs font-bold transition-all ${activeTab === tab.id ? 'bg-[#d62828] text-white shadow-[0_6px_18px_rgba(214,40,40,.20)]' : 'text-[#777e87] hover:text-[#e5e7eb] hover:bg-[#171a20]'}`}
                        >
                            <tab.icon size={14}/> {tab.label}
                        </button>
                    ))}
                </div>

                <div className="flex items-center gap-5">
                    <div className="text-right hidden md:block">
                        <div className="text-[10px] text-[#888] font-bold uppercase tracking-widest">System Status</div>
                        <div className="text-white font-mono text-xs flex items-center justify-end gap-1.5">
                            <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse shadow-[0_0_5px_#10b981]"></span> OPERATIONAL
                        </div>
                    </div>
                    <div className="text-right">
                        <div className="text-lg font-mono font-bold leading-none text-neutral-200">{time.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}</div>
                        <div className="text-[10px] text-[#888] font-bold uppercase tracking-widest">{time.toLocaleDateString()}</div>
                    </div>
                </div>
            </div>

            <div className="at-soc-wall-stage flex-1 relative overflow-hidden bg-[#06080b]">
                <div className={`absolute inset-0 z-0 transition-opacity duration-1000 ${activeTab === 'OPS' ? 'opacity-100' : 'opacity-20 grayscale'}`}>
                    <AttackMapView 
                        results={results} 
                        globalThreats={globalThreats}
                        cinematic={true}
                        allowInteraction={activeTab === 'OPS'} 
                    />
                </div>
                
                <div className="absolute inset-0 pointer-events-none z-[1] bg-[radial-gradient(circle_at_center,transparent_35%,rgba(3,6,10,.70)_100%)]" />

                {activeTab === 'OPS' && (
                    <>
                        <div className="at-soc-left-rail">
                            <div className="at-soc-stat-card">
                                <StatTile
                                    label="Critical Threats"
                                    value={criticalHosts}
                                    trend="up"
                                    trendVal={12}
                                    color="text-[#e56d72]"
                                    icon={Siren}
                                />
                            </div>

                            <div className="at-soc-stat-card">
                                <StatTile
                                    label="High Risks"
                                    value={highHosts}
                                    trend="down"
                                    trendVal={5}
                                    color="text-[#d49b45]"
                                    icon={AlertTriangle}
                                />
                            </div>

                            <div className="at-soc-panel at-soc-ransom-panel">
                                <div className="at-soc-panel-header">
                                    <span>
                                        <Lock size={13} />
                                        Ransomware
                                    </span>

                                    <span className="at-soc-panel-meta">
                                        Live intelligence
                                    </span>
                                </div>

                                <div className="at-soc-ransom-summary">
                                    <div>
                                        <span>Active groups</span>
                                        <strong>
                                            {activeRansomGroups}
                                        </strong>
                                    </div>

                                    <div>
                                        <span>Total victims</span>
                                        <strong className="danger">
                                            {ransomVictims}
                                        </strong>
                                    </div>
                                </div>

                                <div className="at-soc-ransom-list">
                                    <span className="at-soc-section-label">
                                        Latest victims
                                    </span>

                                    {ransomwarePosts.length === 0 ? (
                                        <div className="py-3 text-center text-xs font-mono text-neutral-500 italic">
                                            No active ransomware incidents recorded
                                        </div>
                                    ) : (
                                        ransomwarePosts
                                            .slice(0, 3)
                                            .map((post, index) => (
                                                <div
                                                    key={index}
                                                    className="at-soc-ransom-row"
                                                >
                                                    <div>
                                                        <strong>
                                                            {post.post_title}
                                                        </strong>

                                                        <span>
                                                            {post.group_name}
                                                        </span>
                                                    </div>

                                                    <time>
                                                        {new Date(
                                                            post.discovered,
                                                        ).toLocaleDateString()}
                                                    </time>
                                                </div>
                                            ))
                                    )}
                                </div>
                            </div>
                        </div>

                        <div className="at-soc-right-rail">
                            <div className="at-soc-panel at-soc-ioc-panel">
                                <IocStatTile counts={iocCounts} stats={iocStats} />
                            </div>
                            <div className="at-soc-panel at-soc-vuln-panel">
                                <VulnAnalyticsTile 
                                    exploitCount={exploitData.length} 
                                    totalCves={cveData.length} 
                                    cisaCount={vulnStats.kev}
                                    zdiCount={cveItems.filter(i=>i.source==='ZDI').length} 
                                    criticalCve={cveData.find(c => c.severity === 'CRITICAL')}
                                />
                            </div>
                        </div>
                    </>
                )}

                {activeTab === 'LIVE' && (
                    <div className="absolute inset-4 z-20 flex gap-4 animate-fade-in">
                        <div className="w-1/2 h-full bg-[#111]/60 backdrop-blur-md border border-[#222] rounded-xl overflow-hidden shadow-2xl p-6 flex flex-col">
                            <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2 font-cyber">
                                <Zap className="text-white" size={24}/> THREAT STREAM
                            </h3>
                            <div className="flex-1 overflow-hidden rounded-lg border border-[#333] bg-[#111]/40">
                                <LiveThreatFeed 
                                    ransomwarePosts={ransomwarePosts}
                                    threatFoxItems={threatFoxItems}
                                    cveItems={cveItems}
                                />
                            </div>
                        </div>
                        <div className="w-1/2 h-full flex flex-col gap-4">
                            <div className="flex-1 bg-[#111]/60 backdrop-blur-md border border-[#222] rounded-xl p-6">
                                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2 uppercase tracking-wider">
                                    <Activity className="text-white" size={20}/> Recent Operations
                                </h3>
                                <div className="space-y-3">
                                    {results.slice(0, 8).map((host, i) => (
                                        <div key={i} className="flex justify-between items-center p-3 bg-[#111] border border-[#222] rounded hover:border-neutral-600 transition-colors">
                                            <div className="flex items-center gap-3">
                                                <span className={`w-2 h-2 rounded-full ${host.riskLevel === 'CRITICAL' ? 'bg-red-500 animate-pulse' : host.riskLevel === 'HIGH' ? 'bg-red-700' : 'bg-[#151515]'}`}></span>
                                                <span className="font-mono text-sm text-neutral-300">{host.ip}</span>
                                            </div>
                                            <span className="text-xs text-[#888]">{host.country}</span>
                                            <span className="text-xs font-bold text-white">{host.signatures.length} Sigs</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'VULN' && (
                    <div className="absolute inset-4 z-20 bg-[#111]/80 backdrop-blur-md border border-[#222] rounded-xl p-8 animate-fade-in flex flex-col gap-6">
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 shrink-0">
                            <div className="bg-[#111]/60 border border-red-500/30 rounded-lg p-4 flex items-center gap-4 hover:bg-red-900/10 transition-colors">
                                <div className="p-3 bg-red-900/20 rounded-full border border-red-500/30 text-red-500 animate-pulse"><Flame size={24}/></div>
                                <div>
                                    <div className="text-[10px] text-red-400 font-bold uppercase tracking-widest">Critical CVEs</div>
                                    <div className="text-3xl font-mono font-bold text-white">{vulnStats.critical.toLocaleString()}</div>
                                </div>
                            </div>
                            <div className="bg-[#111]/60 border border-white/20 rounded-lg p-4 flex items-center gap-4 hover:bg-white/5 transition-colors">
                                <div className="p-3 bg-white/10 rounded-full border border-white/20 text-white"><AlertCircle size={24}/></div>
                                <div>
                                    <div className="text-[10px] text-neutral-400 font-bold uppercase tracking-widest">Known Exploited</div>
                                    <div className="text-3xl font-mono font-bold text-white">{vulnStats.kev.toLocaleString()}</div>
                                </div>
                            </div>
                            <div className="bg-[#111]/60 border border-white/20 rounded-lg p-4 flex items-center gap-4 hover:bg-[#111] transition-colors">
                                <div className="p-3 bg-[#111] rounded-full border border-white/20 text-white"><BarChart3 size={24}/></div>
                                <div>
                                    <div className="text-[10px] text-neutral-400 font-bold uppercase tracking-widest">Avg Severity</div>
                                    <div className="text-3xl font-mono font-bold text-white">{vulnStats.avgScore}</div>
                                </div>
                            </div>
                            <div className="bg-[#111]/60 border border-white/20 rounded-lg p-4 flex items-center gap-4 hover:bg-white/5 transition-colors">
                                <div className="p-3 bg-white/10 rounded-full border border-white/20 text-white"><Zap size={24}/></div>
                                <div>
                                    <div className="text-[10px] text-neutral-400 font-bold uppercase tracking-widest">Public Exploits</div>
                                    <div className="text-3xl font-mono font-bold text-white">{exploitData.length.toLocaleString()}</div>
                                </div>
                            </div>
                        </div>

                        {/* Additional Stats Row (New) */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 h-32 shrink-0">
                             <div className="bg-[#111] border border-[#222] rounded-lg p-4 flex items-center justify-between">
                                 <div>
                                     <h3 className="text-xs font-bold text-red-400 uppercase mb-2 flex items-center gap-2">
                                         <Network size={14}/> Attack Vectors
                                     </h3>
                                     <div className="flex gap-4 text-xs font-mono text-[#AAA]">
                                         <div>NET: <span className="text-white">{vulnStats.vectors.NETWORK}</span></div>
                                         <div>ADJ: <span className="text-white">{vulnStats.vectors.ADJACENT}</span></div>
                                         <div>LOC: <span className="text-white">{vulnStats.vectors.LOCAL}</span></div>
                                         <div>PHY: <span className="text-white">{vulnStats.vectors.PHYSICAL}</span></div>
                                     </div>
                                 </div>
                                 <div className="h-full w-48 flex items-end gap-1">
                                     {['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'].map((v, i) => (
                                         <div key={v} className="w-1/4 bg-white/10 h-full relative rounded-t">
                                             <div className="absolute bottom-0 left-0 right-0 bg-white/40 hover:bg-white/60 transition-colors" style={{ height: `${(vulnStats.vectors[v] / Math.max(1, vulnStats.total)) * 100}%` }}></div>
                                         </div>
                                     ))}
                                 </div>
                             </div>
                             
                             <div className="bg-[#111] border border-[#222] rounded-lg p-4 flex flex-col relative overflow-hidden">
                                 <h3 className="text-xs font-bold text-red-400 uppercase mb-2 flex items-center gap-2 z-10">
                                     <Siren size={14}/> Recent KEV Additions
                                 </h3>
                                 <div className="flex-1 overflow-hidden relative z-10">
                                     <div className="animate-vertical-scroll space-y-2">
                                         {[...vulnStats.kevList, ...vulnStats.kevList].map((k, i) => (
                                             <div key={i} className="flex justify-between text-[10px] border-b border-[#222] pb-1">
                                                 <span className="font-bold text-red-300">{k.id}</span>
                                                 <span className="text-[#888] truncate max-w-[200px]">{k.product}</span>
                                             </div>
                                         ))}
                                     </div>
                                 </div>
                                 <div className="absolute top-0 right-0 p-4 opacity-5 pointer-events-none">
                                     <Skull size={100}/>
                                 </div>
                             </div>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 flex-1 min-h-0">
                            <div className="col-span-1 space-y-6">
                                <div className="bg-[#111] border border-[#222] p-6 rounded-lg h-full flex flex-col">
                                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><BarChart3 className="text-red-400"/> SEVERITY DISTRIBUTION</h3>
                                    <div className="flex-1 flex items-center justify-center gap-4">
                                        {[
                                            { label: 'CRITICAL', count: vulnStats.critical, color: 'bg-red-600', text: 'text-red-500' },
                                            { label: 'HIGH', count: vulnStats.high, color: 'bg-red-800', text: 'text-red-400' },
                                            { label: 'MEDIUM', count: vulnStats.medium, color: 'bg-neutral-400', text: 'text-neutral-400' },
                                            { label: 'LOW', count: vulnStats.low, color: 'bg-neutral-600', text: 'text-neutral-600' }
                                        ].map((sev, i) => (
                                            <div key={i} className="flex flex-col items-center gap-2">
                                                <div className="w-12 bg-[#151515] rounded-t relative overflow-hidden h-32 flex items-end">
                                                    <div className={`w-full ${sev.color} transition-all duration-1000`} style={{ height: `${(sev.count / vulnStats.total) * 100}%` }}></div>
                                                </div>
                                                <div className={`text-xs font-bold ${sev.text}`}>{sev.count}</div>
                                                <div className="text-[8px] text-[#888] uppercase">{sev.label}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="col-span-1 space-y-6">
                                <div className="bg-[#111] border border-[#222] p-6 rounded-lg h-full flex flex-col">
                                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Bug className="text-red-500"/> TOP WEAKNESSES (CWE)</h3>
                                    <div className="space-y-3 overflow-y-auto custom-scrollbar flex-1">
                                        {vulnStats.topCwes.map((cwe, i) => (
                                            <div key={i} className="flex items-center gap-2">
                                                <div className="flex-1 text-sm text-neutral-300 font-mono">{cwe.label}</div>
                                                <div className="w-1/2 bg-[#151515] h-2 rounded-full overflow-hidden">
                                                    <div className="bg-red-500 h-full" style={{width: `${(cwe.count / vulnStats.topCwes[0].count) * 100}%`}}></div>
                                                </div>
                                                <div className="text-xs font-mono text-white w-8 text-right">{cwe.count}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="col-span-1 space-y-6">
                                <div className="bg-[#111] border border-[#222] p-6 rounded-lg h-full flex flex-col">
                                    <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2"><Target className="text-white"/> TOP VULNERABLE VENDORS</h3>
                                    <div className="space-y-3 overflow-y-auto custom-scrollbar flex-1">
                                        {topVendors.map((v, i) => (
                                            <div key={i} className="flex items-center gap-2">
                                                <div className="flex-1 text-sm text-neutral-300">{v.label}</div>
                                                <div className="w-1/2 bg-[#151515] h-2 rounded-full overflow-hidden">
                                                    <div className="bg-red-700 h-full" style={{width: `${(v.count / topVendors[0].count) * 100}%`}}></div>
                                                </div>
                                                <div className="text-xs font-mono text-white w-8 text-right">{v.count}</div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'IOC' && (
                    <div className="absolute inset-4 z-20 bg-[#111]/80 backdrop-blur-md border border-[#222] rounded-xl p-8 animate-fade-in flex flex-col gap-6">
                        <div className="flex justify-between items-center mb-2">
                            <h3 className="text-2xl font-bold text-white flex items-center gap-2 font-cyber"><Database className="text-red-500"/> INDICATOR ANALYTICS</h3>
                            <div className="text-xs font-mono text-[#888] animate-pulse flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-red-500"></span> LIVE INGEST ACTIVE
                            </div>
                        </div>

                        {/* Recent IOC Ticker (New) */}
                        <div className="bg-[#111] border-y border-[#222] py-2 overflow-hidden flex items-center gap-4">
                            <div className="text-[10px] font-bold text-[#888] uppercase px-4 border-r border-[#333]">Recent Ingest</div>
                            <div className="flex-1 overflow-hidden">
                                <div className="flex gap-8 animate-marquee whitespace-nowrap">
                                    {[...latestIocs, ...latestIocs].map((item, i) => (
                                        <div key={i} className="flex items-center gap-2 text-xs font-mono text-[#AAA]">
                                            <span className={`text-[9px] px-1.5 rounded font-bold ${item.src === 'FEODO' ? 'bg-red-900/20 text-red-400' : 'bg-[#111] text-red-400'}`}>{item.src}</span>
                                            <span className="text-white">{item.val}</span>
                                            <span className="text-neutral-600">[{item.threat}]</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-4 gap-6 pb-4">
                            {iocCounts.map((ioc, idx) => (
                                <div key={idx} className="bg-[#111] border border-[#222] p-4 rounded-lg flex flex-col items-center justify-center relative overflow-hidden group">
                                    <div className="absolute inset-0 bg-gradient-to-br from-transparent to-white/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                                    <div className="text-3xl font-bold text-white mb-2 relative z-10">{ioc.value.toLocaleString()}</div>
                                    <div className={`text-xs font-bold uppercase relative z-10 ${ioc.color}`}>{ioc.label}</div>
                                    <div className={`absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-current to-transparent opacity-50 ${ioc.color}`}></div>
                                </div>
                            ))}
                        </div>

                        <div className="grid grid-cols-2 gap-6 flex-1 min-h-0">
                            <div className="col-span-1 bg-[#111] border border-[#222] p-6 rounded-lg flex flex-col">
                                <h4 className="text-sm font-bold text-[#AAA] uppercase mb-4">Top Malware Families</h4>
                                <div className="space-y-2 flex-1 overflow-y-auto custom-scrollbar">
                                    {iocStats.malware.slice(0, 10).map((m, i) => (
                                        <div key={i} className="flex justify-between items-center group hover:bg-white/5 p-1 rounded">
                                            <span className="text-sm text-neutral-300 font-mono truncate w-1/3 group-hover:text-white transition-colors">{m.label}</span>
                                            <div className="flex-1 mx-4 h-1 bg-[#151515] rounded-full overflow-hidden">
                                                <div className="bg-red-500 h-full shadow-[0_0_5px_#ef4444]" style={{width: `${(m.count / iocStats.malware[0].count) * 100}%`}}></div>
                                            </div>
                                            <span className="text-sm font-bold text-white">{m.count}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="col-span-1 bg-[#111] border border-[#222] p-6 rounded-lg flex flex-col">
                                <h4 className="text-sm font-bold text-[#AAA] uppercase mb-4">Bad Infrastructure (ASN)</h4>
                                <div className="space-y-2 flex-1 overflow-y-auto custom-scrollbar">
                                    {iocStats.asns.slice(0, 10).map((a, i) => (
                                        <div key={i} className="flex justify-between items-center group hover:bg-white/5 p-1 rounded">
                                            <span className="text-sm text-neutral-300 font-mono truncate max-w-[200px] w-1/3 group-hover:text-white">{a.label}</span>
                                            <div className="flex-1 mx-4 h-1 bg-[#151515] rounded-full overflow-hidden">
                                                <div className="bg-red-700 h-full shadow-[0_0_5px_#b91c1c]" style={{width: `${(a.count / iocStats.asns[0].count) * 100}%`}}></div>
                                            </div>
                                            <span className="text-sm font-bold text-white">{a.count}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="col-span-1 bg-[#111] border border-[#222] p-6 rounded-lg">
                                <h4 className="text-sm font-bold text-[#AAA] uppercase mb-4">IOC Distribution by Type</h4>
                                <div className="flex items-center justify-around h-full">
                                    {iocStats.types.map((t, i) => (
                                        <div key={i} className="flex flex-col items-center gap-2">
                                            <div className="h-32 w-10 bg-[#151515] rounded-t relative overflow-hidden flex items-end">
                                                <div className="w-full bg-[#151515] shadow-[0_0_10px_#3b82f6]" style={{ height: `${(t.count / Math.max(1, iocStats.types[0].count)) * 100}%` }}></div>
                                            </div>
                                            <div className="mt-1 text-xs font-bold text-white">{t.count}</div>
                                            <div className="text-[10px] text-[#888] uppercase">{t.label}</div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="col-span-1 bg-[#111] border border-[#222] p-6 rounded-lg flex flex-col">
                                <h4 className="text-sm font-bold text-[#AAA] uppercase mb-4">Top C2 Countries (Feodo)</h4>
                                <div className="grid grid-cols-2 gap-4">
                                    {iocStats.countries.slice(0, 8).map((c, i) => (
                                        <div key={i} className="flex items-center justify-between bg-[#111]/30 p-2 rounded border border-[#222] hover:border-red-500/30 transition-colors">
                                            <div className="flex items-center gap-2">
                                                <img src={`https://flagcdn.com/w20/${c.label.toLowerCase()}.png`} className="w-5 h-3 rounded-sm opacity-80" alt={c.label}/>
                                                <span className="text-sm text-neutral-300 font-mono">{c.label}</span>
                                            </div>
                                            <span className="text-sm font-bold text-red-400">{c.count}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'NEWS' && (
                    <div className="absolute inset-4 z-20 bg-[#111]/80 backdrop-blur-md border border-[#222] rounded-xl p-0 animate-fade-in overflow-hidden flex flex-col">
                        <div className="absolute top-0 left-0 right-0 z-10 bg-gradient-to-b from-black via-black/80 to-transparent h-24 p-8 flex items-center gap-4">
                             <h3 className="text-2xl font-bold text-white flex items-center gap-2 font-cyber"><Globe className="text-red-500"/> GLOBAL INTEL BRIEF</h3>
                             <span className="text-xs font-mono text-[#888] bg-[#111] px-2 py-1 rounded border border-[#222]">{newsItems.length} Sources Active</span>
                        </div>
                        
                        <div className="flex-1 relative overflow-hidden">
                             <div className="overflow-y-auto custom-scrollbar w-full h-full px-8 pb-8 pt-24 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 absolute inset-0">
                                {scrollingNews.map((news, i) => {
                                    const criticality = getCriticality(news);
                                    return (
                                        <div key={`${news.link}-${i}`} className={`bg-[#111] border p-6 rounded-lg hover:bg-[#151515] transition-colors group relative ${getTagStyle(news.category)}`}>
                                            {criticality === 'CRITICAL' && (
                                                <div className="absolute -right-1 -top-1 bg-red-600 text-white text-[9px] font-bold px-2 py-0.5 rounded-bl shadow-[0_0_8px_#dc2626] animate-pulse">CRITICAL</div>
                                            )}
                                            <div className="text-xs font-bold uppercase mb-2 flex justify-between opacity-80 items-center">
                                                <span className="flex items-center gap-2">
                                                    {news.source}
                                                    <span className="px-2 py-0.5 rounded text-[8px] font-bold uppercase bg-[#111]/30 border border-white/10">
                                                        {news.category}
                                                    </span>
                                                </span>
                                                <span>{new Date(news.timestamp).toLocaleDateString()}</span>
                                            </div>
                                            <h4 className="text-lg font-bold text-white mb-2 group-hover:text-red-500 transition-colors leading-tight">{news.title}</h4>
                                            <p className="text-sm opacity-70 line-clamp-3 leading-relaxed">{news.description}</p>
                                        </div>
                                    );
                                })}
                             </div>
                        </div>
                        <div className="absolute bottom-0 left-0 right-0 h-24 bg-gradient-to-t from-black to-transparent pointer-events-none z-10"></div>
                    </div>
                )}
            </div>

            <div className="h-8 shrink-0 z-30">
                <NewsTicker items={newsItems} />
            </div>
        </div>
    );
};

