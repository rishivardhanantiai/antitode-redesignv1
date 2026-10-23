
import React, { useState } from 'react';
import { Search, Globe, Server, Shield, Lock, Code, Leaf, Activity, ArrowRight, Wifi, FileText, CheckCircle, XCircle, Loader2, Network, Skull, ExternalLink, Zap, Key, History, Archive, AlertTriangle, Download, Radar } from 'lucide-react';
import { WebCheckResult } from '../../types';
import { performWebCheck } from '../../services/webcheck';
import { downloadFile, generateWebCheckPDF } from '../../services/exporter';

const Card: React.FC<{ title: string, icon: any, children: React.ReactNode, color?: string, className?: string, loading?: boolean, badge?: string }> = ({ title, icon: Icon, children, color = "text-red-500", className = "", loading = false, badge }) => (
    <div className={`bg-[#111] border border-[#222] rounded-lg p-5 backdrop-blur-sm flex flex-col h-full hover:border-[#333] transition-colors ${className}`}>
        <div className="flex items-center gap-2 mb-4 border-b border-[#222] pb-2 justify-between">
            <div className="flex items-center gap-2">
                <Icon className={color} size={18} />
                <h3 className="text-sm font-bold text-neutral-200 uppercase tracking-wider">{title}</h3>
                {badge && (
                    <span className="text-[9px] font-mono font-bold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-1.5 py-0.5 rounded">
                        {badge}
                    </span>
                )}
            </div>
            {loading && <Loader2 className="animate-spin text-neutral-600" size={12}/>}
        </div>
        <div className="flex-1">
            {children}
        </div>
    </div>
);

interface WebCheckViewProps {
    logoUrl?: string;
}

export const WebCheckView: React.FC<WebCheckViewProps> = ({ logoUrl }) => {
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<WebCheckResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    const handleScan = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!input) return;

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            // Pass a callback to receive partial updates
            await performWebCheck(input, (partialResult) => {
                setResult(prev => ({ ...prev, ...partialResult }));
            });
        } catch (err) {
            setError("Scan failed. Please check the domain/IP and try again.");
        } finally {
            setLoading(false);
        }
    };

    const handleExportReport = () => {
        if (!result) return;

        const lines: string[] = [];
        const sep = "--------------------------------------------------------------------------------";
        
        lines.push(sep);
        lines.push(`ANTI.AI WEB CHECK REPORT`);
        lines.push(sep);
        lines.push(`Target:       ${result.target}`);
        lines.push(`Scan Date:    ${new Date().toLocaleString()}`);
        lines.push(`Input Type:   ${result.inputType}`);
        lines.push(`Threat Risk:  ${result.blocklist?.summary || 'ANALYZING'}`);
        lines.push("");

        if (result.ipInfo) {
            lines.push("[ IDENTITY & NETWORK ]");
            lines.push(`IP Address:   ${result.ipInfo.ip}`);
            lines.push(`Location:     ${result.ipInfo.city}, ${result.ipInfo.country_name} (${result.ipInfo.country_code})`);
            lines.push(`ASN:          ${result.ipInfo.asn?.asn} - ${result.ipInfo.asn?.name}`);
            lines.push(`Organization: ${result.ipInfo.company?.name || 'N/A'}`);
            lines.push(`Risk Score:   ${result.ipInfo.threat.scores?.threat_score || 0}/100`);
            
            const threats = [];
            if (result.ipInfo.threat.is_tor) threats.push("TOR Node");
            if (result.ipInfo.threat.is_proxy) threats.push("Proxy/VPN");
            if (result.ipInfo.threat.is_known_attacker) threats.push("Known Attacker");
            if (threats.length > 0) lines.push(`Flags:        ${threats.join(', ')}`);
            lines.push("");
        }

        if (result.dns) {
            lines.push("[ DNS RECORDS ]");
            if (result.dns.a.length) lines.push(`A Records:    ${result.dns.a.join(', ')}`);
            if (result.dns.mx.length) lines.push(`MX Records:   ${result.dns.mx.join(', ')}`);
            if (result.dns.ns.length) lines.push(`NS Records:   ${result.dns.ns.join(', ')}`);
            if (result.dns.txt.length) lines.push(`TXT Records:  ${result.dns.txt.length} records found`);
            lines.push("");
        }

        if (result.http) {
            lines.push("[ HTTP ANALYSIS ]");
            lines.push(`Status:       ${result.http.status} ${result.http.statusText}`);
            if (result.http.server) lines.push(`Server:       ${result.http.server}`);
            
            lines.push("\n-- Security Headers --");
            result.http.securityHeaders.forEach(h => {
                lines.push(`${h.name.padEnd(30)}: ${h.valid ? 'PRESENT' : 'MISSING'}`);
            });
            lines.push("");
        }

        if (result.page && result.page.techStack.length > 0) {
            lines.push("[ TECHNOLOGY STACK ]");
            lines.push(result.page.techStack.join(', '));
            lines.push("");
        }

        if (result.blocklist && result.blocklist.sources.length > 0) {
            lines.push("[ THREAT INTELLIGENCE ]");
            result.blocklist.sources.forEach(src => {
                lines.push(`[${src.detected ? 'DETECTED' : 'CLEAN'}] ${src.name}`);
            });
            lines.push("");
        }

        if (result.otx) {
            lines.push("[ ALIENVAULT OTX ]");
            lines.push(`Pulses:       ${result.otx.pulse_count}`);
            lines.push(`Tags:         ${result.otx.tags.join(', ')}`);
            lines.push(`Malware:      ${result.otx.malware_families.join(', ')}`);
            lines.push("");
        }

        if (result.ct && result.ct.latest) {
            lines.push("[ SSL/TLS CERTIFICATE ]");
            lines.push(`Issuer:       ${result.ct.latest.issuer_name}`);
            lines.push(`Subject:      ${result.ct.latest.common_name}`);
            lines.push(`Validity:     ${result.ct.latest.not_before} to ${result.ct.latest.not_after}`);
            lines.push(`Subdomains:   ${result.ct.total} known subdomains logged`);
            lines.push("");
        }

        if (result.carbon) {
            lines.push("[ CARBON FOOTPRINT ]");
            lines.push(`Rating:       ${result.carbon.rating}`);
            lines.push(`Emissions:    ${result.carbon.g}g CO2 per visit`);
            lines.push("");
        }

        lines.push(sep);
        lines.push("End of Report");
        lines.push(sep);

        const filename = `webcheck_${result.target.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.txt`;
        downloadFile(lines.join('\n'), filename, 'text/plain');
    };

    const formatWayback = (ts?: string) => {
        if (!ts) return 'Unknown';
        const Y = ts.substring(0,4);
        const M = ts.substring(4,6);
        const D = ts.substring(6,8);
        return `${Y}-${M}-${D}`;
    };

    return (
        <div className="h-full bg-[#111] overflow-y-auto custom-scrollbar p-4 md:p-8 w-full relative">
            {/* Header Input Section */}
            <div className="max-w-3xl mx-auto mb-12 text-center">
                <h1 className="text-3xl md:text-4xl font-cyber font-bold text-white mb-4 text-glow">WEB <span className="text-red-500">CHECK</span></h1>
                <p className="text-[#AAA] mb-8 text-sm md:text-base font-mono">
                    Deep passive analysis of domains, IPs, and URLs. 
                    <span className="block text-xs text-neutral-600 mt-2">DNS Firewall • SSL • Blocklists • Whois</span>
                </p>
                
                <form onSubmit={handleScan} className="relative max-w-lg mx-auto">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Globe className="h-5 w-5 text-[#888]" />
                    </div>
                    <input
                        type="text"
                        className="block w-full pl-10 pr-24 py-3 bg-[#111]/50 border border-[#333] rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 text-white placeholder-neutral-500 sm:text-sm font-mono transition-all"
                        placeholder="example.com, 8.8.8.8, or https://site.com"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                    />
                    <button
                        type="submit"
                        disabled={loading && !result}
                        className="absolute right-2 top-2 bottom-2 px-4 bg-red-500/20 hover:bg-red-500/40 text-red-500 border border-red-500/50 rounded text-xs font-bold uppercase transition-colors flex items-center gap-2"
                    >
                        {loading ? <Loader2 className="animate-spin" size={14}/> : <Search size={14}/>}
                        SCAN
                    </button>
                </form>
                {error && <div className="mt-4 text-red-400 text-xs font-mono bg-red-900/20 border border-red-900 p-2 rounded">{error}</div>}
                
                {result && (
                    <div className="mt-4 flex justify-center gap-2">
                        <button 
                            onClick={handleExportReport}
                            className="text-xs flex items-center gap-2 text-[#AAA] hover:text-white transition-colors bg-[#111] px-4 py-2 rounded-full border border-[#333] hover:border-neutral-500"
                        >
                            <Download size={14}/> EXPORT TXT
                        </button>
                        <button 
                            onClick={() => generateWebCheckPDF(result, logoUrl)}
                            className="text-xs flex items-center gap-2 text-[#AAA] hover:text-white transition-colors bg-[#111] px-4 py-2 rounded-full border border-[#333] hover:border-neutral-500"
                        >
                            <Download size={14}/> EXPORT PDF
                        </button>
                    </div>
                )}
            </div>

            {result && (
                <div className="w-full animate-fade-in grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6 pb-10">
                    
                    {/* 1. Target Info */}
                    <div className="md:col-span-2 lg:col-span-3 xl:col-span-4">
                        <div className="bg-gradient-to-r from-neutral-900 to-black border border-[#222] rounded-lg p-6 flex flex-col md:flex-row items-center justify-between gap-6">
                            <div className="flex items-center gap-4">
                                <div className="p-4 rounded-full bg-red-500/10 border border-red-500/30 relative">
                                    <Globe className="text-red-500" size={32}/>
                                    {result.visuals?.favicon && (
                                        <img src={result.visuals.favicon} alt="fav" className="absolute -bottom-1 -right-1 w-6 h-6 rounded bg-[#111] p-0.5 border border-[#333]" onError={(e) => e.currentTarget.style.display = 'none'}/>
                                    )}
                                </div>
                                <div>
                                    <h2 className="text-2xl font-bold text-white font-mono">{result.target}</h2>
                                    <div className="flex gap-2 mt-1">
                                        <span className="px-2 py-0.5 rounded bg-[#151515] border border-[#333] text-xs text-[#AAA] font-mono">{result.inputType}</span>
                                        {result.http.status > 0 ? (
                                            <span className={`px-2 py-0.5 rounded border text-xs font-mono ${result.http.status === 200 ? 'bg-neutral-900/30 border-neutral-500/30 text-white' : 'bg-neutral-900/30 border-neutral-500/30 text-white'}`}>HTTP {result.http.status}</span>
                                        ) : loading && (
                                            <span className="px-2 py-0.5 rounded border border-[#333] bg-[#151515]/50 text-[#888] text-xs flex items-center gap-1"><Loader2 className="animate-spin" size={10}/> Connecting...</span>
                                        )}
                                        {result.blocklist?.summary === 'MALICIOUS' && <span className="px-2 py-0.5 rounded border border-red-500 bg-red-900 text-white text-xs font-bold animate-pulse">THREAT DETECTED</span>}
                                    </div>
                                </div>
                            </div>
                            <div className="flex gap-8 text-sm text-[#AAA] font-mono">
                                <div className="text-center">
                                    <div className="text-[10px] uppercase text-neutral-600 mb-1">Location</div>
                                    <div className="text-white flex items-center gap-1 justify-center">
                                        {result.ipInfo?.flag ? <img src={result.ipInfo.flag} alt="flag" className="w-4 h-3"/> : loading && !result.ipInfo ? <Loader2 className="animate-spin" size={10}/> : null}
                                        {result.ipInfo?.country_code || '-'}
                                    </div>
                                </div>
                                <div className="text-center">
                                    <div className="text-[10px] uppercase text-neutral-600 mb-1">ASN</div>
                                    <div className="text-white">{result.ipInfo?.asn?.asn || '-'}</div>
                                </div>
                                <div className="text-center">
                                    <div className="text-[10px] uppercase text-neutral-600 mb-1">ISP</div>
                                    <div className="text-white">{result.ipInfo?.asn?.name ? result.ipInfo.asn.name.substring(0, 15) + '..' : '-'}</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* 3. DNS Firewall (DoT) */}
                    <Card title="DNS Firewall Analysis" icon={Shield} color="text-red-400" loading={loading && result.dnsSecurity.length === 0}>
                        <div className="space-y-3">
                            {result.dnsSecurity && result.dnsSecurity.length > 0 ? (
                                result.dnsSecurity.map((res, i) => (
                                    <div key={i} className="flex items-center justify-between p-2 rounded bg-[#111]/30 border border-[#222] text-xs">
                                        <span className="text-[#AAA] font-mono">{res.provider}</span>
                                        {res.status === 'BLOCKED' ? (
                                            <span className="text-red-400 font-bold flex items-center gap-1 px-2 py-0.5 bg-red-900/20 rounded border border-red-500/30">
                                                <XCircle size={10}/> BLOCKED
                                            </span>
                                        ) : res.status === 'CLEAN' ? (
                                            <span className="text-white flex items-center gap-1">
                                                <CheckCircle size={10}/> ALLOWED
                                            </span>
                                        ) : (
                                            <span className="text-neutral-600">UNKNOWN</span>
                                        )}
                                    </div>
                                ))
                            ) : (
                                <div className="text-[#888] italic text-xs">
                                    {loading ? "Querying security providers..." : "No DNS Firewall data available."}
                                </div>
                            )}
                            <div className="text-[10px] text-[#888] mt-2 pt-2 border-t border-[#222]/50">
                                Checks domain resolution against major security DNS providers (Quad9, Cloudflare Malware, OpenDNS).
                            </div>
                        </div>
                    </Card>

                    {/* 4. Blocklist Analysis */}
                    <Card title="Global Blocklists" icon={Skull} color="text-red-400" className="md:col-span-1 row-span-2" loading={loading && !result.blocklist}>
                         {result.blocklist ? (
                             <div className="space-y-3 h-full flex flex-col">
                                 <div className={`p-3 rounded text-center border ${result.blocklist.summary === 'MALICIOUS' ? 'bg-red-900/20 border-red-500/50' : 'bg-neutral-900/20 border-neutral-500/50'}`}>
                                     <div className="text-[10px] text-[#AAA] uppercase mb-1">Threat Status</div>
                                     <div className={`text-xl font-bold ${result.blocklist.summary === 'MALICIOUS' ? 'text-red-400' : 'text-white'}`}>{result.blocklist.summary}</div>
                                 </div>
                                 
                                 <div className="flex-1 overflow-y-auto custom-scrollbar space-y-1 pr-1 max-h-48">
                                     {result.blocklist.sources.map((src, idx) => (
                                         <div key={idx} className="flex items-center justify-between p-2 rounded bg-[#111]/30 border border-[#222] text-xs">
                                             <span className="text-[#AAA] truncate pr-2">{src.name}</span>
                                             {src.detected ? (
                                                 <span className="text-red-400 font-bold flex items-center gap-1 whitespace-nowrap"><Skull size={10}/> LISTED</span>
                                             ) : (
                                                 <span className="text-white/50 flex items-center gap-1 whitespace-nowrap"><CheckCircle size={10}/> Clean</span>
                                             )}
                                         </div>
                                     ))}
                                     <a href={`https://www.virustotal.com/gui/${result.inputType === 'IP' ? 'ip-address' : 'domain'}/${result.target}`} target="_blank" rel="noopener noreferrer" className="flex items-center justify-between p-2 rounded bg-[#111]/30 border border-[#222] text-xs hover:bg-[#111] transition-colors group">
                                         <span className="text-red-400 group-hover:text-[#888]">VirusTotal</span>
                                         <ExternalLink size={10} className="text-neutral-600 group-hover:text-[#888]"/>
                                     </a>
                                 </div>
                                 
                                 {result.blocklist.summary === 'MALICIOUS' && (
                                     <div className="text-[10px] text-red-400 bg-red-900/10 p-2 rounded border border-red-900/30 flex items-start gap-2">
                                         <AlertTriangle size={12} className="mt-0.5 shrink-0"/>
                                         <span>Warning: This indicator appears on known blocklists (RBL/Spamhaus/URLHaus).</span>
                                     </div>
                                 )}
                             </div>
                         ) : (
                             <div className="text-center text-[#888] italic mt-10">
                                 {loading ? "Analyzing threat feeds..." : "Analysis pending."}
                             </div>
                         )}
                    </Card>

                    {/* 5. DNS Records */}
                    <Card title="DNS Records" icon={Server} color="text-red-400" loading={loading && result.dns.a.length === 0}>
                        <div className="space-y-3 font-mono text-xs">
                            {result.dns.a.length > 0 && (
                                <div>
                                    <span className="text-red-400 font-bold">A</span>
                                    <div className="pl-4 text-[#AAA]">{result.dns.a.slice(0, 3).join('\n')}</div>
                                </div>
                            )}
                            {result.dns.mx.length > 0 && (
                                <div>
                                    <span className="text-red-400 font-bold">MX</span>
                                    <div className="pl-4 text-[#AAA]">{result.dns.mx.slice(0, 2).join('\n')}</div>
                                </div>
                            )}
                            {result.dns.ns.length > 0 && (
                                <div>
                                    <span className="text-white font-bold">NS</span>
                                    <div className="pl-4 text-[#AAA]">{result.dns.ns.slice(0, 2).join('\n')}</div>
                                </div>
                            )}
                            {(!result.dns.a.length && !result.dns.mx.length) && <span className="text-[#888] italic">{loading ? "Resolving..." : "No records found."}</span>}
                        </div>
                    </Card>

                    {/* 6. Certificate Identity */}
                    <Card title="Certificate Identity" icon={Lock} color="text-red-400" className="md:col-span-1 row-span-2" loading={loading && !result.ct}>
                        {result.ct ? (
                            <div className="flex flex-col h-full">
                                <div className="mb-3 text-xs">
                                    <div className="flex justify-between items-center mb-1">
                                        <span className="text-[#888] uppercase font-bold text-[10px]">Latest Cert</span>
                                        <span className="text-white font-mono text-[10px]">VALID</span>
                                    </div>
                                    <div className="bg-[#151515]/50 p-2 rounded border border-[#333] mb-1">
                                        <div className="text-white font-bold">{result.ct.latest?.issuer_name.split(',')[0] || 'Unknown'}</div>
                                        <div className="text-[10px] text-[#888]">{new Date(result.ct.latest?.not_after || '').toLocaleDateString()}</div>
                                    </div>
                                </div>
                                
                                <div className="flex-1 flex flex-col min-h-0">
                                    <div className="flex justify-between items-center mb-2">
                                        <span className="text-[10px] text-[#888] uppercase font-bold">Subdomains Found ({result.ct.subdomains.length})</span>
                                        {result.ct.subdomains.length > 10 && <span className="text-[10px] text-neutral-600 italic">Top 50</span>}
                                    </div>
                                    <div className="flex-1 overflow-y-auto custom-scrollbar bg-[#111]/30 rounded border border-[#222] p-2 space-y-1">
                                        {result.ct.subdomains.slice(0, 50).map((sub, i) => (
                                            <div key={i} className="text-xs text-neutral-300 font-mono truncate hover:text-white cursor-default" title={sub}>
                                                {sub}
                                            </div>
                                        ))}
                                        {result.ct.subdomains.length === 0 && <div className="text-[#888] text-xs italic text-center py-4">No subdomains found in logs.</div>}
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full text-[#888]">
                                <Key size={24} className={`opacity-20 mb-2 ${loading ? 'animate-pulse' : ''}`}/>
                                <span className="text-xs italic">{loading ? "Querying CT Logs..." : "No Certificate Data"}</span>
                            </div>
                        )}
                    </Card>

                    {/* 7. AlienVault OTX Intelligence */}
                    <Card title="AlienVault OTX Intelligence" icon={Radar} color="text-white" loading={loading && !result.otx}>
                        {result.otx ? (
                            <div className="space-y-4">
                                <div className="flex justify-between items-center p-2 rounded bg-[#111] border border-[#222]">
                                    <span className="text-xs text-[#AAA] font-mono">Pulse Count</span>
                                    <span className="text-white font-bold">{result.otx.pulse_count}</span>
                                </div>
                                {result.otx.malware_families.length > 0 && (
                                    <div>
                                        <div className="text-[10px] text-[#888] uppercase font-bold mb-1">Malware Families</div>
                                        <div className="flex flex-wrap gap-1">
                                            {result.otx.malware_families.map((m, i) => (
                                                <span key={i} className="text-[10px] bg-red-900/20 text-red-300 px-1.5 py-0.5 rounded border border-red-500/20">{m}</span>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                {result.otx.tags.length > 0 && (
                                    <div>
                                        <div className="text-[10px] text-[#888] uppercase font-bold mb-1">Tags</div>
                                        <div className="flex flex-wrap gap-1">
                                            {result.otx.tags.slice(0, 10).map((t, i) => (
                                                <span key={i} className="text-[10px] bg-[#151515] text-[#AAA] px-1.5 py-0.5 rounded border border-[#333]">{t}</span>
                                            ))}
                                            {result.otx.tags.length > 10 && <span className="text-[9px] text-neutral-600">+{result.otx.tags.length - 10}</span>}
                                        </div>
                                    </div>
                                )}
                                <div className="text-[10px] text-[#888] mt-2 text-center">
                                    <a href={`https://otx.alienvault.com/indicator/${result.inputType === 'IP' ? 'ip' : 'domain'}/${result.target}`} target="_blank" rel="noopener noreferrer" className="hover:text-white flex items-center justify-center gap-1">
                                        View Full OTX Report <ExternalLink size={10}/>
                                    </a>
                                </div>
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full text-[#888]">
                                <Radar size={24} className={`opacity-20 mb-2 ${loading ? 'animate-pulse' : ''}`}/>
                                <span className="text-xs italic">{loading ? "Querying OTX..." : "No Threat Intel Found"}</span>
                            </div>
                        )}
                    </Card>

                    {/* 8. Archive / Digital History */}
                    <Card title="Digital History" icon={Archive} color="text-white" loading={loading && !result.archive}>
                        {result.archive ? (
                            <div className="space-y-4">
                                <div className={`p-3 rounded border text-center ${result.archive.available ? 'bg-neutral-900/20 border-neutral-500/30' : 'bg-[#151515] border-[#333]'}`}>
                                    <div className="text-[10px] uppercase text-[#888] mb-1">Wayback Machine</div>
                                    <div className={`text-lg font-bold ${result.archive.available ? 'text-white' : 'text-[#AAA]'}`}>
                                        {result.archive.available ? 'SNAPSHOT AVAILABLE' : 'NO SNAPSHOTS'}
                                    </div>
                                </div>
                                {result.archive.available && (
                                    <>
                                        <div className="space-y-1 text-xs font-mono">
                                            <div className="flex justify-between">
                                                <span className="text-[#888]">Last Snapshot:</span>
                                                <span className="text-white">{formatWayback(result.archive.timestamp)}</span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span className="text-[#888]">HTTP Status:</span>
                                                <span className="text-red-500">{result.archive.status}</span>
                                            </div>
                                        </div>
                                        {result.archive.url && (
                                            <a 
                                                href={result.archive.url} 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                                className="block w-full py-2 bg-neutral-600/20 hover:bg-neutral-600/40 text-white border border-neutral-500/50 rounded text-center text-xs font-bold transition-colors flex items-center justify-center gap-2"
                                            >
                                                <History size={12}/> View Archive
                                            </a>
                                        )}
                                    </>
                                )}
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full text-[#888] gap-2">
                                <Archive size={24} className={`opacity-20 ${loading ? 'animate-pulse' : ''}`}/>
                                <span className="text-xs italic">{loading ? "Checking Wayback..." : "No Archive Data"}</span>
                            </div>
                        )}
                    </Card>

                    {/* 12. Carbon Footprint */}
                    {result.carbon && (
                        <Card title="Carbon Footprint" icon={Leaf} color="text-white">
                            <div className="flex items-center justify-center flex-col h-full">
                                <div className={`text-5xl font-bold mb-2 ${
                                    ['A+','A','B'].includes(result.carbon.rating) ? 'text-white' : 
                                    ['C','D'].includes(result.carbon.rating) ? 'text-white' : 'text-red-400'
                                }`}>
                                    {result.carbon.rating}
                                </div>
                                <div className="text-sm text-neutral-300 font-mono mb-1">{result.carbon.g}g CO2</div>
                            </div>
                        </Card>
                    )}

                    {/* 13. Server / IP Details */}
                    {result.ipInfo && (
                        <Card title="Server Details" icon={Wifi} color="text-[#888]">
                             <div className="space-y-3 font-mono text-xs">
                                <div className="flex justify-between border-b border-[#222] pb-1">
                                    <span className="text-[#888]">IP Address</span>
                                    <span className="text-white">{result.ipInfo.ip}</span>
                                </div>
                                <div className="flex justify-between border-b border-[#222] pb-1">
                                    <span className="text-[#888]">Threat Score</span>
                                    <span className="text-red-400">{result.ipInfo.threat.scores?.threat_score || 0}</span>
                                </div>
                                <div className="flex justify-between border-b border-[#222] pb-1">
                                    <span className="text-[#888]">Datacenter</span>
                                    <span className={result.ipInfo.threat.is_datacenter ? "text-white" : "text-[#AAA]"}>{result.ipInfo.threat.is_datacenter ? 'YES' : 'NO'}</span>
                                </div>
                                <div className="flex justify-between border-b border-[#222] pb-1">
                                    <span className="text-[#888]">Tor / Proxy</span>
                                    <span className={result.ipInfo.threat.is_tor || result.ipInfo.threat.is_proxy ? "text-red-400" : "text-[#AAA]"}>
                                        {result.ipInfo.threat.is_tor || result.ipInfo.threat.is_proxy ? 'YES' : 'NO'}
                                    </span>
                                </div>
                                
                                {/* Shodan Data */}
                                {result.ipInfo.shodan && (
                                    <div className="pt-2 mt-2 border-t border-[#222]">
                                        <div className="text-[10px] text-white font-bold mb-1 flex items-center gap-1"><Zap size={10}/> SHODAN</div>
                                        
                                        {result.ipInfo.shodan.ports.length > 0 && (
                                            <div className="flex flex-wrap gap-1 mb-2">
                                                {result.ipInfo.shodan.ports.map(p => (
                                                    <span key={p} className="text-[9px] bg-[#151515] text-neutral-300 px-1 rounded border border-[#333]">{p}</span>
                                                ))}
                                            </div>
                                        )}
                                        
                                        {result.ipInfo.shodan.vulns.length > 0 && (
                                            <div className="flex flex-wrap gap-1">
                                                {result.ipInfo.shodan.vulns.map(v => (
                                                    <span key={v} className="text-[9px] bg-red-900/20 text-red-400 px-1 rounded border border-red-500/30">{v}</span>
                                                ))}
                                            </div>
                                        )}
                                        
                                        {!result.ipInfo.shodan.ports.length && !result.ipInfo.shodan.vulns.length && (
                                            <span className="text-[#888] italic">No open ports found.</span>
                                        )}
                                    </div>
                                )}
                             </div>
                        </Card>
                    )}
                </div>
            )}
        </div>
    );
};

