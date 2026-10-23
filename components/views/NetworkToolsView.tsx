import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Search, Server, Mail, Globe, Activity, Terminal, Shield, Hash, ArrowRight, CheckCircle, XCircle, Zap, Copy, MapPin, AlertTriangle, Network, FileCode, FileText, List, ExternalLink, Play, Pause, RefreshCw, Wifi, Lock, Eye, Archive, Radio, Clock, ChevronDown, Cloud, Upload, Briefcase, Rocket, Layers, Box, Download, Share2, HardDrive, Fingerprint, Key, Flame, Siren, Map as MapIcon, ShieldAlert, CreditCard, Languages, Calendar, Cookie, Loader2, Gauge, Database, File, Radar, Plus } from 'lucide-react';
import { calculateSubnet, SubnetInfo, performRdapLookup, WhoisResult, analyzeSpf, SpfResult, analyzeDmarc, DmarcResult, analyzeHttpHeaders, HttpHeaderResult, analyzeEmailHeaders, EmailHeaderAnalysis, performPing, PingResult, performPortScan, PortResult, performCrtLookup, checkWaybackAvailability, fetchIpWhoIs, IpWhoIsResult, fetchIpApiData, IpApiIsResult, searchAsn, fetchAsnDetails, AsnSearchResult, AsnDetails, resolveIpToAsn } from '../../services/netTools';
import { queryDoH, checkRBL, resolveHostname, enrichIP, performMultiDnsLookup, checkDomainSecurity, SecurityCheckResult, EXTENDED_DNS_PROVIDERS, DetailedDnsRecord, DnsProviderConfig, DNS_RECORD_TYPES, analyzeDga, DgaResult } from '../../services/dns';
import { calculateCompositeRisk, RiskAnalysis } from '../../services/riskEngine';
import { mmdbService } from '../../services/mmdb';
import { CrtShEntry, WaybackResult, IpDataResponse, OtxAnalysis } from '../../types';
import { downloadFile, generateNetworkToolsPDF } from '../../services/exporter';
import { fetchOtxIndicator } from '../../services/otx';

type ToolCategory = 'SUPER_SCAN' | 'DNS' | 'DNS_SEC' | 'EMAIL' | 'NETWORK' | 'SUBNET' | 'HEADERS' | 'PING' | 'SCAN' | 'CRT' | 'ARCHIVE' | 'MY_IP' | 'ASN';

export const NetworkToolsView: React.FC = () => {
    const [input, setInput] = useState('');
    const [activeCategory, setActiveCategory] = useState<ToolCategory>('SUPER_SCAN');
    const [isLoading, setIsLoading] = useState(false);
    const [scanStatus, setScanStatus] = useState<string>('');
    const [error, setError] = useState<string | null>(null);

    // DNS Advanced State
    const [dnsProviderTab, setDnsProviderTab] = useState<string>('google');
    const [dnsResults, setDnsResults] = useState<Record<string, DetailedDnsRecord[]>>({});
    const [controlDProfile, setControlDProfile] = useState<string>('controld_unfiltered');
    const [securityResults, setSecurityResults] = useState<SecurityCheckResult[]>([]);
    const [dgaResult, setDgaResult] = useState<DgaResult | null>(null);

    // Risk Analysis State
    const [riskAnalysis, setRiskAnalysis] = useState<RiskAnalysis | null>(null);

    // Other Results State
    const [subnetResult, setSubnetResult] = useState<SubnetInfo | null>(null);
    const [whoisResult, setWhoisResult] = useState<WhoisResult | null>(null);
    const [spfResult, setSpfResult] = useState<SpfResult | null>(null);
    const [dmarcResult, setDmarcResult] = useState<DmarcResult | null>(null);
    const [mxRecords, setMxRecords] = useState<DetailedDnsRecord[]>([]);
    const [httpResult, setHttpResult] = useState<HttpHeaderResult | null>(null);
    const [headerResult, setHeaderResult] = useState<EmailHeaderAnalysis | null>(null);
    const [rblStatus, setRblStatus] = useState<{status: string, listed: string[]}|null>(null);
    const [crtResults, setCrtResults] = useState<CrtShEntry[]>([]);
    const [waybackResult, setWaybackResult] = useState<WaybackResult | null>(null);
    const [ipWhoIsResult, setIpWhoIsResult] = useState<IpWhoIsResult | null>(null);
    const [ipApiResult, setIpApiResult] = useState<IpApiIsResult | null>(null);
    const [enrichmentResult, setEnrichmentResult] = useState<IpDataResponse | null>(null);
    const [mailServerReputation, setMailServerReputation] = useState<any[]>([]);
    const [otxResult, setOtxResult] = useState<OtxAnalysis | null>(null);
    
    // ASN State
    const [asnResult, setAsnResult] = useState<AsnDetails | any | null>(null);
    const [asnSearchResults, setAsnSearchResults] = useState<AsnSearchResult[]>([]);
    const [asnSuggestions, setAsnSuggestions] = useState<AsnSearchResult[]>([]);
    const [showAsnSuggestions, setShowAsnSuggestions] = useState(false);

    const [pingResults, setPingResults] = useState<PingResult[]>([]);
    const [isPinging, setIsPinging] = useState(false);
    const [scanResults, setScanResults] = useState<PortResult[]>([]);
    
    const pingRef = useRef<any>(null);

    useEffect(() => {
        return () => { if (pingRef.current) clearInterval(pingRef.current); };
    }, []);

    // Auto-completion effect for ASN
    useEffect(() => {
        if (activeCategory === 'ASN' && input.trim().length > 2) {
            if (input.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) || input.toUpperCase().startsWith('AS')) {
                setShowAsnSuggestions(false);
                return;
            }

            const timeout = setTimeout(async () => {
                try {
                    const results = await searchAsn(input);
                    setAsnSuggestions(results);
                    setShowAsnSuggestions(true);
                } catch (e) {
                    setAsnSuggestions([]);
                }
            }, 300);
            return () => clearTimeout(timeout);
        } else {
            setShowAsnSuggestions(false);
        }
    }, [input, activeCategory]);

    const stopPing = () => {
        if (pingRef.current) { clearInterval(pingRef.current); pingRef.current = null; }
        setIsPinging(false);
    };

    const startPing = async (target: string) => {
        if (isPinging) return;
        setIsPinging(true);
        setPingResults([]);
        let seq = 1;
        const doPing = async () => {
            const res = await performPing(target, seq++);
            setPingResults(prev => [...prev, res].slice(-20));
        };
        doPing();
        pingRef.current = setInterval(doPing, 1000);
    };

    const runDnsLookup = async (target: string) => {
        const providers = EXTENDED_DNS_PROVIDERS.filter(p => !p.id.includes('security') && !p.category);
        const resultsMap: Record<string, DetailedDnsRecord[]> = {};
        
        providers.forEach(p => resultsMap[p.id] = []);
        setDnsResults(resultsMap);

        const promises = providers.map(async (provider) => {
            const lookups = DNS_RECORD_TYPES.map(type => performMultiDnsLookup(target, type, provider));
            const results = await Promise.all(lookups);
            
            // Filter out failed lookups (nulls) and flatten
            const validResults = results.filter(r => r !== null) as DetailedDnsRecord[][];
            const flatResults = validResults.flat();
            
            setDnsResults(prev => ({
                ...prev,
                [provider.id]: flatResults
            }));
        });

        await Promise.all(promises);
        
        if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
             const rbl = await checkRBL(target);
             setRblStatus({ status: rbl.status, listed: rbl.listedIn });
        }
    };

    const handleSelectAsn = async (asn: string) => {
        setIsLoading(true);
        setAsnSearchResults([]);
        try {
            const details = await fetchAsnDetails(asn);
            if (details) setAsnResult(details);
            else throw new Error("ASN details not found.");
        } catch (e) {
            setError("Failed to fetch ASN details.");
        } finally {
            setIsLoading(false);
        }
    };

    const handleSuggestionClick = (item: AsnSearchResult) => {
        setInput(item.asn);
        setShowAsnSuggestions(false);
        handleSelectAsn(item.asn);
    };

    const handleRunTool = async (e?: React.FormEvent) => {
        if (e) e.preventDefault();
        setShowAsnSuggestions(false);
        
        if (activeCategory === 'PING') {
            if (isPinging) stopPing();
            else if (input) startPing(input.trim());
            return;
        }

        if (activeCategory !== 'MY_IP' && !input) return;

        setIsLoading(true);
        setError(null);
        setScanStatus('Initializing...');
        
        // Reset all result states
        setSubnetResult(null); setWhoisResult(null); setSpfResult(null); setDmarcResult(null);
        setMxRecords([]); setHttpResult(null); setHeaderResult(null); setRblStatus(null);
        setScanResults([]); setCrtResults([]); setWaybackResult(null);
        setIpWhoIsResult(null); setIpApiResult(null); setEnrichmentResult(null);
        setAsnResult(null); setAsnSearchResults([]); setSecurityResults([]); setDgaResult(null);
        setMailServerReputation([]); setRiskAnalysis(null); setOtxResult(null);
        setDnsResults({});
        
        const target = input.trim();
        // Remove protocol if present
        const cleanTarget = target.replace(/^https?:\/\//, '').replace(/\/$/, '');
        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(cleanTarget.split('/')[0]);
        const isCidr = target.includes('/');

        try {
            if (activeCategory === 'SUPER_SCAN') {
                let resolvedIp = isIp ? cleanTarget : null;
                setScanStatus('Resolving Hostname...');
                
                // 1. DNS Resolution (if domain) - Critical first step to get IP
                if (!isIp && !resolvedIp) {
                    try {
                        const dnsRes = await queryDoH(cleanTarget, 'A');
                        if (dnsRes?.Answer?.[0]?.data) resolvedIp = dnsRes.Answer[0].data;
                    } catch(e) {}
                }

                // Track current state locally to pass to refreshRisk (React state updates are async)
                let currentIpData: IpDataResponse | null = null;
                let currentSecurity: SecurityCheckResult[] = [];
                let currentHttp: HttpHeaderResult | null = null;
                let currentWhois: WhoisResult | null = null;

                const updateRisk = () => {
                    const analysis = calculateCompositeRisk(cleanTarget, currentIpData, currentSecurity, currentHttp, currentWhois);
                    setRiskAnalysis(analysis);
                };

                // Initialize risk with empty data so UI shows up immediately
                updateRisk();

                const tasks: Promise<void>[] = [];

                // Task: IP Enrichment
                if (resolvedIp) {
                    tasks.push(
                        enrichIP(resolvedIp).then(data => {
                            setEnrichmentResult(data);
                            currentIpData = data;
                            setScanStatus("Enriched IP Data...");
                            updateRisk();
                        }).catch(() => console.warn("IP Enrich failed"))
                    );
                    
                    // Background tasks (don't block risk recalc immediately)
                    checkRBL(resolvedIp).then(r => setRblStatus({ status: r.status, listed: r.listedIn })).catch(()=>{});
                    performPortScan(resolvedIp).then(setScanResults).catch(()=>{});
                }

                // Task: Security Checks
                tasks.push(
                    checkDomainSecurity(cleanTarget).then(sec => {
                        setSecurityResults(sec);
                        currentSecurity = sec;
                        setScanStatus("Threat Intelligence Checked...");
                        updateRisk();
                    })
                );

                // Task: Whois
                tasks.push(
                    performRdapLookup(cleanTarget, isIp ? 'IP' : 'DOMAIN').then(w => {
                        setWhoisResult(w);
                        currentWhois = w;
                        setScanStatus("Registration Data Loaded...");
                        updateRisk();
                    })
                );
                
                // Task: OTX Intelligence
                tasks.push(
                    fetchOtxIndicator(cleanTarget).then(otx => {
                        setOtxResult(otx);
                        setScanStatus("AlienVault Data Loaded...");
                    }).catch(() => {})
                );

                // Task: HTTP & Domain specific
                if (!isIp) {
                    tasks.push(
                        analyzeHttpHeaders(cleanTarget).then(h => {
                            setHttpResult(h);
                            currentHttp = h;
                            setScanStatus("HTTP Headers Analyzed...");
                            updateRisk();
                        })
                    );
                    
                    performCrtLookup(cleanTarget).then(res => {
                         const unique = Array.from(new Map(res.map(item => [item.id, item])).values());
                         setCrtResults(unique.sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime()));
                    }).catch(() => {});
                    
                    checkWaybackAvailability(cleanTarget).then(setWaybackResult).catch(() => {});
                    analyzeSpf(cleanTarget).then(setSpfResult).catch(() => {});
                    analyzeDmarc(cleanTarget).then(setDmarcResult).catch(() => {});
                    
                    runDnsLookup(cleanTarget); 
                    queryDoH(cleanTarget, 'MX').then(mxRes => {
                        if (mxRes && mxRes.Answer) {
                            setMxRecords(mxRes.Answer.map((a: any) => ({ type: 'MX', name: a.name, ttl: a.TTL, data: a.data.replace(/"/g, ''), provider: 'Google' })));
                        }
                    }).catch(() => {});
                    
                    setDgaResult(analyzeDga(cleanTarget));
                } else {
                    setScanStatus("Analyzing IP Address...");
                }

                await Promise.allSettled(tasks);
                setScanStatus("Scan Complete");
                setIsLoading(false);

            } else if (activeCategory === 'DNS') {
                await runDnsLookup(target);
                setIsLoading(false);
            } else if (activeCategory === 'DNS_SEC') {
                const results = await checkDomainSecurity(target);
                setSecurityResults(results);
                if (!isIp) {
                    setDgaResult(analyzeDga(target));
                }
                setIsLoading(false);
            } else if (activeCategory === 'MY_IP') {
                const res = await fetchIpWhoIs();
                setIpWhoIsResult(res);
                setIsLoading(false);
            } else if (activeCategory === 'ASN') {
                let asnToLookup = target.toUpperCase();
                let isSearch = true;

                if (isIp) {
                    try {
                        const res = await resolveIpToAsn(target);
                        if (res) {
                            asnToLookup = res;
                            isSearch = false;
                        } else {
                            throw new Error("Could not resolve IP to ASN.");
                        }
                    } catch(e) {
                        throw new Error("IP resolution failed.");
                    }
                } else if (/^(AS)?\d+$/.test(asnToLookup)) {
                    isSearch = false;
                    if (!asnToLookup.startsWith('AS')) asnToLookup = `AS${asnToLookup}`;
                }

                if (!isSearch) {
                    try {
                        const details = await fetchAsnDetails(asnToLookup);
                        if (details) setAsnResult(details);
                        else throw new Error("ASN details not found.");
                    } catch(e) {
                        throw new Error("Failed to fetch ASN details.");
                    }
                } else {
                    const results = await searchAsn(target);
                    if (results.length === 0) throw new Error("No ASNs found for this name.");
                    
                    const exactMatch = results.find(r => r.asn === target.toUpperCase() || r.name.toLowerCase() === target.toLowerCase());
                    if (exactMatch) {
                         const details = await fetchAsnDetails(exactMatch.asn);
                         if (details) setAsnResult(details);
                         else setAsnSearchResults(results);
                    } else {
                        setAsnSearchResults(results);
                    }
                }
                setIsLoading(false);
            } else if (activeCategory === 'SUBNET') {
                const cidrInput = isCidr ? target : (isIp ? `${target}/24` : null);
                if (!cidrInput) throw new Error("Please enter a valid IP or CIDR");
                const res = calculateSubnet(cidrInput);
                if (res) setSubnetResult(res);
                else throw new Error("Invalid network format");
                setIsLoading(false);
            } else if (activeCategory === 'EMAIL') {
                if (isIp) throw new Error("Email checks require a domain.");
                const mxRes = await queryDoH(target, 'MX');
                let mxRecs: any[] = [];
                if (mxRes && mxRes.Answer) {
                    mxRecs = mxRes.Answer.map((a: any) => ({ type: 'MX', name: a.name, ttl: a.TTL, data: a.data.replace(/"/g, ''), provider: 'Google' }));
                    setMxRecords(mxRecs);
                }
                const spf = await analyzeSpf(target);
                setSpfResult(spf);
                const dmarc = await analyzeDmarc(target);
                setDmarcResult(dmarc);
                const security = await checkDomainSecurity(target);
                setSecurityResults(security);
                if (mxRecs.length > 0) {
                    mxRecs.slice(0, 5).forEach(async (mx) => {
                        try {
                            const parts = mx.data.split(' ');
                            const hostname = parts.length > 1 ? parts[1] : parts[0];
                            if (hostname) {
                                const ipRes = await queryDoH(hostname, 'A');
                                if (ipRes?.Answer?.[0]?.data) {
                                    const ip = ipRes.Answer[0].data;
                                    const rbl = await checkRBL(ip);
                                    const geo = await enrichIP(ip);
                                    setMailServerReputation(prev => {
                                        if (prev.some(p => p.ip === ip)) return prev;
                                        return [...prev, {
                                            hostname,
                                            ip,
                                            rbl: rbl.status,
                                            country: geo?.country_code || 'XX',
                                            score: geo?.threat.scores?.threat_score || 0,
                                            flag: geo?.flag
                                        }];
                                    });
                                }
                            }
                        } catch(e) {}
                    });
                }
                setIsLoading(false);

            } else if (activeCategory === 'NETWORK') {
                if (isIp) {
                    const res = await fetchIpApiData(target);
                    setIpApiResult(res);
                } else {
                    const rdap = await performRdapLookup(target, 'DOMAIN');
                    setWhoisResult(rdap);
                }
                setIsLoading(false);
            } else if (activeCategory === 'HEADERS') {
                const analysis = analyzeEmailHeaders(input);
                setHeaderResult(analysis);
                setIsLoading(false);
            } else if (activeCategory === 'SCAN') {
                let ipToScan = target;
                if (!isIp) {
                    const dns = await queryDoH(target, 'A');
                    if (dns?.Answer?.[0]?.data) ipToScan = dns.Answer[0].data;
                }
                const ports = await performPortScan(ipToScan);
                if (ports.length === 0) throw new Error("No open ports found in DB.");
                setScanResults(ports);
                setIsLoading(false);
            } else if (activeCategory === 'CRT') {
                if (isIp) throw new Error("Certificate logs require a domain.");
                const logs = await performCrtLookup(target);
                if (logs.length === 0) throw new Error("No certificates found.");
                const unique = Array.from(new Map(logs.map(item => [item.id, item])).values());
                setCrtResults(unique.sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime()));
                setIsLoading(false);
            } else if (activeCategory === 'ARCHIVE') {
                const result = await checkWaybackAvailability(target);
                if (result) setWaybackResult(result);
                else throw new Error("Wayback lookup failed.");
                setIsLoading(false);
            }
        } catch (err: any) {
            setError(err.message || "Operation failed.");
            setIsLoading(false);
        }
    };

    const handleExportReport = () => {
        let content = '';
        const timestamp = new Date().toLocaleString();
        const sep = "--------------------------------------------------";

        content += `ANTI.AI NETWORK TOOL REPORT\n`;
        content += `Module: ${activeCategory}\n`;
        content += `Target: ${input || 'N/A'}\n`;
        content += `Generated: ${timestamp}\n${sep}\n\n`;

        if (activeCategory === 'SUPER_SCAN' && riskAnalysis) {
            content += `[RISK ANALYSIS]\n`;
            content += `Verdict: ${riskAnalysis.verdict}\n`;
            content += `Score: ${riskAnalysis.score}/100\n`;
            content += `Factors:\n`;
            riskAnalysis.factors.forEach(f => content += `- [${f.type}] ${f.label} (${f.impact > 0 ? '+' + f.impact : f.impact})\n`);
            content += `\n`;
        }

        if (activeCategory === 'ASN' && asnResult) {
            content += `ASN: ${asnResult.asn}\nName: ${asnResult.name}\nDescription: ${asnResult.description}\nCountry: ${asnResult.country_code}\n`;
            content += `Peers: ${asnResult.peers} | Upstreams: ${asnResult.upstreams} | Downstreams: ${asnResult.downstreams}\n\n[PREFIXES]\n`;
            asnResult.prefixes.forEach((p: any) => content += `${p.prefix} (${p.description})\n`);
        } else if (activeCategory === 'DNS') {
            Object.keys(dnsResults).forEach(provider => {
                content += `[PROVIDER: ${provider.toUpperCase()}]\n`;
                dnsResults[provider].forEach(r => content += `${r.type.padEnd(5)} | ${r.name.padEnd(30)} | ${r.data}\n`);
                content += '\n';
            });
        } else if (activeCategory === 'EMAIL') {
            content += `[MX RECORDS]\n`;
            mxRecords.forEach(mx => content += `${mx.data} (TTL: ${mx.ttl})\n`);
            content += `\n[SPF]\nRaw: ${spfResult?.raw || 'None'}\nValid: ${spfResult?.valid}\n`;
            content += `\n[DMARC]\nRaw: ${dmarcResult?.raw || 'None'}\nPolicy: ${dmarcResult?.policy}\n`;
        } else if (activeCategory === 'SUBNET' && subnetResult) {
            content += `Network: ${subnetResult.networkAddress}\nBroadcast: ${subnetResult.broadcastAddress}\nNetmask: ${subnetResult.netmask}\nHost Range: ${subnetResult.firstHost} - ${subnetResult.lastHost}\nTotal Hosts: ${subnetResult.totalHosts}\n`;
        } else if (activeCategory === 'PING') {
            pingResults.forEach(p => content += `SEQ ${p.seq}: ${p.status} (${p.time}ms) from ${p.ip}\n`);
        } else if (activeCategory === 'SCAN') {
            scanResults.forEach(p => content += `Port ${p.port}/${p.transport}: ${p.service}\n`);
        } else if (activeCategory === 'CRT') {
            crtResults.forEach(c => content += `${c.entry_timestamp} | ${c.common_name} | ${c.issuer_name}\n`);
        } else if (activeCategory === 'SUPER_SCAN') {
            if (enrichmentResult) content += `[IDENTITY]\nIP: ${enrichmentResult.ip}\nOrg: ${enrichmentResult.asn?.name}\nLoc: ${enrichmentResult.city}, ${enrichmentResult.country_name}\n\n`;
            if (securityResults.length > 0) {
                content += `[SECURITY CHECKS]\n`;
                securityResults.forEach(s => content += `${s.provider}: ${s.status}\n`);
                content += '\n';
            }
            if (httpResult) content += `[HTTP]\nServer: ${httpResult.serverInfo.server}\nHeaders: ${Object.keys(httpResult.headers).length} captured\n`;
            if (otxResult) {
                 content += `\n[ALIENVAULT OTX]\nPulses: ${otxResult.pulse_count}\nTags: ${otxResult.tags.join(', ')}\nMalware: ${otxResult.malware_families.join(', ')}\n`;
            }
        }

        downloadFile(content, `net_report_${activeCategory}_${Date.now()}.txt`, 'text/plain');
    };

    const handleExportPdf = () => {
        const data = {
            riskAnalysis,
            dnsResults,
            enrichmentResult,
            securityResults,
            httpResult
        };
        generateNetworkToolsPDF(activeCategory, input || 'N/A', data);
    };

    // Helper functions for rendering parts of the UI
    const renderDnsTab = (id: string, label: string, icon?: any) => {
        const isActive = dnsProviderTab === id || (id === 'controld' && dnsProviderTab.startsWith('controld'));
        return (
            <button 
                onClick={() => setDnsProviderTab(id === 'controld' ? controlDProfile : id)}
                className={`px-4 py-2 text-xs font-bold flex items-center gap-2 transition-all border-b-2 ${isActive ? 'border-red-500 text-white bg-white/5' : 'border-transparent text-[#888] hover:text-neutral-300'}`}
            >
                {icon && icon} {label}
            </button>
        );
    };

    const renderDnsTable = () => {
        const currentId = dnsProviderTab.startsWith('controld') ? dnsProviderTab : dnsProviderTab;
        const records = dnsResults[currentId] || [];
        if (records.length === 0) return <div className="p-8 text-center text-[#888] text-xs italic">No records found. Run a scan to populate.</div>;
        return (
            <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-[#111] text-[#888] uppercase font-bold">
                        <tr><th className="p-3">Type</th><th className="p-3">Name</th><th className="p-3">TTL</th><th className="p-3">Data</th></tr>
                    </thead>
                    <tbody className="divide-y divide-neutral-800 text-neutral-300">
                        {records.map((rec, idx) => (
                            <tr key={idx} className="hover:bg-white/5 transition-colors">
                                <td className="p-3 font-bold text-red-500">{rec.type}</td><td className="p-3">{rec.name}</td><td className="p-3 text-[#888]">{rec.ttl}</td><td className="p-3 break-all">{rec.data}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    };

    // Helper for rendering My IP results
    const renderMyIpTool = () => {
        if (!ipWhoIsResult && !isLoading) return <div className="flex flex-col items-center justify-center h-64 text-center animate-fade-in border border-[#222] border-dashed rounded-xl bg-[#111]/20 m-4"><div className="w-16 h-16 rounded-full bg-red-900/10 border border-red-500/20 flex items-center justify-center mb-4"><Search size={24} className="text-red-500 opacity-80" /></div><h3 className="text-white font-cyber text-lg mb-2">IDENTITY TRACING</h3><p className="text-neutral-500 text-sm max-w-md">Click MY IP to securely trace your current network identity and location exposure.</p></div>;
        if (!ipWhoIsResult) return null;

        return (
            <div className="space-y-6 animate-fade-in">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                        <h3 className="text-sm font-bold text-white mb-4 uppercase flex items-center gap-2">
                            <Server size={16} className="text-red-400"/> My Connection
                        </h3>
                        <div className="space-y-2 text-xs font-mono text-neutral-300">
                            <div className="flex justify-between border-b border-[#222] pb-1"><span>IP Address</span> <span className="text-white font-bold">{ipWhoIsResult.ip}</span></div>
                            <div className="flex justify-between border-b border-[#222] pb-1"><span>ISP</span> <span className="text-red-400">{ipWhoIsResult.connection.isp}</span></div>
                            <div className="flex justify-between border-b border-[#222] pb-1"><span>Org</span> <span className="truncate max-w-[200px]">{ipWhoIsResult.connection.org}</span></div>
                            <div className="flex justify-between border-b border-[#222] pb-1"><span>ASN</span> <span>AS{ipWhoIsResult.connection.asn}</span></div>
                        </div>
                    </div>
                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                        <h3 className="text-sm font-bold text-white mb-4 uppercase flex items-center gap-2">
                            <MapIcon size={16} className="text-white"/> Physical Location
                        </h3>
                        <div className="space-y-2 text-xs font-mono text-neutral-300">
                            <div className="flex justify-between border-b border-[#222] pb-1"><span>City</span> <span>{ipWhoIsResult.city}</span></div>
                            <div className="flex justify-between border-b border-[#222] pb-1">
                                <span>Country</span> 
                                <span className="flex items-center gap-2">
                                    {ipWhoIsResult.flag?.img && <img src={ipWhoIsResult.flag.img} className="w-4 h-3 rounded-sm" alt="flag"/>}
                                    {ipWhoIsResult.country} ({ipWhoIsResult.country_code})
                                </span>
                            </div>
                            <div className="flex justify-between border-b border-[#222] pb-1"><span>Coordinates</span> <span>{ipWhoIsResult.latitude}, {ipWhoIsResult.longitude}</span></div>
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    // Helper for rendering Network/Whois tool results
    const renderNetworkTool = () => {
        if (!ipApiResult && !whoisResult && !isLoading) return <div className="flex flex-col items-center justify-center h-64 text-center animate-fade-in border border-[#222] border-dashed rounded-xl bg-[#111]/20 m-4"><div className="w-16 h-16 rounded-full bg-red-900/10 border border-red-500/20 flex items-center justify-center mb-4"><Search size={24} className="text-red-500 opacity-80" /></div><h3 className="text-white font-cyber text-lg mb-2">WHOIS & IP INTELLIGENCE</h3><p className="text-neutral-500 text-sm max-w-md">Enter an IP address or Domain above to retrieve ownership, registration, and network routing information.</p></div>;

        return (
            <div className="space-y-6 animate-fade-in">
                {ipApiResult && (
                    <>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                <h3 className="text-sm font-bold text-white mb-4 uppercase flex items-center gap-2">
                                    <Server size={16} className="text-red-400"/> Network Identity
                                </h3>
                                <div className="space-y-2 text-xs font-mono text-neutral-300">
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>IP</span> <span className="text-white">{ipApiResult.ip}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>ASN</span> <span className="text-red-400">AS{ipApiResult.asn?.asn ?? "-"}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Org</span> <span className="truncate max-w-[200px]">{ipApiResult.asn?.org}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Route</span> <span>{ipApiResult.asn?.domain}</span></div>
                                </div>
                            </div>
                            <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                <h3 className="text-sm font-bold text-white mb-4 uppercase flex items-center gap-2">
                                    <MapIcon size={16} className="text-white"/> Location & Abuse
                                </h3>
                                <div className="space-y-2 text-xs font-mono text-neutral-300">
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>City</span> <span>{ipApiResult.location?.city}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Country</span> <span>{ipApiResult.location?.country} ({ipApiResult.location?.country_code})</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Timezone</span> <span>{ipApiResult.location?.timezone}</span></div>
                                    {ipApiResult.abuse && (
                                        <div className="mt-2 pt-2 border-t border-[#222]">
                                            <div className="text-[#888] mb-1">Abuse Contact</div>
                                            <div className="text-red-400">{ipApiResult.abuse.email}</div>
                                            <div className="text-[#888]">{ipApiResult.abuse.phone}</div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                        {ipApiResult.whois?.text && (
                            <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                <h3 className="text-sm font-bold text-white mb-2 uppercase flex items-center gap-2">
                                    <FileText size={16} className="text-[#AAA]"/> Raw WHOIS
                                </h3>
                                <div className="h-64 overflow-y-auto custom-scrollbar bg-[#111] p-4 rounded border border-[#222] text-[10px] font-mono text-[#AAA] whitespace-pre-wrap">
                                    {ipApiResult.whois?.text}
                                </div>
                            </div>
                        )}
                    </>
                )}

                {whoisResult && (
                    <div className="space-y-6">
                        <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                            <h3 className="text-sm font-bold text-white mb-4 uppercase flex items-center gap-2">
                                <Globe size={16} className="text-red-400"/> Domain Registration (RDAP)
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs font-mono text-neutral-300">
                                <div className="space-y-2">
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Name</span> <span className="text-white">{whoisResult.name}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Handle</span> <span>{whoisResult.handle}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Registrar</span> <span className="text-red-500">{whoisResult.org}</span></div>
                                </div>
                                <div className="space-y-2">
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Registered</span> <span>{whoisResult.registrationDate}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Updated</span> <span>{whoisResult.lastChangedDate}</span></div>
                                    <div className="flex justify-between border-b border-[#222] pb-1"><span>Status</span> <span>Active</span></div>
                                </div>
                            </div>
                            {whoisResult.address && whoisResult.address.length > 0 && (
                                <div className="mt-4 pt-4 border-t border-[#222]">
                                    <div className="text-[#888] mb-1">Registrant Address</div>
                                    <div className="text-[#AAA]">{whoisResult.address.join(', ')}</div>
                                </div>
                            )}
                        </div>
                        
                        <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                            <h3 className="text-sm font-bold text-white mb-4 uppercase flex items-center gap-2">
                                <List size={16} className="text-[#AAA]"/> Registration Events
                            </h3>
                            <div className="space-y-1 max-h-48 overflow-y-auto custom-scrollbar">
                                {whoisResult.events.map((e: any, i: number) => (
                                    <div key={i} className="flex justify-between text-xs text-[#AAA] p-2 hover:bg-white/5 rounded border border-transparent hover:border-[#222]">
                                        <span className="capitalize">{e.eventAction}</span>
                                        <span className="font-mono text-white">{new Date(e.eventDate).toLocaleDateString()}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="h-[calc(100vh-70px)] bg-cyber-grid flex flex-col relative overflow-hidden">
            {/* Header */}
            <div className="p-4 border-b border-[#222] bg-[#111]/40 shrink-0">
                <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-neutral-900/20 rounded-lg border border-neutral-500/30 text-red-400">
                        <HardDrive size={20}/>
                    </div>
                    <div>
                        <h2 className="text-lg font-bold text-white font-cyber flex items-center gap-2">
                            NETWORK <span className="text-red-500">UTILITIES</span>
                        </h2>
                        <p className="text-xs text-[#888] font-mono">Diagnostics & Reconnaissance Suite</p>
                    </div>
                </div>

                <div className="flex flex-wrap gap-2">
                    <button onClick={() => setActiveCategory('SUPER_SCAN')} className={`px-4 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'SUPER_SCAN' ? 'bg-[#1a0f0f] border border-red-500 text-red-500 shadow-lg shadow-red-900/20' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>SUPER SCAN</button>
                    <button onClick={() => setActiveCategory('DNS')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'DNS' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>DNS LOOKUP</button>
                    <button onClick={() => setActiveCategory('DNS_SEC')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'DNS_SEC' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>DNS FIREWALL</button>
                    <button onClick={() => setActiveCategory('NETWORK')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'NETWORK' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>WHOIS/IP</button>
                    <button onClick={() => setActiveCategory('EMAIL')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'EMAIL' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>EMAIL SEC</button>
                    <button onClick={() => setActiveCategory('ASN')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'ASN' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>ASN INTEL</button>
                    <button onClick={() => setActiveCategory('CRT')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'CRT' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>CERT LOGS</button>
                    <button onClick={() => setActiveCategory('SCAN')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'SCAN' ? 'bg-[#1a0f0f] border border-red-500/30 text-red-500' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>PORT SCAN</button>
                    <div className="h-8 w-px bg-[#1C1C1C] mx-2 hidden md:block"></div>
                    <button onClick={() => setActiveCategory('PING')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'PING' ? 'bg-white text-black' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>PING</button>
                    <button onClick={() => setActiveCategory('SUBNET')} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'SUBNET' ? 'bg-white text-black' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>CALC</button>
                    <button onClick={() => { setActiveCategory('MY_IP'); handleRunTool(); }} className={`px-3 py-2 rounded text-xs font-bold transition-all ${activeCategory === 'MY_IP' ? 'bg-white text-black' : 'bg-[#151515] text-[#888] border border-[#333] hover:text-white'}`}>MY IP</button>
                </div>
            </div>

            {/* Main Content */}
            <div className="flex-1 overflow-hidden relative flex flex-col p-6 max-w-7xl mx-auto w-full">
                
                {/* Input Bar */}
                {activeCategory !== 'MY_IP' && activeCategory !== 'HEADERS' && (
                    <form onSubmit={handleRunTool} className="mb-8 relative group max-w-2xl mx-auto w-full">
                        <div className="absolute inset-0 bg-gradient-to-r from-red-600 to-red-900 rounded-lg blur opacity-20 group-hover:opacity-40 transition-opacity"></div>
                        <div className="relative flex items-center bg-[#111] border border-[#333] rounded-lg overflow-hidden shadow-2xl">
                            <div className="pl-4 text-[#888]">
                                {isLoading ? <RefreshCw className="animate-spin" size={18}/> : <Terminal size={18}/>}
                            </div>
                            <input 
                                type="text" 
                                className="flex-1 bg-transparent border-none text-white px-4 py-3 focus:ring-0 placeholder-neutral-600 font-mono text-sm"
                                placeholder={
                                    activeCategory === 'ASN' ? 'Enter ASN (AS13335) or Organization Name...' :
                                    activeCategory === 'SUBNET' ? 'Enter CIDR (192.168.1.0/24)...' :
                                    activeCategory === 'SUPER_SCAN' ? 'Enter Domain or IP for deep analysis...' :
                                    'Enter target (domain, IP, or URL)...'
                                }
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                            />
                            <button 
                                type="submit"
                                disabled={isLoading || (!input && activeCategory !== 'PING')} // PING can re-trigger stop
                                className="bg-[#151515] hover:bg-[#1C1C1C] text-white px-6 py-3 font-bold text-xs transition-colors border-l border-[#333] flex items-center gap-2"
                            >
                                {isPinging ? <Pause size={14}/> : <Play size={14}/>} RUN
                            </button>
                        </div>
                        {error && (
                            <div className="absolute top-full left-0 right-0 mt-2 p-2 bg-red-900/80 text-red-200 text-xs rounded border border-red-500/50 backdrop-blur-sm animate-fade-in flex items-center gap-2">
                                <AlertTriangle size={12}/> {error}
                            </div>
                        )}

                        {/* ASN Suggestions Dropdown */}
                        {showAsnSuggestions && asnSuggestions.length > 0 && (
                            <div className="absolute top-full left-0 right-0 mt-1 bg-[#111] border border-[#333] rounded-lg shadow-xl z-50 max-h-60 overflow-y-auto custom-scrollbar">
                                {asnSuggestions.map((item) => (
                                    <button
                                        key={item.asn}
                                        type="button"
                                        onClick={() => handleSuggestionClick(item)}
                                        className="w-full text-left px-4 py-2 hover:bg-[#151515] border-b border-[#222] last:border-0 transition-colors group"
                                    >
                                        <div className="flex justify-between items-center">
                                            <span className="font-bold text-red-500 text-xs">{item.asn}</span>
                                            <span className="text-[10px] bg-[#151515] px-1.5 rounded text-[#AAA]">{item.country_code}</span>
                                        </div>
                                        <div className="text-xs text-neutral-300 truncate font-bold">{item.name}</div>
                                        <div className="text-[10px] text-[#888] truncate">{item.description_short}</div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </form>
                )}

                {activeCategory === 'HEADERS' && (
                    <div className="flex flex-col gap-4 h-full">
                        <textarea 
                            className="flex-1 bg-[#111]/50 border border-[#333] rounded-lg p-4 font-mono text-xs text-neutral-300 focus:border-red-500 focus:outline-none resize-none custom-scrollbar"
                            placeholder="Paste raw email headers here..."
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                        />
                        <button 
                            onClick={() => handleRunTool()}
                            className="bg-neutral-600 hover:bg-neutral-500 text-white py-3 rounded-lg font-bold text-sm shadow-lg shadow-green-900/20 transition-all"
                        >
                            ANALYZE HEADERS
                        </button>
                    </div>
                )}

                <div className="flex-1 overflow-y-auto custom-scrollbar space-y-6 pb-20">
                    
                    {/* SUPER SCAN DASHBOARD */}
                    {activeCategory === 'SUPER_SCAN' && (
                        (riskAnalysis || isLoading) ? (
                            <div className="space-y-6 animate-slide-in-up">
                                {/* Progress Bar / Status Text */}
                                {isLoading && (
                                    <div className="flex items-center gap-3 bg-[#111] border border-red-500/30 p-3 rounded-lg animate-pulse">
                                        <Loader2 className="animate-spin text-red-400" size={18} />
                                        <span className="text-sm font-mono text-red-300">{scanStatus}</span>
                                    </div>
                                )}

                                {/* Summary Card */}
                                {riskAnalysis && (
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5 flex flex-col items-center justify-center text-center">
                                        <div className="text-xs font-bold text-[#888] uppercase tracking-widest mb-2">Composite Risk</div>
                                        <div className={`text-5xl font-cyber font-bold mb-2 ${
                                            riskAnalysis.level === 'CRITICAL' ? 'text-red-500' : 
                                            riskAnalysis.level === 'HIGH' ? 'text-white' :
                                            riskAnalysis.level === 'MEDIUM' ? 'text-white' : 'text-white'
                                        }`}>
                                            {riskAnalysis.score}
                                        </div>
                                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                            riskAnalysis.level === 'CRITICAL' ? 'bg-red-900/20 border-red-500/30 text-red-400' : 
                                            riskAnalysis.level === 'HIGH' ? 'bg-neutral-900/20 border-neutral-500/30 text-white' :
                                            riskAnalysis.level === 'MEDIUM' ? 'bg-neutral-900/20 border-neutral-500/30 text-white' : 'bg-neutral-900/20 border-neutral-500/30 text-white'
                                        }`}>
                                            {riskAnalysis.verdict.toUpperCase()}
                                        </span>
                                    </div>
                                    
                                    <div className="md:col-span-2 bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <div className="flex items-center gap-4 mb-4">
                                            {enrichmentResult?.flag && <img src={enrichmentResult.flag} className="w-8 h-6 rounded shadow-sm" alt="flag"/>}
                                            <div>
                                                <div className="text-xl font-bold text-white">{input}</div>
                                                <div className="text-xs text-[#AAA]">{enrichmentResult?.ip ? `Resolves to: ${enrichmentResult.ip}` : 'Resolving...'}</div>
                                            </div>
                                        </div>
                                        
                                        <div className="grid grid-cols-1 gap-2 max-h-32 overflow-y-auto custom-scrollbar">
                                            {riskAnalysis.factors.map((factor, i) => (
                                                <div key={i} className={`flex items-center gap-2 text-xs p-1.5 rounded ${
                                                    factor.type === 'NEGATIVE' ? 'bg-red-900/10 text-red-300' : 
                                                    factor.type === 'POSITIVE' ? 'bg-neutral-900/10 text-white' : 'bg-[#151515] text-[#AAA]'
                                                }`}>
                                                    {factor.type === 'NEGATIVE' ? <AlertTriangle size={12}/> : factor.type === 'POSITIVE' ? <CheckCircle size={12}/> : <Activity size={12}/>}
                                                    <span>{factor.label}</span>
                                                    {factor.impact !== 0 && <span className="ml-auto font-mono opacity-70">{factor.impact > 0 ? '+' : ''}{factor.impact}</span>}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                                )}

                                {/* Detailed Information Grid */}
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                    {/* Domain Info */}
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <h3 className="text-sm font-bold text-red-400 uppercase mb-4 flex items-center gap-2">
                                            <Globe size={16}/> Domain Intelligence
                                        </h3>
                                        {whoisResult ? (
                                            <div className="space-y-2 text-xs font-mono text-neutral-300">
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Registrar</span> <span className="text-white truncate max-w-[200px]">{whoisResult.org}</span></div>
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Created</span> <span>{whoisResult.registrationDate}</span></div>
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Expires</span> <span>{
                                                    whoisResult.events?.find((e: any) => e.eventAction === 'expiration')?.eventDate ? new Date(whoisResult.events.find((e: any) => e.eventAction === 'expiration').eventDate).toLocaleDateString() : 'Unknown'
                                                }</span></div>
                                                
                                                {/* Expandable Raw Whois */}
                                                <div className="mt-4">
                                                    <div className="text-[10px] text-[#888] uppercase font-bold mb-1">Raw Whois Data</div>
                                                    <div className="max-h-32 overflow-y-auto custom-scrollbar bg-[#111] p-2 rounded border border-[#222] text-[10px] text-[#888] whitespace-pre-wrap">
                                                        {whoisResult.raw?.handle ? JSON.stringify(whoisResult.raw, null, 2) : "No raw data."}
                                                    </div>
                                                </div>
                                            </div>
                                        ) : <div className="text-[#888] text-xs italic">{isLoading ? "Loading WHOIS..." : "No WHOIS data available."}</div>}
                                    </div>

                                    {/* Infrastructure & DNS */}
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <h3 className="text-sm font-bold text-red-400 uppercase mb-4 flex items-center gap-2">
                                            <Server size={16}/> Infrastructure & DNS
                                        </h3>
                                        {enrichmentResult ? (
                                            <div className="space-y-2 text-xs font-mono text-neutral-300 mb-4">
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Hosting Org</span> <span className="text-white truncate max-w-[200px]">{enrichmentResult.asn?.name || 'N/A'}</span></div>
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>ASN</span> <span className="text-red-500">{enrichmentResult.asn?.asn || 'N/A'}</span></div>
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Location</span> <span>{enrichmentResult.city}, {enrichmentResult.country_name}</span></div>
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Type</span> <span>{enrichmentResult.threat.is_datacenter ? 'Datacenter' : 'Residential/ISP'}</span></div>
                                            </div>
                                        ) : <div className="text-[#888] text-xs italic mb-4">{isLoading ? "Enriching IP..." : "No infrastructure data."}</div>}
                                        
                                        <div className="bg-[#111] p-2 rounded border border-[#222]">
                                            <div className="text-[10px] text-[#888] uppercase font-bold mb-1">Resolved Records</div>
                                            <div className="text-[10px] font-mono text-[#AAA] space-y-1">
                                                {dnsResults.google?.slice(0, 5).map((r, i) => (
                                                    <div key={i} className="flex gap-2">
                                                        <span className={`w-8 font-bold ${r.type === 'A' ? 'text-red-400' : r.type === 'MX' ? 'text-white' : 'text-[#888]'}`}>{r.type}</span>
                                                        <span className="break-all">{r.data}</span>
                                                    </div>
                                                ))}
                                                {!dnsResults.google?.length && <span className="italic">{isLoading ? "Querying DNS..." : "No records found."}</span>}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Deep Intelligence (Shodan & IPData) */}
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <h3 className="text-sm font-bold text-white uppercase mb-4 flex items-center gap-2">
                                            <Zap size={16}/> Deep Intelligence (Shodan & IPData)
                                        </h3>
                                        {enrichmentResult ? (
                                            <div className="space-y-4">
                                                {/* IPData Scores */}
                                                <div className="grid grid-cols-2 gap-2 text-xs">
                                                    <div className="bg-[#111] p-2 rounded border border-[#222]">
                                                        <div className="text-[10px] text-[#888] uppercase">Threat Score</div>
                                                        <div className={`font-mono font-bold ${enrichmentResult.threat.scores?.threat_score && enrichmentResult.threat.scores.threat_score > 50 ? 'text-red-400' : 'text-white'}`}>
                                                            {enrichmentResult.threat.scores?.threat_score ?? 0} / 100
                                                        </div>
                                                    </div>
                                                    <div className="bg-[#111] p-2 rounded border border-[#222]">
                                                        <div className="text-[10px] text-[#888] uppercase">Trust Score</div>
                                                        <div className="font-mono font-bold text-red-400">
                                                            {enrichmentResult.threat.scores?.trust_score ?? 0} / 100
                                                        </div>
                                                    </div>
                                                </div>

                                                {/* Shodan Data */}
                                                {enrichmentResult.shodan ? (
                                                    <div className="space-y-2">
                                                        <div className="text-[10px] text-[#888] uppercase font-bold border-b border-[#222] pb-1">Shodan Exposure</div>
                                                        
                                                        {enrichmentResult.shodan.ports.length > 0 ? (
                                                            <div className="flex flex-wrap gap-1">
                                                                {enrichmentResult.shodan.ports.map(p => (
                                                                    <span key={p} className="text-[10px] bg-[#151515] text-neutral-300 px-1.5 py-0.5 rounded border border-[#333] font-mono">
                                                                        {p}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        ) : <span className="text-xs text-[#888] italic">No open ports detected.</span>}

                                                        {enrichmentResult.shodan.vulns.length > 0 && (
                                                            <div className="mt-2">
                                                                <div className="text-[10px] text-red-400 uppercase font-bold mb-1">Vulnerabilities</div>
                                                                <div className="flex flex-wrap gap-1">
                                                                    {enrichmentResult.shodan.vulns.map(v => (
                                                                        <span key={v} className="text-[10px] bg-red-900/20 text-red-300 px-1.5 py-0.5 rounded border border-red-500/30 font-mono">
                                                                            {v}
                                                                        </span>
                                                                    ))}
                                                                </div>
                                                            </div>
                                                        )}
                                                        
                                                        {enrichmentResult.shodan.tags && enrichmentResult.shodan.tags.length > 0 && (
                                                            <div className="mt-2 flex flex-wrap gap-1">
                                                                 {enrichmentResult.shodan.tags.map(t => (
                                                                     <span key={t} className="text-[10px] bg-[#111] text-red-300 px-1.5 py-0.5 rounded border border-red-500/30">
                                                                         {t}
                                                                     </span>
                                                                 ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                ) : <div className="text-xs text-[#888] italic">No Shodan data available for this IP.</div>}
                                            </div>
                                        ) : <div className="text-[#888] text-xs italic">{isLoading ? "Fetching intelligence..." : "No deep intel available."}</div>}
                                    </div>

                                    {/* HTTP Security */}
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <h3 className="text-sm font-bold text-white uppercase mb-4 flex items-center gap-2">
                                            <Lock size={16}/> Web Security & Headers
                                        </h3>
                                        {httpResult ? (
                                            <div className="space-y-2 text-xs font-mono text-neutral-300">
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Server</span> <span className="text-white">{httpResult.serverInfo.server || 'Unknown'}</span></div>
                                                <div className="flex justify-between border-b border-[#222] pb-1"><span>Status</span> <span className={httpResult.status === 200 ? 'text-white' : 'text-white'}>{httpResult.status} {httpResult.statusText}</span></div>
                                                
                                                <div className="mt-4">
                                                    <div className="text-[#888] mb-2 uppercase font-bold text-[10px]">Response Headers</div>
                                                    <div className="max-h-32 overflow-y-auto custom-scrollbar bg-[#111] p-2 rounded border border-[#222] space-y-1">
                                                        {Object.entries(httpResult.headers).map(([k, v], i) => (
                                                            <div key={i} className="flex gap-2">
                                                                <span className="text-red-400 w-1/3 truncate" title={k}>{k}:</span>
                                                                <span className="text-[#AAA] break-all w-2/3">{v}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                </div>
                                            </div>
                                        ) : <div className="text-[#888] text-xs italic">{isLoading ? "Analyzing headers..." : "HTTP probe failed or not applicable."}</div>}
                                    </div>

                                    {/* AlienVault OTX Intelligence */}
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <h3 className="text-sm font-bold text-red-400 uppercase mb-4 flex items-center gap-2">
                                            <Radar size={16}/> AlienVault OTX Intelligence
                                        </h3>
                                        {otxResult ? (
                                            <div className="space-y-3">
                                                <div className="flex justify-between items-center p-2 rounded bg-[#111] border border-[#222]">
                                                    <span className="text-xs text-[#AAA] font-mono">Pulse Count</span>
                                                    <span className="text-white font-bold">{otxResult.pulse_count}</span>
                                                </div>
                                                {otxResult.malware_families.length > 0 && (
                                                    <div>
                                                        <div className="text-[10px] text-[#888] uppercase font-bold mb-1">Malware Families</div>
                                                        <div className="flex flex-wrap gap-1">
                                                            {otxResult.malware_families.map((m, i) => (
                                                                <span key={i} className="text-[10px] bg-red-900/20 text-red-300 px-1.5 py-0.5 rounded border border-red-500/20">{m}</span>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}
                                                {otxResult.tags.length > 0 && (
                                                    <div>
                                                        <div className="text-[10px] text-[#888] uppercase font-bold mb-1">Tags</div>
                                                        <div className="flex flex-wrap gap-1">
                                                            {otxResult.tags.slice(0, 10).map((t, i) => (
                                                                <span key={i} className="text-[10px] bg-[#151515] text-[#AAA] px-1.5 py-0.5 rounded border border-[#333]">{t}</span>
                                                            ))}
                                                            {otxResult.tags.length > 10 && <span className="text-[9px] text-neutral-600">+{otxResult.tags.length - 10}</span>}
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        ) : (
                                            <div className="text-[#888] text-xs italic text-center p-4">
                                                {isLoading ? "Querying OTX..." : "No OTX data found."}
                                            </div>
                                        )}
                                    </div>

                                    {/* Threat Indicators */}
                                    <div className="bg-[#111]/40 border border-[#222] rounded-lg p-5">
                                        <h3 className="text-sm font-bold text-red-400 uppercase mb-4 flex items-center gap-2">
                                            <ShieldAlert size={16}/> Threat Indicators
                                        </h3>
                                        <div className="space-y-2 text-xs font-mono text-neutral-300 max-h-48 overflow-y-auto custom-scrollbar">
                                            {securityResults.length > 0 ? securityResults.map((s, i) => (
                                                <div key={i} className="flex justify-between items-center p-1.5 rounded bg-[#111] border border-[#222]">
                                                    <div className="flex flex-col">
                                                        <span className="text-[#AAA]">{s.provider}</span>
                                                        {s.details && <span className="text-[9px] text-neutral-600">{s.details}</span>}
                                                    </div>
                                                    <span className={`font-bold ${s.status === 'BLOCKED' ? 'text-red-400' : 'text-white'}`}>{s.status}</span>
                                                </div>
                                            )) : <span className="text-[#888] italic">{isLoading ? "Checking threat feeds..." : "No threat data available."}</span>}
                                            
                                            {rblStatus && (
                                                <div className="flex justify-between items-center p-1.5 rounded bg-[#111] border border-[#222]">
                                                    <span className="text-[#AAA]">RBL Status</span>
                                                    <span className={`font-bold ${rblStatus.status === 'LISTED' ? 'text-red-400' : 'text-white'}`}>{rblStatus.status}</span>
                                                </div>
                                            )}
                                        </div>
                                        {crtResults.length > 0 && (
                                            <div className="mt-4 pt-4 border-t border-[#222]">
                                                <div className="text-[10px] text-[#888] uppercase font-bold mb-2">Latest SSL Certificate</div>
                                                <div className="text-xs font-mono bg-[#111] p-2 rounded border border-[#222]">
                                                    <div className="text-white truncate" title={crtResults[0].common_name}>{crtResults[0].common_name}</div>
                                                    <div className="text-[#888]">Issued by: {crtResults[0].issuer_name.split(',')[0]}</div>
                                                    <div className="text-[#888]">Valid until: {new Date(crtResults[0].not_after).toLocaleDateString()}</div>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                                
                                {riskAnalysis && (
                                <div className="flex justify-center pt-4 gap-2">
                                    <button onClick={handleExportReport} className="text-xs text-[#AAA] hover:text-white flex items-center gap-2 border border-[#333] hover:border-neutral-500 px-4 py-2 rounded-full transition-colors">
                                        <Download size={14}/> EXPORT TEXT REPORT
                                    </button>
                                    <button onClick={handleExportPdf} className="text-xs text-[#AAA] hover:text-white flex items-center gap-2 border border-[#333] hover:border-neutral-500 px-4 py-2 rounded-full transition-colors">
                                        <File size={14}/> EXPORT PDF
                                    </button>
                                </div>
                                )}
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-64 text-center animate-fade-in border border-[#222] border-dashed rounded-xl bg-[#111]/20 mt-4">
                                <div className="w-16 h-16 rounded-full bg-red-900/10 border border-red-500/20 flex items-center justify-center mb-4">
                                    <Radar size={24} className="text-red-500 opacity-80" />
                                </div>
                                <h3 className="text-white font-cyber text-lg mb-2">SUPER SCAN SUITE</h3>
                                <p className="text-neutral-500 text-sm max-w-md">
                                    Enter a target domain, IP, or CIDR above to initiate a deep reconnaissance scan aggregating Threat Intelligence, DNS, WHOIS, and Vulnerability data.
                                </p>
                            </div>
                        )
                    )}

                    {/* ASN TOOL */}
                    {activeCategory === 'ASN' && (
                        <div className="space-y-6 animate-fade-in">
                            {asnResult && (
                                <div className="bg-[#111]/40 border border-[#222] rounded-lg p-6 relative overflow-hidden">
                                    <div className="absolute top-0 right-0 p-4 opacity-10">
                                        <Share2 size={120} className="text-white"/>
                                    </div>
                                    <div className="relative z-10">
                                        <div className="flex items-center gap-4 mb-6">
                                            <div className="bg-[#111] p-3 rounded-lg border border-neutral-500/30 text-red-400">
                                                <Share2 size={32}/>
                                            </div>
                                            <div>
                                                <h2 className="text-3xl font-bold text-white font-mono">{asnResult.asn}</h2>
                                                <div className="text-sm text-[#AAA]">{asnResult.name}</div>
                                            </div>
                                            {asnResult.country_code && (
                                                <img src={`https://flagcdn.com/w80/${asnResult.country_code.toLowerCase()}.png`} className="h-8 rounded shadow-sm ml-auto opacity-80" alt={asnResult.country_code}/>
                                            )}
                                        </div>

                                        <p className="text-sm text-[#AAA] mb-6 max-w-2xl leading-relaxed">
                                            {asnResult.description}
                                        </p>

                                        <div className="grid grid-cols-3 gap-4 mb-8">
                                            <div className="bg-[#111] p-4 rounded border border-[#222] text-center">
                                                <div className="text-2xl font-bold text-white">{asnResult.peers}</div>
                                                <div className="text-[10px] text-[#888] uppercase font-bold">IPv4 Peers</div>
                                            </div>
                                            <div className="bg-[#111] p-4 rounded border border-[#222] text-center">
                                                <div className="text-2xl font-bold text-white">{asnResult.upstreams}</div>
                                                <div className="text-[10px] text-[#888] uppercase font-bold">Upstreams</div>
                                            </div>
                                            <div className="bg-[#111] p-4 rounded border border-[#222] text-center">
                                                <div className="text-2xl font-bold text-white">{asnResult.downstreams}</div>
                                                <div className="text-[10px] text-[#888] uppercase font-bold">Downstreams</div>
                                            </div>
                                        </div>

                                        <div>
                                            <h3 className="text-xs font-bold text-red-400 uppercase mb-4 border-b border-neutral-900/50 pb-2">Announced Prefixes (Top 50)</h3>
                                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 max-h-60 overflow-y-auto custom-scrollbar">
                                                {asnResult.prefixes.map((p: any, i: number) => (
                                                    <div key={i} className="text-xs font-mono text-[#AAA] bg-[#111] p-2 rounded border border-[#222] flex justify-between items-center group hover:border-red-500/30 transition-colors">
                                                        <span>{p.prefix}</span>
                                                        <span className="text-[9px] text-neutral-600 group-hover:text-red-400">{p.description}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {asnSearchResults.length > 0 && !asnResult && (
                                <div>
                                    <h3 className="text-sm font-bold text-[#AAA] mb-4">Search Results ({asnSearchResults.length})</h3>
                                    <div className="grid grid-cols-1 gap-2">
                                        {asnSearchResults.map((res) => (
                                            <button 
                                                key={res.asn}
                                                onClick={() => handleSelectAsn(res.asn)}
                                                className="flex items-center gap-4 bg-[#111] border border-[#222] p-3 rounded hover:bg-red-900/10 hover:border-red-500/30 transition-all text-left group"
                                            >
                                                <span className="font-mono text-red-400 font-bold w-20">{res.asn}</span>
                                                <div className="flex-1 min-w-0">
                                                    <div className="text-sm font-bold text-white truncate">{res.name}</div>
                                                    <div className="text-xs text-[#888] truncate">{res.description_short}</div>
                                                </div>
                                                <span className="text-xs text-[#AAA] bg-[#151515] px-2 py-1 rounded">{res.country_code}</span>
                                                <ArrowRight size={16} className="text-neutral-600 group-hover:text-red-400"/>
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* DNS TOOL */}
                    {activeCategory === 'DNS' && (
                        <div className="space-y-4">
                            <div className="flex bg-[#111] p-1 rounded-lg overflow-x-auto custom-scrollbar gap-1 border border-[#222]">
                                {renderDnsTab('google', 'Google')}
                                {renderDnsTab('cloudflare', 'Cloudflare')}
                                {renderDnsTab('quad9', 'Quad9')}
                                {renderDnsTab('dns0', 'DNS0.eu')}
                                {renderDnsTab('cira', 'CIRA')}
                            </div>
                            <div className="bg-[#111]/40 border border-[#222] rounded-lg p-4 min-h-[300px]">
                                {renderDnsTable()}
                            </div>
                        </div>
                    )}

                    {/* DNS FIREWALL TOOL */}
                    {activeCategory === 'DNS_SEC' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in">
                            {securityResults.length > 0 ? securityResults.map((res, i) => (
                                <div key={i} className="bg-[#111] border border-[#222] p-4 rounded-lg flex items-center justify-between">
                                    <div>
                                        <div className="text-sm font-bold text-white">{res.provider}</div>
                                        <div className="text-xs text-[#888]">{res.filterType} Filter</div>
                                    </div>
                                    <div className="text-right">
                                        <div className={`text-lg font-bold ${res.status === 'BLOCKED' ? 'text-red-500' : res.status === 'FAILED' ? 'text-[#888]' : 'text-white'}`}>
                                            {res.status}
                                        </div>
                                        <div className="text-[10px] text-[#AAA]">{res.details}</div>
                                    </div>
                                </div>
                            )) : <div className="text-center text-[#888] p-10 col-span-2">No security checks run.</div>}
                            
                            {dgaResult && (
                                <div className="col-span-2 bg-[#111] border border-[#222] p-4 rounded-lg mt-4">
                                    <h3 className="text-sm font-bold text-white uppercase mb-2">Heuristic Analysis</h3>
                                    <div className="flex justify-between items-center">
                                        <span className="text-[#AAA] text-xs">Entropy Score: <span className="text-white font-mono">{dgaResult.entropy.toFixed(2)}</span></span>
                                        <span className={`text-xs font-bold px-2 py-1 rounded ${dgaResult.isDga ? 'bg-red-900/20 text-red-400 border border-red-500/30' : 'bg-neutral-900/20 text-white border-neutral-500/30'}`}>
                                            {dgaResult.isDga ? 'POSSIBLE DGA' : 'BENIGN PATTERN'}
                                        </span>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* SUBNET CALC */}
                    {activeCategory === 'SUBNET' && subnetResult && (
                        <div className="bg-[#111]/40 border border-[#222] rounded-lg p-6 animate-fade-in">
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-lg font-bold text-white font-mono">{subnetResult.ip}/{subnetResult.cidr}</h3>
                                <div className="text-xs text-[#888]">
                                    <span className="text-white font-bold">{subnetResult.usableHosts.toLocaleString()}</span> Usable Hosts
                                </div>
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 text-xs font-mono text-neutral-300">
                                <div><div className="text-[#888] mb-1">Netmask</div>{subnetResult.netmask}</div>
                                <div><div className="text-[#888] mb-1">Network</div>{subnetResult.networkAddress}</div>
                                <div><div className="text-[#888] mb-1">Broadcast</div>{subnetResult.broadcastAddress}</div>
                                <div><div className="text-[#888] mb-1">Host Range</div>{subnetResult.firstHost} - {subnetResult.lastHost}</div>
                            </div>
                            <div className="mt-6 pt-6 border-t border-[#222]">
                                <div className="text-[#888] text-[10px] mb-2 uppercase font-bold">Binary Representation</div>
                                <div className="font-mono text-xs space-y-1">
                                    <div className="flex gap-4"><span className="w-16 text-neutral-600">IP</span> <span className="text-red-400">{subnetResult.binaryIp}</span></div>
                                    <div className="flex gap-4"><span className="w-16 text-neutral-600">Mask</span> <span className="text-white">{subnetResult.binaryNetmask}</span></div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* EMAIL TOOL */}
                    {activeCategory === 'EMAIL' && (
                        <div className="space-y-6 animate-fade-in">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div className={`p-4 rounded border bg-[#111]/40 ${spfResult?.valid ? 'border-neutral-500/30' : 'border-red-500/30'}`}>
                                    <div className="text-xs font-bold text-[#888] uppercase mb-2">SPF Record</div>
                                    <div className={`text-xl font-bold mb-1 ${spfResult?.valid ? 'text-white' : 'text-red-400'}`}>{spfResult?.valid ? 'VALID' : 'INVALID/MISSING'}</div>
                                    <div className="text-[10px] font-mono text-[#AAA] break-all">{spfResult?.raw}</div>
                                </div>
                                <div className={`p-4 rounded border bg-[#111]/40 ${dmarcResult?.valid ? 'border-neutral-500/30' : 'border-red-500/30'}`}>
                                    <div className="text-xs font-bold text-[#888] uppercase mb-2">DMARC Policy</div>
                                    <div className={`text-xl font-bold mb-1 ${dmarcResult?.policy === 'reject' ? 'text-white' : dmarcResult?.policy === 'quarantine' ? 'text-white' : 'text-red-400'}`}>{dmarcResult?.policy?.toUpperCase() || 'NONE'}</div>
                                    <div className="text-[10px] text-[#AAA]">Pct: {dmarcResult?.percentage}% | Mail: {dmarcResult?.email}</div>
                                </div>
                                <div className="p-4 rounded border bg-[#111]/40 border-[#222]">
                                    <div className="text-xs font-bold text-[#888] uppercase mb-2">Mail Servers</div>
                                    <div className="text-xl font-bold text-white mb-1">{mxRecords.length} MX Records</div>
                                    <div className="text-[10px] text-[#AAA]">Primary: {mxRecords[0]?.name || 'N/A'}</div>
                                </div>
                            </div>

                            {/* Mail Server Reputation */}
                            {mailServerReputation.length > 0 && (
                                <div className="bg-[#111]/40 border border-[#222] rounded-lg p-4">
                                    <h3 className="text-sm font-bold text-white mb-4 uppercase">MX Infrastructure Reputation</h3>
                                    <div className="space-y-2">
                                        {mailServerReputation.map((server, i) => (
                                            <div key={i} className="flex justify-between items-center p-2 rounded bg-[#111] border border-[#222] text-xs">
                                                <div className="flex items-center gap-3">
                                                    {server.flag && <img src={server.flag} className="w-4 h-3 rounded-sm"/>}
                                                    <span className="font-mono text-neutral-300">{server.hostname}</span>
                                                    <span className="text-neutral-600">({server.ip})</span>
                                                </div>
                                                <div className="flex gap-2">
                                                    <span className={`px-2 py-0.5 rounded font-bold ${server.rbl === 'LISTED' ? 'bg-red-900/20 text-red-400' : 'bg-neutral-900/20 text-white'}`}>
                                                        {server.rbl === 'LISTED' ? 'BLACKLISTED' : 'CLEAN RBL'}
                                                    </span>
                                                    <span className={`px-2 py-0.5 rounded font-bold border ${server.score > 50 ? 'border-red-500/30 text-red-400' : 'border-red-500/30 text-red-400'}`}>
                                                        Risk: {server.score}
                                                    </span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* NETWORK / WHOIS */}
                    {activeCategory === 'NETWORK' && renderNetworkTool()}

                    {/* MY IP */}
                    {activeCategory === 'MY_IP' && renderMyIpTool()}

                    {/* PING */}
                    {activeCategory === 'PING' && (
                        <div className="bg-[#111] border border-[#222] rounded-lg p-4 font-mono text-xs h-[400px] overflow-y-auto custom-scrollbar text-white">
                            {pingResults.map((p, i) => (
                                <div key={i} className="mb-1">
                                    <span className="text-[#888]">[{new Date().toLocaleTimeString()}]</span> 64 bytes from {p.ip}: seq={p.seq} time={p.time}ms status={p.status}
                                </div>
                            ))}
                            {isPinging && <div className="animate-pulse mt-2">_</div>}
                        </div>
                    )}

                    {/* CRT LOGS */}
                    {activeCategory === 'CRT' && (
                        <div className="bg-[#111]/40 border border-[#222] rounded-lg overflow-hidden animate-fade-in">
                            <table className="w-full text-left text-xs font-mono">
                                <thead className="bg-[#111] text-[#888] uppercase font-bold">
                                    <tr><th className="p-3">Logged At</th><th className="p-3">Common Name</th><th className="p-3">Issuer</th></tr>
                                </thead>
                                <tbody className="divide-y divide-neutral-800 text-neutral-300">
                                    {crtResults.map((crt, i) => (
                                        <tr key={i} className="hover:bg-white/5">
                                            <td className="p-3">{new Date(crt.entry_timestamp).toLocaleDateString()}</td>
                                            <td className="p-3 text-red-500">{crt.common_name}</td>
                                            <td className="p-3 text-[#888]">{crt.issuer_name.split(',')[0]}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};


