
import React from 'react';
import { BookOpen, Server, FileJson, Shield, Network, Terminal, Activity, FileText, Zap, HelpCircle, Command, MessageSquare, Search, Layers, Database, Share2, FileCode, Cpu, AlertTriangle } from 'lucide-react';

// Simple Rocket icon wrapper since it wasn't imported in main list
const Rocket = ({ size, className }: { size: number, className?: string }) => (
    <svg xmlns="http://www.w3.org/2000/svg" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg>
);

const HelpSection = ({ title, icon: Icon, children }: { title: string, icon: any, children?: React.ReactNode }) => (
    <div className="bg-[#111] border border-[#222] rounded-lg p-6 hover:border-[#333] transition-colors">
        <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-3 border-b border-[#222] pb-3">
            <Icon className="text-red-500" size={24}/> {title}
        </h3>
        <div className="text-[#AAA] text-sm leading-relaxed space-y-4">
            {children}
        </div>
    </div>
);

const KeyShortcut = ({ keys, desc }: { keys: string[], desc: string }) => (
    <div className="flex justify-between items-center py-2 border-b border-[#222] last:border-0">
        <span className="text-[#AAA]">{desc}</span>
        <div className="flex gap-1">
            {keys.map((k, i) => (
                <span key={i} className="px-2 py-1 bg-[#151515] rounded border border-[#333] font-mono text-xs text-white min-w-[24px] text-center">
                    {k}
                </span>
            ))}
        </div>
    </div>
);

export const HelpView: React.FC = () => {
    return (
        <div className="h-[calc(100vh-70px)] bg-cyber-grid flex flex-col">
            <div className="bg-[#111]/40 border-b border-[#222] p-6 flex items-center gap-4 shrink-0">
                <div className="p-3 bg-[#111] rounded-lg border border-neutral-500/30 text-red-400">
                    <HelpCircle size={28}/>
                </div>
                <div>
                    <h2 className="text-2xl font-bold text-white font-cyber flex items-center gap-2">
                        SYSTEM <span className="text-red-500">GUIDE</span>
                    </h2>
                    <p className="text-sm text-[#888] font-mono mt-1">Technical Documentation & Usage Manual</p>
                </div>
            </div>

            <div className="flex-1 overflow-y-auto custom-scrollbar p-6 md:p-8">
                <div className="max-w-7xl mx-auto space-y-8">
                    
                    {/* Introduction */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <HelpSection title="Getting Started" icon={Rocket}>
                            <p>
                                <strong>ANTI.AI Threat Processor</strong> is a client-side threat intelligence and forensic analysis platform. 
                                It runs entirely in your browser, ensuring data privacy while providing advanced analytic capabilities.
                            </p>
                            <div className="bg-[#111] border border-neutral-500/20 p-4 rounded text-white text-xs font-mono mt-2">
                                <strong className="text-red-400">QUICK START:</strong> Drag & Drop any JSON logs, PCAP capture files, or STIX bundles directly onto the dashboard to begin analysis immediately.
                            </div>
                        </HelpSection>

                        <HelpSection title="Data Ingestion" icon={Database}>
                            <p>The system accepts multiple file formats for analysis:</p>
                            <ul className="list-disc list-inside space-y-2 ml-2">
                                <li><strong>JSON Logs:</strong> Array of objects with <code>ip</code>, <code>commands</code>, and <code>timestamp</code> fields.</li>
                                <li><strong>PCAP / PCAPNG:</strong> Standard network capture files for deep packet inspection.</li>
                                <li><strong>STIX 2.1:</strong> Threat intelligence bundles (`.json`) for graph visualization.</li>
                                <li><strong>MMDB:</strong> MaxMind GeoLite2 databases (`.mmdb`) for offline geolocation enrichment.</li>
                            </ul>
                        </HelpSection>
                    </div>

                    <div className="h-px bg-[#151515] w-full"></div>

                    {/* Architecture & Tech Specs */}
                    <h3 className="text-xl font-bold text-white mb-4 pl-2 border-l-4 border-red-500">Technical Architecture</h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <HelpSection title="Zero-Trust Privacy" icon={Shield}>
                            <p>
                                This system employs a <strong>Local-First</strong> architecture. All heavy lifting—log parsing, graph generation, and pattern matching—is executed within your browser's JavaScript engine (V8/SpiderMonkey).
                            </p>
                            <div className="bg-neutral-900/10 border border-neutral-500/20 p-3 rounded text-white text-xs font-mono mt-2">
                                NO UPLOADS: Your raw logs and PCAP files are never sent to a remote server.
                            </div>
                        </HelpSection>

                        <HelpSection title="System Limits & Storage" icon={Cpu}>
                            <p>
                                Data persistence is handled via <strong>IndexedDB</strong>. 
                                Large datasets (&gt;100MB JSON or &gt;500k graph nodes) may impact browser performance.
                            </p>
                            <ul className="list-disc list-inside space-y-1 ml-2 text-[#888] text-xs mt-2">
                                <li>Recommended Max Log Size: 50MB</li>
                                <li>Recommended Max Nodes: 2,000</li>
                                <li>Storage Quota: Dependent on Browser (typ. 50-80% disk)</li>
                            </ul>
                        </HelpSection>
                    </div>

                    <div className="h-px bg-[#151515] w-full"></div>

                    {/* Module Breakdown */}
                    <h3 className="text-xl font-bold text-white mb-4 pl-2 border-l-4 border-neutral-500">System Modules</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <HelpSection title="Dashboard & SOC Wall" icon={Activity}>
                            <p>
                                The central hub for monitoring active threats. The <strong>SOC Wall</strong> mode provides a cinematic, high-contrast view suitable for large screens in Security Operations Centers.
                            </p>
                            <ul className="mt-2 text-xs space-y-1 text-[#888] font-mono">
                                <li>• Live Attack Map</li>
                                <li>• IOC Velocity Tracking</li>
                                <li>• Critical Alert Feed</li>
                            </ul>
                        </HelpSection>

                        <HelpSection title="Network Forensics" icon={Network}>
                            <p>
                                Analyze packet captures (PCAP) directly in-browser. Features include TCP stream reassembly, file extraction, TLS fingerprinting (JA3), and protocol breakdown.
                            </p>
                            <ul className="mt-2 text-xs space-y-1 text-[#888] font-mono">
                                <li>• Stream Follow</li>
                                <li>• Hex/ASCII Viewer</li>
                                <li>• Geo-IP Correlation</li>
                            </ul>
                        </HelpSection>

                        <HelpSection title="Graph Investigation" icon={Share2}>
                            <p>
                                Visual link analysis connecting IPs, Domains, Threat Actors, and Malware signatures. Supports physics-based force layout and structured "Kill Chain" layout modes.
                            </p>
                            <ul className="mt-2 text-xs space-y-1 text-[#888] font-mono">
                                <li>• STIX 2.1 Visualization</li>
                                <li>• Entity Expansion</li>
                                <li>• Cluster Detection</li>
                            </ul>
                        </HelpSection>

                        <HelpSection title="Rule Engineering" icon={FileCode}>
                            <p>
                                Create, edit, and convert detection rules (YARA, Sigma, Suricata). Integrated AI assistant helps generate rules from natural language or log samples.
                            </p>
                            <ul className="mt-2 text-xs space-y-1 text-[#888] font-mono">
                                <li>• Multi-format Converter</li>
                                <li>• Syntax Highlighting</li>
                                <li>• Simulation Engine</li>
                            </ul>
                        </HelpSection>

                        <HelpSection title="Threat Intelligence" icon={Shield}>
                            <p>
                                Aggregated feeds from CISA, ZDI, URLHaus, and MalwareBazaar. Search for IOCs (Hashes, IPs, Domains) across multiple providers instantly.
                            </p>
                            <ul className="mt-2 text-xs space-y-1 text-[#888] font-mono">
                                <li>• TAXII Relay Support</li>
                                <li>• CSV/JSON Export</li>
                                <li>• Real-time Feed Sync</li>
                            </ul>
                        </HelpSection>

                        <HelpSection title="AI Assistant" icon={MessageSquare}>
                            <p>
                                Context-aware LLM integration (Gemini) that can explain alerts, suggest mitigation strategies, and summarize complex threat actor profiles.
                            </p>
                            <ul className="mt-2 text-xs space-y-1 text-[#888] font-mono">
                                <li>• Contextual Chat</li>
                                <li>• Rule Generation</li>
                                <li>• Report Summarization</li>
                            </ul>
                        </HelpSection>
                    </div>

                    <div className="h-px bg-[#151515] w-full"></div>

                    {/* Shortcuts & Reference */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        <HelpSection title="Keyboard Shortcuts" icon={Command}>
                            <div className="flex flex-col gap-2">
                                <KeyShortcut keys={['/']} desc="Focus Global Search" />
                                <KeyShortcut keys={['Esc']} desc="Close Modals / Clear Selection" />
                                <KeyShortcut keys={['Ctrl', 'Enter']} desc="Submit Rule / Send Message" />
                            </div>
                        </HelpSection>

                        <HelpSection title="Technical JSON Format" icon={FileJson}>
                            <p className="mb-2">For custom log ingestion, ensure your JSON follows this schema:</p>
                            <pre className="bg-[#111] border border-[#333] p-3 rounded text-xs font-mono text-white overflow-x-auto">
{`[
  {
    "timestamp": "2023-10-27T10:00:00Z",
    "ip": "192.168.1.100",
    "country": "US",
    "commands": [
      "powershell.exe -enc ...",
      "whoami /all"
    ]
  }
]`}
                            </pre>
                        </HelpSection>
                        
                        <HelpSection title="Troubleshooting" icon={AlertTriangle}>
                            <p>If you encounter issues:</p>
                            <ul className="list-disc list-inside space-y-2 ml-2 mt-2">
                                <li>Use <strong>Settings {'>'} Clear Data</strong> to reset the local database if the app state becomes corrupted.</li>
                                <li>Ensure CORS proxies are accessible if external lookups fail.</li>
                                <li>Check the <strong>System Logs</strong> tab in Settings for error details.</li>
                            </ul>
                        </HelpSection>
                    </div>

                </div>
            </div>
        </div>
    );
};

