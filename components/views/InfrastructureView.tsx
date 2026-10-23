import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
    Server, Cpu, HardDrive, Box, Play, Square, RotateCcw, Trash2, Terminal,
    Plus, RefreshCw, ChevronRight, Copy, Check, AlertTriangle, Wifi, WifiOff,
    Clock, Package, Layers, Activity, BarChart2, CloudCog, Network, ShieldCheck,
    X, Edit2, ToggleLeft, ToggleRight, Download, Upload, ChevronDown, Loader2,
    Globe, MonitorCog, KeyRound, Radio, Eye, EyeOff
} from 'lucide-react';
import {
    adminService,
    RegisterShipperResponse,
    Shipper,
    ListShippersResponse,
} from '../../api/services/adminService';
import {
    agentService,
    ServersOverviewResponse, ServerOverviewItem, ServerDetailResponse,
    AgentStatus, DeploymentStatus, TemplateCategory,
    ListContainersResponse, ContainerSummary,
    ListDeploymentsResponse, ListTemplatesResponse, DeploymentTemplate,
    AgentMetrics, RegisterAgentResponse, DeployStackResponse,
    AgentInstallScriptResponse, DeleteAgentHardResponse,
} from '../../api/services/agentService';
import { handleApiError } from '../../api/client';
import { useAuth } from '../../contexts/AuthContext';
import { isPublicDemo } from '../../src/utils/demoMode';

// ── Utility helpers ────────────────────────────────────────────────────────

const agentStatusBadge = (status: AgentStatus | 'none') => {
    const map: Record<string, { label: string; cls: string; dot: string }> = {
        online:  { label: 'ONLINE',  cls: 'text-white  bg-neutral-500/10  border-neutral-500/30',  dot: 'bg-neutral-500'  },
        pending: { label: 'PENDING', cls: 'text-white bg-neutral-500/10 border-neutral-500/30', dot: 'bg-neutral-400 animate-pulse' },
        offline: { label: 'OFFLINE', cls: 'text-red-400    bg-red-500/10    border-red-500/30',    dot: 'bg-red-500'    },
        error:   { label: 'ERROR',   cls: 'text-red-400    bg-red-500/10    border-red-500/30',    dot: 'bg-red-500'    },
        none:    { label: 'NO AGENT',cls: 'text-[#AAA]   bg-[#151515]      border-[#333]',      dot: 'bg-neutral-500'   },
    };
    const c = map[status] ?? map.none;
    return (
        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${c.cls}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
            {c.label}
        </span>
    );
};

const deployStatusBadge = (status: DeploymentStatus) => {
    const map: Record<DeploymentStatus, { label: string; cls: string }> = {
        active:    { label: 'ACTIVE',    cls: 'text-white  bg-neutral-500/10  border-neutral-500/30'  },
        deploying: { label: 'DEPLOYING', cls: 'text-white bg-neutral-500/10 border-neutral-500/30' },
        stopped:   { label: 'STOPPED',   cls: 'text-[#AAA]   bg-[#1C1C1C]      border-neutral-600'      },
        error:     { label: 'ERROR',     cls: 'text-red-400    bg-red-500/10    border-red-500/30'    },
        removed:   { label: 'REMOVED',   cls: 'text-neutral-600   bg-[#111]      border-[#222]'      },
    };
    const c = map[status] ?? map.stopped;
    return <span className={`px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${c.cls}`}>{c.label}</span>;
};

const containerStateBadge = (state: string) => {
    if (state === 'running') return <span className="px-2 py-0.5 rounded border text-[10px] font-mono font-bold text-white bg-neutral-500/10 border-neutral-500/30">RUNNING</span>;
    if (state === 'exited')  return <span className="px-2 py-0.5 rounded border text-[10px] font-mono font-bold text-[#AAA] bg-[#1C1C1C] border-neutral-600">EXITED</span>;
    return <span className="px-2 py-0.5 rounded border text-[10px] font-mono font-bold text-white bg-neutral-500/10 border-neutral-500/30">{state.toUpperCase()}</span>;
};

const fmtBytes = (b: number) => {
    if (b >= 1_073_741_824) return `${(b / 1_073_741_824).toFixed(1)} GB`;
    if (b >= 1_048_576)     return `${(b / 1_048_576).toFixed(0)} MB`;
    return `${b} B`;
};

const fmtDate = (s: string) => {
    try { return new Date(s).toLocaleString(); } catch { return s; }
};

// ── CopyButton ─────────────────────────────────────────────────────────────

/** Lower-case helper: does the signed-in user hold this permission? Server still enforces it. */
const useCan = () => {
    const { permissions } = useAuth();
    return (p: string) => permissions.includes(p);
};

const CopyButton: React.FC<{ text: string; className?: string }> = ({ text, className = '' }) => {
    const [copied, setCopied] = useState(false);
    const copy = () => {
        navigator.clipboard.writeText(text).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        });
    };
    return (
        <button onClick={copy} className={`p-1.5 rounded hover:bg-white/10 transition-colors ${className}`} title="Copy">
            {copied ? <Check size={14} className="text-white" /> : <Copy size={14} className="text-[#AAA] hover:text-white" />}
        </button>
    );
};

// ── ConfirmDialog ──────────────────────────────────────────────────────────

interface ConfirmDialogProps {
    title: string;
    message: string;
    confirmLabel?: string;
    danger?: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}
const ConfirmDialog: React.FC<ConfirmDialogProps> = ({ title, message, confirmLabel = 'Confirm', danger = false, onConfirm, onCancel }) => (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm">
        <div className="bg-[#111] border border-[#333] rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl">
            <h3 className="text-lg font-bold text-white font-cyber mb-2">{title}</h3>
            <p className="text-sm text-neutral-300 mb-6">{message}</p>
            <div className="flex justify-end gap-3">
                <button onClick={onCancel} className="px-4 py-2 rounded-lg bg-[#151515] hover:bg-[#1C1C1C] text-neutral-300 text-sm font-mono transition-colors">Cancel</button>
                <button onClick={onConfirm} className={`px-4 py-2 rounded-lg text-white text-sm font-mono font-bold transition-colors ${danger ? 'bg-red-600 hover:bg-red-500' : 'bg-red-500/20 hover:bg-red-500/30 text-red-500 border border-red-500/30'}`}>{confirmLabel}</button>
            </div>
        </div>
    </div>
);

// ── InstallCommandModal ────────────────────────────────────────────────────

const InstallCommandModal: React.FC<{
    result: RegisterAgentResponse;
    onClose: () => void;
}> = ({ result, onClose }) => {
    const [showFull, setShowFull] = useState(false);
    const [fullScript, setFullScript] = useState<AgentInstallScriptResponse | null>(null);
    const [loadingFull, setLoadingFull] = useState(false);

    const loadFull = async () => {
        if (fullScript) { setShowFull(true); return; }
        setLoadingFull(true);
        try {
            const s = await agentService.getInstallScript(result.agent.AgentId, true);
            setFullScript(s);
            setShowFull(true);
        } finally { setLoadingFull(false); }
    };

    const current = showFull && fullScript ? fullScript.script : result.installCommand;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-[#333] rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]">
                <div className="flex items-center justify-between p-5 border-b border-[#222]">
                    <div>
                        <h3 className="text-lg font-bold text-white font-cyber">Agent Registered</h3>
                        <p className="text-xs text-[#AAA] mt-1">Run this command on the target server to connect the agent.</p>
                    </div>
                    <button onClick={onClose} className="p-2 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={18}/></button>
                </div>
                <div className="p-5 overflow-y-auto custom-scrollbar space-y-4">
                    {/* Instructions */}
                    <ol className="space-y-1">
                        {result.instructions.map((step, i) => (
                            <li key={i} className="text-xs text-neutral-300 font-mono">{step}</li>
                        ))}
                    </ol>
                    {/* Script toggle */}
                    <div className="flex items-center gap-3">
                        <button onClick={() => { setShowFull(false); }} className={`text-xs px-3 py-1.5 rounded-lg border transition-colors font-mono ${!showFull ? 'bg-red-500/10 border-red-500/30 text-red-500' : 'bg-[#151515] border-[#333] text-[#AAA] hover:text-white'}`}>Agent Only</button>
                        <button onClick={loadFull} disabled={loadingFull} className={`text-xs px-3 py-1.5 rounded-lg border transition-colors font-mono flex items-center gap-1 ${showFull ? 'bg-red-500/10 border-red-500/30 text-red-500' : 'bg-[#151515] border-[#333] text-[#AAA] hover:text-white'}`}>
                            {loadingFull && <Loader2 size={12} className="animate-spin"/>}Full Docker Setup
                        </button>
                    </div>
                    {/* Script block */}
                    <div className="relative">
                        <pre className="bg-[#111]/80 border border-[#333] rounded-lg p-4 text-xs text-white font-mono overflow-x-auto whitespace-pre-wrap break-all">{current}</pre>
                        <div className="absolute top-2 right-2"><CopyButton text={current} /></div>
                    </div>
                    <p className="text-xs text-[#888]">The agent will appear as <strong className="text-white">PENDING → ONLINE</strong> within 60 seconds after running the command.</p>
                </div>
                <div className="p-4 border-t border-[#222] flex justify-end">
                    <button onClick={onClose} className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-500 text-sm font-mono rounded-lg transition-colors">Done</button>
                </div>
            </div>
        </div>
    );
};

// ── ContainerLogsModal ─────────────────────────────────────────────────────

const ContainerLogsModal: React.FC<{
    agentId: string;
    container: ContainerSummary;
    onClose: () => void;
}> = ({ agentId, container, onClose }) => {
    const [tail, setTail] = useState(200);
    const [logs, setLogs] = useState('');
    const [loading, setLoading] = useState(false);
    const endRef = useRef<HTMLDivElement>(null);

    const load = useCallback(async (t = tail) => {
        setLoading(true);
        try {
            const r = await agentService.getContainerLogs(agentId, container.id, t);
            setLogs(r.logs);
            setTimeout(() => endRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
        } catch (e: any) {
            setLogs(`Error loading logs: ${e?.response?.data?.message ?? e.message}`);
        } finally { setLoading(false); }
    }, [agentId, container.id, tail]);

    useEffect(() => { load(); }, []);

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-[#333] rounded-xl w-full max-w-4xl shadow-2xl flex flex-col" style={{ height: '80vh' }}>
                <div className="flex items-center justify-between p-4 border-b border-[#222] shrink-0">
                    <div className="flex items-center gap-3">
                        <Terminal size={18} className="text-red-500" />
                        <span className="font-mono text-white font-bold">{container.name}</span>
                        <span className="text-[#888] text-xs font-mono">{container.image}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <select value={tail} onChange={e => { const v = Number(e.target.value); setTail(v); load(v); }} className="bg-[#151515] border border-[#333] text-neutral-300 text-xs rounded px-2 py-1 font-mono">
                            {[50, 100, 200, 500, 1000].map(n => <option key={n} value={n}>Tail {n}</option>)}
                        </select>
                        <button onClick={() => load()} disabled={loading} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><RefreshCw size={15} className={loading ? 'animate-spin' : ''}/></button>
                        <button onClick={onClose} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={16}/></button>
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto custom-scrollbar p-4 bg-[#111]/80 font-mono text-xs text-white leading-relaxed whitespace-pre-wrap">
                    {loading ? <span className="text-[#888] animate-pulse">Loading logs...</span> : logs || <span className="text-neutral-600">No log output.</span>}
                    <div ref={endRef} />
                </div>
            </div>
        </div>
    );
};

// ── DeployModal ─────────────────────────────────────────────────────────────

interface DeployErrorDetail {
    message: string;
    detail?: string;
    deploymentId?: string;
}

const DeployModal: React.FC<{
    agentId: string;
    templates: DeploymentTemplate[];
    onSuccess: (res: DeployStackResponse) => void;
    onClose: () => void;
}> = ({ agentId, templates, onSuccess, onClose }) => {
    const [selectedId, setSelectedId] = useState(templates[0]?.TemplateId ?? '');
    const [envVars, setEnvVars] = useState<Record<string, string>>({});
    const [stackName, setStackName] = useState('');
    const [loading, setLoading] = useState(false);
    const [deployError, setDeployError] = useState<DeployErrorDetail | null>(null);

    const selected = templates.find(t => t.TemplateId === selectedId);

    useEffect(() => {
        if (!selected) return;
        const defaults: Record<string, string> = {};
        Object.entries(selected.EnvTemplate ?? {}).forEach(([k, v]) => { defaults[k] = v.default; });
        setEnvVars(defaults);
        setStackName('');
    }, [selectedId]);

    const submit = async () => {
        if (!selectedId) { setDeployError({ message: 'Select a template.' }); return; }
        setLoading(true); setDeployError(null);
        try {
            const res = await agentService.deployStack(agentId, {
                TemplateId: selectedId,
                envVars: Object.fromEntries(Object.entries(envVars).filter(([, v]) => v !== '')),
                ...(stackName ? { stackName } : {}),
            });
            onSuccess(res);
        } catch (e: any) {
            const body = e?.response?.data;
            setDeployError({
                message: body?.message ?? 'Deployment failed',
                detail: body?.error ?? undefined,
                deploymentId: body?.deploymentId ?? undefined,
            });
        } finally { setLoading(false); }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-[#333] rounded-xl w-full max-w-xl shadow-2xl flex flex-col max-h-[90vh]">
                <div className="flex items-center justify-between p-5 border-b border-[#222] shrink-0">
                    <div>
                        <h3 className="text-lg font-bold text-white font-cyber">Deploy Stack</h3>
                        <p className="text-xs text-[#AAA] mt-1">Deploy a template as a Docker Stack to this agent.</p>
                    </div>
                    <button onClick={onClose} className="p-2 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={18}/></button>
                </div>
                <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
                    {/* Template picker */}
                    <div>
                        <label className="text-xs text-[#AAA] font-mono block mb-1">Template *</label>
                        <select value={selectedId} onChange={e => setSelectedId(e.target.value)} className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono">
                            {templates.filter(t => t.IsActive).map(t => (
                                <option key={t.TemplateId} value={t.TemplateId}>{t.Name} — {t.Category}</option>
                            ))}
                        </select>
                        {selected && <p className="text-xs text-[#888] mt-1">{selected.Description}</p>}
                    </div>
                    {/* Stack name */}
                    <div>
                        <label className="text-xs text-[#AAA] font-mono block mb-1">Stack Name <span className="text-neutral-600">(optional)</span></label>
                        <input value={stackName} onChange={e => setStackName(e.target.value)} placeholder={selected ? `${selected.Name.toLowerCase().replace(/\s+/g, '-')}-...` : ''} className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono placeholder-neutral-600" />
                    </div>
                    {/* Env vars */}
                    {selected && Object.keys(selected.EnvTemplate ?? {}).length > 0 && (
                        <div>
                            <p className="text-xs text-[#AAA] font-mono mb-2">Environment Variables</p>
                            <div className="space-y-2">
                                {Object.entries(selected.EnvTemplate).map(([key, meta]) => (
                                    <div key={key}>
                                        <label className="text-[10px] text-[#888] font-mono">{key}{meta.required && <span className="text-red-400"> *</span>} — <span className="text-neutral-600">{meta.description}</span></label>
                                        <input value={envVars[key] ?? ''} onChange={e => setEnvVars(prev => ({ ...prev, [key]: e.target.value }))} placeholder={meta.default} className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded px-2 py-1.5 text-xs font-mono placeholder-neutral-600 mt-0.5" />
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {deployError && (
                        <div className="space-y-2 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                            <div className="flex items-start gap-2">
                                <AlertTriangle size={14} className="text-red-400 mt-0.5 shrink-0" />
                                <div className="min-w-0">
                                    <p className="text-xs text-red-400 font-mono font-bold">{deployError.message}</p>
                                    {deployError.deploymentId && (
                                        <p className="text-[10px] text-red-500/70 font-mono mt-0.5">Deployment ID: {deployError.deploymentId}</p>
                                    )}
                                </div>
                            </div>
                            {deployError.detail && (
                                <pre className="text-[11px] text-red-300 font-mono bg-[#111]/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">{deployError.detail}</pre>
                            )}
                        </div>
                    )}
                </div>
                <div className="p-4 border-t border-[#222] shrink-0 flex justify-end gap-3">
                    <button onClick={onClose} className="px-4 py-2 rounded-lg bg-[#151515] hover:bg-[#1C1C1C] text-neutral-300 text-sm font-mono">Cancel</button>
                    <button onClick={submit} disabled={loading || !selectedId} className="px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-500 text-sm font-mono font-bold disabled:opacity-50 flex items-center gap-2">
                        {loading && <Loader2 size={14} className="animate-spin"/>}Deploy
                    </button>
                </div>
            </div>
        </div>
    );
};

// ── TemplateFormModal ──────────────────────────────────────────────────────

const TemplateFormModal: React.FC<{
    template?: DeploymentTemplate | null;
    onSuccess: () => void;
    onClose: () => void;
}> = ({ template, onSuccess, onClose }) => {
    const [name, setName] = useState(template?.Name ?? '');
    const [description, setDescription] = useState(template?.Description ?? '');
    const [category, setCategory] = useState<TemplateCategory>(template?.Category ?? 'honeypot');
    const [stackContent, setStackContent] = useState(template?.StackFileContent ?? '');
    const [envJson, setEnvJson] = useState(template?.EnvTemplate ? JSON.stringify(template.EnvTemplate, null, 2) : '{}');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const submit = async () => {
        if (!name.trim()) { setError('Name is required.'); return; }
        if (!stackContent.trim()) { setError('Stack file content is required.'); return; }
        let envTemplate: Record<string, any> = {};
        try { envTemplate = JSON.parse(envJson); } catch { setError('Invalid JSON in Environment Template.'); return; }
        setLoading(true); setError('');
        try {
            if (template) {
                await agentService.updateTemplate(template.TemplateId, { Name: name, Description: description, Category: category, StackFileContent: stackContent, EnvTemplate: envTemplate });
            } else {
                await agentService.createTemplate({ Name: name, Description: description, Category: category, StackFileContent: stackContent, EnvTemplate: envTemplate });
            }
            onSuccess();
        } catch (e: any) {
            setError(e?.response?.data?.message ?? 'Failed to save template');
        } finally { setLoading(false); }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-[#333] rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]">
                <div className="flex items-center justify-between p-5 border-b border-[#222] shrink-0">
                    <h3 className="text-lg font-bold text-white font-cyber">{template ? 'Edit Template' : 'New Template'}</h3>
                    <button onClick={onClose} className="p-2 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={18}/></button>
                </div>
                <div className="flex-1 overflow-y-auto custom-scrollbar p-5 space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <div className="col-span-2">
                            <label className="text-xs text-[#AAA] font-mono block mb-1">Name *</label>
                            <input value={name} onChange={e => setName(e.target.value)} className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono" placeholder="Cowrie SSH Honeypot"/>
                        </div>
                        <div>
                            <label className="text-xs text-[#AAA] font-mono block mb-1">Category</label>
                            <select value={category} onChange={e => setCategory(e.target.value as TemplateCategory)} className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono">
                                <option value="honeypot">honeypot</option>
                                <option value="utility">utility</option>
                                <option value="monitoring">monitoring</option>
                            </select>
                        </div>
                        <div>
                            <label className="text-xs text-[#AAA] font-mono block mb-1">Description</label>
                            <input value={description} onChange={e => setDescription(e.target.value)} className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono" placeholder="Brief description..."/>
                        </div>
                    </div>
                    <div>
                        <label className="text-xs text-[#AAA] font-mono block mb-1">Docker Compose / Stack File *</label>
                        <textarea value={stackContent} onChange={e => setStackContent(e.target.value)} rows={10} className="w-full bg-[#111]/80 border border-[#333] text-white rounded-lg p-3 text-xs font-mono resize-y" placeholder={"version: '3.8'\nservices:\n  ..."} />
                    </div>
                    <div>
                        <label className="text-xs text-[#AAA] font-mono block mb-1">Environment Template <span className="text-neutral-600">(JSON)</span></label>
                        <textarea value={envJson} onChange={e => setEnvJson(e.target.value)} rows={5} className="w-full bg-[#111]/80 border border-[#333] text-white rounded-lg p-3 text-xs font-mono resize-y" placeholder={'{"SSH_PORT": {"description": "SSH port", "default": "2222", "required": false}}'} />
                    </div>
                    {error && <p className="text-xs text-red-400 font-mono bg-red-500/10 border border-red-500/30 rounded px-3 py-2">{error}</p>}
                </div>
                <div className="p-4 border-t border-[#222] shrink-0 flex justify-end gap-3">
                    <button onClick={onClose} className="px-4 py-2 rounded-lg bg-[#151515] hover:bg-[#1C1C1C] text-neutral-300 text-sm font-mono">Cancel</button>
                    <button onClick={submit} disabled={loading} className="px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-500 text-sm font-mono font-bold disabled:opacity-50 flex items-center gap-2">
                        {loading && <Loader2 size={14} className="animate-spin"/>}{template ? 'Save Changes' : 'Create Template'}
                    </button>
                </div>
            </div>
        </div>
    );
};

// ── RegisterServerModal ───────────────────────────────────────────────────

const RegisterServerModal: React.FC<{
    onSuccess: () => void;
    onClose: () => void;
}> = ({ onSuccess, onClose }) => {
    const [form, setForm] = useState({ ServerId: '', Hostname: '', PublicIp: '', Region: '', PrivateIp: '', Provider: 'aws', Os: '' });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const set = (k: string, v: string) => setForm(prev => ({ ...prev, [k]: v }));

    const submit = async () => {
        if (!form.ServerId.trim() || !form.Hostname.trim() || !form.PublicIp.trim() || !form.Region.trim()) {
            setError('Server ID, Hostname, Public IP and Region are required.');
            return;
        }
        setLoading(true); setError('');
        try {
            await adminService.registerServer({
                ServerId: form.ServerId.trim(),
                Hostname: form.Hostname.trim(),
                PublicIp: form.PublicIp.trim(),
                Region: form.Region.trim(),
                ...(form.PrivateIp.trim() ? { PrivateIp: form.PrivateIp.trim() } : {}),
                ...(form.Provider.trim() ? { Provider: form.Provider.trim() } : {}),
                ...(form.Os.trim() ? { Os: form.Os.trim() } : {}),
            });
            onSuccess();
        } catch (e: any) {
            const status = e?.response?.status;
            const data = e?.response?.data;
            if (status === 409) {
                setError(`Server ID "${form.ServerId.trim()}" is already taken. Please choose another Server ID.`);
            } else if (status === 403 || data?.code === 'PLAN_LIMIT_REACHED') {
                const used = data?.used;
                const limit = data?.limit;
                setError(
                    data?.message ||
                    (typeof used === 'number' && typeof limit === 'number'
                        ? `Server limit reached (${used} of ${limit} servers used). Upgrade to Pro for 10 servers.`
                        : 'Server limit reached on your plan. Please upgrade to Pro to add more servers.')
                );
            } else if (status === 402 || data?.code === 'PLAN_INACTIVE') {
                setError('Your subscription is inactive. Please renew your plan to register servers.');
            } else {
                setError(handleApiError(e));
            }
        } finally { setLoading(false); }
    };

    const fields: { key: string; label: string; placeholder: string; required?: boolean }[] = [
        { key: 'ServerId',  label: 'Server ID',   placeholder: 'deqoy-prod-1',         required: true },
        { key: 'Hostname',  label: 'Hostname',    placeholder: 'deqoy',                required: true },
        { key: 'PublicIp',  label: 'Public IP',   placeholder: '13.233.163.244',       required: true },
        { key: 'Region',    label: 'Region',      placeholder: 'ap-south-1',           required: true },
        { key: 'PrivateIp', label: 'Private IP',  placeholder: '10.0.1.50 (optional)' },
        { key: 'Provider',  label: 'Provider',    placeholder: 'aws' },
        { key: 'Os',        label: 'OS',          placeholder: 'Ubuntu 24.04 (optional)' },
    ];

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-[#333] rounded-xl w-full max-w-lg shadow-2xl flex flex-col">
                <div className="flex items-center justify-between p-5 border-b border-[#222]">
                    <div>
                        <h3 className="text-lg font-bold text-white font-cyber">Register Server</h3>
                        <p className="text-xs text-[#AAA] mt-1">Add a new honeypot server to the fleet.</p>
                    </div>
                    <button onClick={onClose} className="p-2 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={18}/></button>
                </div>
                <div className="p-5 space-y-3">
                    {fields.map(f => (
                        <div key={f.key}>
                            <label className="text-xs text-[#AAA] font-mono block mb-1">
                                {f.label}{f.required && <span className="text-red-400"> *</span>}
                            </label>
                            <input
                                value={(form as any)[f.key]}
                                onChange={e => set(f.key, e.target.value)}
                                placeholder={f.placeholder}
                                className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono placeholder-neutral-600 focus:outline-none focus:border-red-500"
                            />
                        </div>
                    ))}
                    {error && (
                        <div className="flex flex-col gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded p-3">
                            <div className="flex items-start gap-2">
                                <AlertTriangle size={14} className="shrink-0 mt-0.5"/>
                                <span className="flex-1 font-mono">{error}</span>
                            </div>
                            {(error.includes('Server limit reached') || error.includes('Upgrade to Pro')) && (
                                <button
                                    type="button"
                                    onClick={() => {
                                        window.dispatchEvent(
                                            new CustomEvent('open-plan-upgrade', {
                                                detail: {
                                                    code: 'PLAN_LIMIT_REACHED',
                                                    message: 'You have reached the server limit on your current plan. Upgrade to Pro for 10 servers.',
                                                },
                                            })
                                        );
                                    }}
                                    className="self-start text-[11px] font-bold text-orange-400 hover:text-orange-300 underline font-mono flex items-center gap-1 mt-1"
                                >
                                    Upgrade to Pro Plan (10 Servers) →
                                </button>
                            )}
                        </div>
                    )}
                </div>
                <div className="p-4 border-t border-[#222] flex justify-end gap-3">
                    <button onClick={onClose} className="px-4 py-2 rounded-lg bg-[#151515] hover:bg-[#1C1C1C] text-neutral-300 text-sm font-mono">Cancel</button>
                    <button onClick={submit} disabled={loading} className="px-4 py-2 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-500 text-sm font-mono font-bold disabled:opacity-50 flex items-center gap-2">
                        {loading && <Loader2 size={14} className="animate-spin"/>}Register Server
                    </button>
                </div>
            </div>
        </div>
    );
};

// ── ShipperTokenModal ──────────────────────────────────────────────────────

const INSTALL_PACKAGE_ERROR_HINT =
    'The API may not have been able to build the install tarball (for example, missing honeypot-log-shipper sources or tar on the API host).';

function formatRegisterShipperApiError(e: unknown): string {
    const err = e as { response?: { status?: number; data?: { message?: string } } };
    const status = err?.response?.status;
    const msg = err?.response?.data?.message ?? 'Failed to register shipper';
    if (status !== 500) return msg;
    const t = String(msg);
    if (/\binstall\s+package\b|tarball|shipper\.tar|honeypot-log-shipper|\btar\b/i.test(t)) {
        return `${msg} ${INSTALL_PACKAGE_ERROR_HINT}`;
    }
    return msg;
}

const ShipperTokenModal: React.FC<{
    result: RegisterShipperResponse;
    onClose: () => void;
}> = ({ result, onClose }) => {
    const [revealed, setRevealed] = useState(false);
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-neutral-500/40 rounded-xl w-full max-w-2xl shadow-2xl flex flex-col max-h-[90vh]">
                <div className="flex items-center gap-3 p-5 border-b border-[#222] shrink-0">
                    <div className="p-2 bg-neutral-500/10 rounded-lg border border-neutral-500/30">
                        <KeyRound size={18} className="text-white"/>
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-white font-cyber">Shipper Registered</h3>
                        <p className="text-xs text-white font-mono mt-0.5">⚠ Copy this token now — it will never be shown again.</p>
                    </div>
                    <button onClick={onClose} className="ml-auto p-2 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={18}/></button>
                </div>
                <div className="p-5 space-y-4 overflow-y-auto custom-scrollbar">
                    {/* IDs */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                        <div><span className="text-[#888]">Shipper ID: </span><span className="text-neutral-200">{result.shipper.ShipperId}</span></div>
                        <div><span className="text-[#888]">Allowed IP: </span><span className="text-neutral-200">{result.shipper.AllowedIp}</span></div>
                        <div className="sm:col-span-2"><span className="text-[#888]">Server ID: </span><span className="text-neutral-200">{result.shipper.ServerId}</span></div>
                        <div className="sm:col-span-2 break-all"><span className="text-[#888]">Ingest (config): </span><span className="text-neutral-200">{result.deployment.backendUrl}</span></div>
                    </div>

                    {/* Token */}
                    <div>
                        <div className="flex items-center justify-between mb-1.5">
                            <label className="text-xs text-[#AAA] font-mono">Auth Token</label>
                            <button onClick={() => setRevealed(r => !r)} className="text-[10px] text-[#888] hover:text-neutral-300 font-mono flex items-center gap-1">
                                {revealed ? <EyeOff size={11}/> : <Eye size={11}/>}{revealed ? 'Hide' : 'Reveal'}
                            </button>
                        </div>
                        <div className="relative">
                            <div className={`bg-[#111]/80 border border-neutral-500/30 rounded-lg p-3 pr-10 font-mono text-xs break-all leading-relaxed ${revealed ? 'text-white' : 'blur-sm select-none text-white'}`}>
                                {result.shipper.Token}
                            </div>
                            <div className="absolute top-2 right-2">
                                <CopyButton text={result.shipper.Token} className="text-white"/>
                            </div>
                        </div>
                    </div>

                    {/* Install command (Ubuntu) */}
                    <div>
                        <label className="text-xs text-[#AAA] font-mono block mb-1.5">Run on the Ubuntu server (copy entire line)</label>
                        <div className="relative">
                            <pre
                                tabIndex={0}
                                onClick={ev => {
                                    const sel = window.getSelection();
                                    const range = document.createRange();
                                    range.selectNodeContents(ev.currentTarget);
                                    sel?.removeAllRanges();
                                    sel?.addRange(range);
                                }}
                                className="bg-[#111]/80 border border-[#333] rounded-lg p-3 pr-10 text-xs text-white font-mono overflow-x-auto whitespace-pre-wrap break-all select-all cursor-text"
                            >
                                {result.deployment.installCommand}
                            </pre>
                            <div className="absolute top-2 right-2">
                                <CopyButton text={result.deployment.installCommand}/>
                            </div>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[10px] font-mono">
                            <a href={result.deployment.installScriptUrl} target="_blank" rel="noopener noreferrer" className="text-red-500/80 hover:text-red-500 underline">
                                install.sh
                            </a>
                            <a href={result.deployment.shipperBundleUrl} target="_blank" rel="noopener noreferrer" className="text-red-500/80 hover:text-red-500 underline">
                                shipper.tar.gz
                            </a>
                            <span className="text-neutral-600">(debug / manual fetch)</span>
                        </div>
                    </div>

                    {/* Instructions */}
                    {result.instructions.length > 0 && (
                        <div className="bg-[#151515]/50 border border-[#333] rounded-lg p-3 space-y-1">
                            <p className="text-[10px] text-[#888] font-mono uppercase tracking-wider mb-2">Setup Instructions</p>
                            <ol className="space-y-1.5">
                                {result.instructions.map((step, i) => (
                                    <li key={i} className="text-xs text-neutral-300 font-mono">{step}</li>
                                ))}
                            </ol>
                        </div>
                    )}

                    {/* Warning */}
                    {result.warning ? (
                        <div className="text-xs text-[#888] bg-[#151515]/60 border border-[#333] rounded-lg px-3 py-2 leading-relaxed">
                            {result.warning}
                        </div>
                    ) : null}
                </div>
                <div className="p-4 border-t border-[#222] shrink-0 flex justify-end">
                    <button onClick={onClose} className="px-4 py-2 rounded-lg bg-neutral-500/10 hover:bg-neutral-500/20 border border-neutral-500/30 text-white text-sm font-mono font-bold">I've Saved the Token</button>
                </div>
            </div>
        </div>
    );
};

// ── RegisterShipperModal ───────────────────────────────────────────────────

const RegisterShipperModal: React.FC<{
    serverId: string;
    defaultIp: string;
    onSuccess: (res: RegisterShipperResponse) => void;
    onClose: () => void;
}> = ({ serverId, defaultIp, onSuccess, onClose }) => {
    const [allowedIp, setAllowedIp] = useState(defaultIp);
    const [dockerImage, setDockerImage] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const submit = async () => {
        if (!allowedIp.trim()) { setError('Allowed IP is required.'); return; }
        setLoading(true); setError('');
        try {
            const res = await adminService.registerShipper({
                ServerId: serverId,
                AllowedIp: allowedIp.trim(),
                ...(dockerImage.trim() ? { DockerImage: dockerImage.trim() } : {}),
            });
            onSuccess(res);
        } catch (e: any) {
            setError(e?.response?.data?.message ?? 'Failed to register shipper');
        } finally { setLoading(false); }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/70 backdrop-blur-sm p-4">
            <div className="bg-[#111] border border-[#333] rounded-xl w-full max-w-md shadow-2xl">
                <div className="flex items-center justify-between p-5 border-b border-[#222]">
                    <div>
                        <h3 className="text-lg font-bold text-white font-cyber">Register Log Shipper</h3>
                        <p className="text-xs text-[#AAA] mt-1">Bind a log shipper to <code className="text-red-500">{serverId}</code>.</p>
                    </div>
                    <button onClick={onClose} className="p-2 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={18}/></button>
                </div>
                <div className="p-5 space-y-3">
                    <div>
                        <label className="text-xs text-[#AAA] font-mono block mb-1">Allowed IP <span className="text-red-400">*</span></label>
                        <input
                            value={allowedIp}
                            onChange={e => setAllowedIp(e.target.value)}
                            placeholder="13.233.163.244"
                            className="w-full bg-[#151515] border border-[#333] text-neutral-200 rounded-lg px-3 py-2 text-sm font-mono placeholder-neutral-600 focus:outline-none focus:border-red-500"
                        />
                        <p className="text-[10px] text-neutral-600 mt-1 font-mono">Only requests from this IP will be accepted.</p>
                    </div>
                    {error && (
                        <div className="flex items-start gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded px-3 py-2 whitespace-pre-wrap">
                            <AlertTriangle size={13} className="shrink-0 mt-0.5"/>{error}
                        </div>
                    )}
                </div>
                <div className="p-4 border-t border-[#222] flex justify-end gap-3">
                    <button onClick={onClose} className="px-4 py-2 rounded-lg bg-[#151515] hover:bg-[#1C1C1C] text-neutral-300 text-sm font-mono">Cancel</button>
                    <button onClick={submit} disabled={loading} className="px-4 py-2 rounded-lg bg-neutral-500/10 hover:bg-neutral-500/20 border border-neutral-500/30 text-white text-sm font-mono font-bold disabled:opacity-50 flex items-center gap-2">
                        {loading && <Loader2 size={14} className="animate-spin"/>}Register Shipper
                    </button>
                </div>
            </div>
        </div>
    );
};

// ── Server Detail Panel ────────────────────────────────────────────────────

type DetailTab = 'overview' | 'containers' | 'deployments' | 'metrics';

const ServerDetailPanel: React.FC<{
    server: ServerOverviewItem;
    onClose: () => void;
    onRegisterAgent: (serverId: string) => void;
    onRefreshList: () => void;
    onShipperChanged: () => void;
    templates: DeploymentTemplate[];
}> = ({ server, onClose, onRegisterAgent, onRefreshList, onShipperChanged, templates }) => {
    const can = useCan();
    const [tab, setTab] = useState<DetailTab>('overview');
    const [detail, setDetail] = useState<ServerDetailResponse | null>(null);
    const [containers, setContainers] = useState<ListContainersResponse | null>(null);
    const [deployments, setDeployments] = useState<ListDeploymentsResponse | null>(null);
    const [metrics, setMetrics] = useState<AgentMetrics | null>(null);
    const [loading, setLoading] = useState(false);
    const [loadingAction, setLoadingAction] = useState('');
    const [error, setError] = useState('');
    const [logTarget, setLogTarget] = useState<ContainerSummary | null>(null);
    const [showDeploy, setShowDeploy] = useState(false);
    const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => void } | null>(null);
    const [showRegisterShipper, setShowRegisterShipper] = useState(false);
    const [shipperToken, setShipperToken] = useState<RegisterShipperResponse | null>(null);
    const [shipperActionLoading, setShipperActionLoading] = useState(false);
    const [shipperActionError, setShipperActionError] = useState('');
    const [containersLoadSlow, setContainersLoadSlow] = useState(false);
    const containersListAbortRef = useRef<AbortController | null>(null);

    const agentId = server.agent.isRegistered ? server.agent.agentId : null;
    const isOnline = server.agent.isRegistered && server.agent.status === 'online';

    const loadDetail = useCallback(async () => {
        setLoading(true); setError('');
        try {
            const d = await agentService.getServerOverview(server.ServerId);
            setDetail(d);
        } catch (e: any) {
            setError(e?.response?.data?.message ?? 'Failed to load server details');
        } finally { setLoading(false); }
    }, [server.ServerId]);

    const loadContainers = useCallback(async () => {
        if (!agentId) return;
        containersListAbortRef.current?.abort();
        const ac = new AbortController();
        containersListAbortRef.current = ac;
        setLoading(true); setError('');
        try {
            const c = await agentService.listContainers(agentId, true, ac.signal);
            if (containersListAbortRef.current !== ac) return;
            setContainers(c);
        } catch (e: any) {
            if (e?.code === 'ERR_CANCELED' || ac.signal.aborted) return;
            if (containersListAbortRef.current !== ac) return;
            setError(e?.response?.data?.message ?? 'Failed to load containers');
        } finally {
            if (containersListAbortRef.current === ac) {
                setLoading(false);
            }
        }
    }, [agentId]);

    const loadDeployments = useCallback(async () => {
        if (!agentId) return;
        setLoading(true); setError('');
        try {
            const d = await agentService.listDeployments(agentId);
            setDeployments(d);
        } catch (e: any) {
            setError(e?.response?.data?.message ?? 'Failed to load deployments');
        } finally { setLoading(false); }
    }, [agentId]);

    const loadMetrics = useCallback(async () => {
        if (!agentId) return;
        setLoading(true); setError('');
        try {
            const m = await agentService.getMetrics(agentId);
            setMetrics(m);
        } catch (e: any) {
            setError(e?.response?.data?.message ?? 'Failed to load metrics');
        } finally { setLoading(false); }
    }, [agentId]);

    useEffect(() => {
        if (tab === 'overview') loadDetail();
        else if (tab === 'containers') loadContainers();
        else if (tab === 'deployments') loadDeployments();
        else if (tab === 'metrics') loadMetrics();
    }, [tab]);

    useEffect(() => {
        if (tab !== 'containers') {
            containersListAbortRef.current?.abort();
            containersListAbortRef.current = null;
        }
    }, [tab]);

    useEffect(() => () => {
        containersListAbortRef.current?.abort();
    }, []);

    useEffect(() => {
        if (tab !== 'containers' || !loading) {
            setContainersLoadSlow(false);
            return;
        }
        const id = window.setTimeout(() => setContainersLoadSlow(true), 12000);
        return () => window.clearTimeout(id);
    }, [tab, loading]);

    const doContainerAction = async (container: ContainerSummary, action: 'start' | 'stop' | 'restart') => {
        if (!agentId) return;
        setLoadingAction(`${action}-${container.id}`);
        try { await agentService.containerAction(agentId, container.id, action); await loadContainers(); } finally { setLoadingAction(''); }
    };

    const doRemoveContainer = (container: ContainerSummary) => {
        if (!agentId) return;
        setConfirm({
            title: 'Remove Container',
            message: `Permanently remove container "${container.name}"? This cannot be undone.`,
            action: async () => {
                setConfirm(null);
                setLoadingAction(`remove-${container.id}`);
                try { await agentService.removeContainer(agentId, container.id); await loadContainers(); } finally { setLoadingAction(''); }
            }
        });
    };

    const doDeploymentAction = async (depId: string, action: 'start' | 'stop') => {
        setLoadingAction(`dep-${action}-${depId}`);
        try { await agentService.deploymentAction(depId, action); await loadDeployments(); } finally { setLoadingAction(''); }
    };

    const doRemoveDeployment = (depId: string, name: string) => {
        setConfirm({
            title: 'Remove Deployment',
            message: `Remove deployment "${name}"? This will delete the Docker stack from the server.`,
            action: async () => {
                setConfirm(null);
                setLoadingAction(`dep-remove-${depId}`);
                try { await agentService.removeDeployment(depId); await loadDeployments(); } finally { setLoadingAction(''); }
            }
        });
    };

    const doDeleteAgent = () => {
        if (!agentId) return;
        setConfirm({
            title: 'Remove Agent',
            message: 'Remove this agent? This deletes the Portainer endpoint and marks all deployments as removed. The agent container on the server is NOT stopped automatically.',
            action: async () => {
                setConfirm(null);
                try { await agentService.deleteAgent(agentId); onRefreshList(); onClose(); } catch (e: any) { setError(e?.response?.data?.message ?? 'Failed to remove agent'); }
            }
        });
    };

    const doHardDeleteAgent = () => {
        if (!agentId) return;
        setConfirm({
            title: 'Hard Delete Agent',
            message: `Permanently delete this agent, its Portainer endpoint, and ALL related deployments? This cannot be undone. The server's agent status will be reset to "none".`,
            action: async () => {
                setConfirm(null);
                try { await agentService.hardDeleteAgent(agentId); onRefreshList(); onClose(); } catch (e: any) { setError(e?.response?.data?.message ?? 'Failed to hard-delete agent'); }
            }
        });
    };

    const doDeleteShipper = (shipperId: string) => {
        setConfirm({
            title: 'Delete Shipper',
            message: `Permanently delete shipper ${shipperId}? The shipper container will lose its credentials and stop working.`,
            action: async () => {
                setConfirm(null);
                try { await adminService.deleteShipper(shipperId); await loadDetail(); onShipperChanged(); } catch (e: any) { setError(e?.response?.data?.message ?? 'Failed to delete shipper'); }
            }
        });
    };

    const doDeleteServer = () => {
        setConfirm({
            title: 'Delete Server (Cascade)',
            message: `Permanently delete server "${server.Hostname}" and cascade-delete ALL related shippers, agents, and deployments? ClickHouse log data is retained. This cannot be undone.`,
            action: async () => {
                setConfirm(null);
                try { await adminService.deleteServer(server.ServerId); onRefreshList(); onClose(); } catch (e: any) { setError(e?.response?.data?.message ?? 'Failed to delete server'); }
            }
        });
    };

    const tabs: { id: DetailTab; label: string; icon: React.ElementType; disabled?: boolean }[] = [
        { id: 'overview', label: 'Overview', icon: Server },
        { id: 'containers', label: 'Containers', icon: Box, disabled: !agentId },
        { id: 'deployments', label: 'Deployments', icon: Layers, disabled: !agentId },
        { id: 'metrics', label: 'Metrics', icon: BarChart2, disabled: !agentId },
    ];

    return (
        <div className="flex flex-col h-full border-l border-[#222] bg-[#111]/60 w-full">
            {/* Panel Header */}
            <div className="p-4 border-b border-[#222] flex items-center justify-between shrink-0">
                <div>
                    <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-base font-bold text-white font-cyber">{server.Hostname}</span>
                        {agentStatusBadge(server.agent.isRegistered ? server.agent.status : 'none')}
                    </div>
                    <div className="text-xs text-[#888] font-mono">{server.PublicIp} · {server.Region} · {server.Provider}</div>
                </div>
                <div className="flex items-center gap-2">
                    {can('infrastructure.deployments.manage') && agentId && isOnline && (
                        <button onClick={() => setShowDeploy(true)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-xs font-mono hover:bg-red-500/20 transition-colors">
                            <Upload size={12}/> Deploy
                        </button>
                    )}
                    {can('infrastructure.servers.manage') && !server.agent.isRegistered && (
                        <button onClick={() => onRegisterAgent(server.ServerId)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-neutral-500/10 border border-neutral-500/30 text-red-400 text-xs font-mono hover:bg-neutral-500/20 transition-colors">
                            <Plus size={12}/> Register Agent
                        </button>
                    )}
                    {can('infrastructure.servers.manage') && (<button onClick={doDeleteServer} title="Delete server (cascade)" className="p-1.5 rounded hover:bg-red-900/40 text-red-500/60 hover:text-red-400 transition-colors" >
                        <Trash2 size={15}/>
                    </button>)}
                    <button onClick={onClose} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><X size={16}/></button>
                </div>
            </div>

            {/* Tab Bar */}
            <div className="flex border-b border-[#222] shrink-0">
                {tabs.map(t => (
                    <button key={t.id} onClick={() => !t.disabled && setTab(t.id)} disabled={t.disabled} className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-mono font-bold transition-colors border-b-2 ${tab === t.id ? 'text-red-500 border-red-500' : 'text-[#888] border-transparent hover:text-neutral-300'} ${t.disabled ? 'opacity-30 cursor-not-allowed' : ''}`}>
                        <t.icon size={13}/>{t.label}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto custom-scrollbar p-4">
                {error && (
                    <div className="mb-4 flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                        <AlertTriangle size={13}/>{error}
                    </div>
                )}
                {loading && (
                    <div className="flex flex-col gap-2 text-xs text-[#888] font-mono mb-2">
                        <div className="flex items-center gap-2">
                            <Loader2 size={14} className="animate-spin"/>Loading...
                        </div>
                        {tab === 'containers' && containersLoadSlow && (
                            <button
                                type="button"
                                onClick={() => { setContainersLoadSlow(false); void loadContainers(); }}
                                className="self-start px-2.5 py-1 rounded border border-neutral-500/40 bg-neutral-500/10 text-white/90 hover:bg-neutral-500/20 hover:text-white text-[11px] font-bold transition-colors"
                            >
                                Taking too long? Reload
                            </button>
                        )}
                    </div>
                )}

                {/* ── OVERVIEW ── */}
                {tab === 'overview' && detail && !loading && (
                    <div className="space-y-4">
                        {/* Server Info */}
                        <div className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-3">
                            <h4 className="text-xs font-bold text-[#AAA] uppercase tracking-widest font-mono">Server Info</h4>
                            <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs font-mono">
                                {[
                                    ['Server ID', detail.server.ServerId],
                                    ['Hostname', detail.server.Hostname],
                                    ['Public IP', detail.server.PublicIp],
                                    ['Private IP', detail.server.PrivateIp ?? '—'],
                                    ['Region', detail.server.Region],
                                    ['Provider', detail.server.Provider],
                                    ['OS', detail.server.Os ?? '—'],
                                    ['Docker', detail.server.DockerVersion ?? '—'],
                                    ['Created', fmtDate(detail.server.CreatedAt)],
                                ].map(([k, v]) => (
                                    <div key={k}><span className="text-neutral-600">{k}: </span><span className="text-neutral-200">{v}</span></div>
                                ))}
                            </div>
                        </div>

                        {/* Agent Info */}
                        <div className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <h4 className="text-xs font-bold text-[#AAA] uppercase tracking-widest font-mono">Agent</h4>
                                {can('infrastructure.servers.manage') && detail.agent.isRegistered && agentId && (
                                    <div className="flex items-center gap-1.5">
                                        <button onClick={doDeleteAgent} className="text-[10px] text-white hover:text-white font-mono flex items-center gap-1 px-2 py-0.5 rounded border border-neutral-500/20 hover:border-neutral-500/40 transition-colors">
                                            <Trash2 size={10}/> Soft Remove
                                        </button>
                                        <button onClick={doHardDeleteAgent} className="text-[10px] text-red-400 hover:text-red-300 font-mono flex items-center gap-1 px-2 py-0.5 rounded border border-red-500/20 hover:border-red-500/40 transition-colors">
                                            <Trash2 size={10}/> Hard Delete
                                        </button>
                                    </div>
                                )}
                            </div>
                            {detail.agent.isRegistered ? (
                                <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs font-mono">
                                    {[
                                        ['Agent ID', detail.agent.AgentId],
                                        ['Status', ''],
                                        ['Endpoint ID', String(detail.agent.PortainerEndpointId)],
                                        ['Version', detail.agent.AgentVersion],
                                        ['Docker', detail.agent.DockerVersion],
                                        ['Last Heartbeat', fmtDate(detail.agent.LastHeartbeat)],
                                        ['Registered', fmtDate(detail.agent.CreatedAt)],
                                    ].map(([k, v]) => (
                                        <div key={k} className="flex items-center gap-1.5">
                                            <span className="text-neutral-600">{k}: </span>
                                            {k === 'Status' ? agentStatusBadge((detail.agent as any).Status) : <span className="text-neutral-200">{v}</span>}
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <div className="flex flex-col items-center gap-3 py-4">
                                    <p className="text-xs text-[#888] font-mono">No agent registered for this server.</p>
                                    {can('infrastructure.servers.manage') && (<button onClick={() => onRegisterAgent(server.ServerId)} className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-neutral-500/10 border border-neutral-500/30 text-red-400 text-xs font-mono hover:bg-neutral-500/20 transition-colors">
                                        <Plus size={13}/> Register Agent
                                    </button>)}
                                </div>
                            )}
                        </div>

                        {/* Shipper Info */}
                        <div className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-3">
                            <div className="flex items-center justify-between">
                                <h4 className="text-xs font-bold text-[#AAA] uppercase tracking-widest font-mono">Log Shipper</h4>
                                {can('infrastructure.shippers.manage') && !detail.shipper.isRegistered && (
                                    <button onClick={() => setShowRegisterShipper(true)} className="flex items-center gap-1 px-2.5 py-1 rounded bg-neutral-500/10 border border-neutral-500/30 text-white text-[10px] font-mono hover:bg-neutral-500/20 transition-colors">
                                        <Plus size={10}/> Register
                                    </button>
                                )}
                            </div>
                            {detail.shipper.isRegistered ? (
                                <>
                                    <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs font-mono">
                                        {[
                                            ['Shipper ID', detail.shipper.ShipperId],
                                            ['Allowed IP', detail.shipper.AllowedIp],
                                            ['Registered', fmtDate(detail.shipper.CreatedAt)],
                                        ].map(([k, v]) => (
                                            <div key={k}><span className="text-neutral-600">{k}: </span><span className="text-neutral-200">{v}</span></div>
                                        ))}
                                        <div>
                                            <span className="text-neutral-600">Status: </span>
                                            <span className={detail.shipper.Active ? 'text-white' : 'text-red-400'}>
                                                {detail.shipper.Active ? 'Active' : 'Inactive'}
                                            </span>
                                        </div>
                                    </div>
                                    {shipperActionError && (
                                        <div className="flex items-center gap-1.5 text-[11px] text-red-400 bg-red-500/10 border border-red-500/30 rounded px-2 py-1">
                                            <AlertTriangle size={11}/>{shipperActionError}
                                        </div>
                                    )}
                                    {can('infrastructure.shippers.manage') && (<div className="flex gap-2 pt-1 flex-wrap">
                                        {detail.shipper.Active ? (
                                            <button
                                                onClick={async () => {
                                                    setShipperActionLoading(true); setShipperActionError('');
                                                    try {
                                                        await adminService.deactivateShipper({ ShipperId: (detail.shipper as any).ShipperId });
                                                        await loadDetail(); onShipperChanged();
                                                    } catch (e: any) { setShipperActionError(e?.response?.data?.message ?? 'Failed'); }
                                                    finally { setShipperActionLoading(false); }
                                                }}
                                                disabled={shipperActionLoading}
                                                className="flex items-center gap-1 px-3 py-1.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[11px] font-mono hover:bg-red-500/20 transition-colors disabled:opacity-50"
                                            >
                                                {shipperActionLoading ? <Loader2 size={11} className="animate-spin"/> : <WifiOff size={11}/>} Deactivate
                                            </button>
                                        ) : (
                                            <button
                                                onClick={async () => {
                                                    setShipperActionLoading(true); setShipperActionError('');
                                                    try {
                                                        await adminService.reactivateShipper({ ShipperId: (detail.shipper as any).ShipperId });
                                                        await loadDetail(); onShipperChanged();
                                                    } catch (e: any) { setShipperActionError(e?.response?.data?.message ?? 'Failed'); }
                                                    finally { setShipperActionLoading(false); }
                                                }}
                                                disabled={shipperActionLoading}
                                                className="flex items-center gap-1 px-3 py-1.5 rounded bg-neutral-500/10 border border-neutral-500/30 text-white text-[11px] font-mono hover:bg-neutral-500/20 transition-colors disabled:opacity-50"
                                            >
                                                {shipperActionLoading ? <Loader2 size={11} className="animate-spin"/> : <Radio size={11}/>} Reactivate
                                            </button>
                                        )}
                                        <button
                                            onClick={() => doDeleteShipper((detail.shipper as any).ShipperId)}
                                            disabled={shipperActionLoading}
                                            className="flex items-center gap-1 px-3 py-1.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[11px] font-mono hover:bg-red-500/20 transition-colors disabled:opacity-50"
                                        >
                                            <Trash2 size={11}/> Delete
                                        </button>
                                    </div>)}
                                </>
                            ) : (
                                <p className="text-xs text-[#888] font-mono">No log shipper registered for this server.</p>
                            )}
                        </div>
                        {/* Register Shipper Modal */}
                        {showRegisterShipper && (
                            <RegisterShipperModal
                                serverId={server.ServerId}
                                defaultIp={server.PublicIp}
                                onSuccess={res => { setShowRegisterShipper(false); setShipperToken(res); loadDetail(); onShipperChanged(); }}
                                onClose={() => setShowRegisterShipper(false)}
                            />
                        )}
                        {/* Shipper Token Modal */}
                        {shipperToken && <ShipperTokenModal result={shipperToken} onClose={() => setShipperToken(null)} />}

                        {/* Recent Deployments */}
                        {detail.deployments.length > 0 && (
                            <div className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-3">
                                <h4 className="text-xs font-bold text-[#AAA] uppercase tracking-widest font-mono">Deployments ({detail.deployments.length})</h4>
                                <div className="space-y-1.5">
                                    {detail.deployments.map(dep => (
                                        <div key={dep.DeploymentId} className="flex items-center justify-between py-1.5 border-b border-[#222] last:border-0">
                                            <div>
                                                <span className="text-xs text-neutral-200 font-mono">{dep.StackName}</span>
                                                <span className="text-[10px] text-[#888] ml-2">{dep.TemplateId}</span>
                                            </div>
                                            {deployStatusBadge(dep.Status)}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* ── CONTAINERS ── */}
                {tab === 'containers' && !loading && (
                    !isOnline ? (
                        <div className="flex flex-col items-center justify-center h-40 gap-3">
                            <WifiOff size={28} className="text-neutral-600"/>
                            <p className="text-sm text-[#888] font-mono">Agent is offline. Container operations unavailable.</p>
                        </div>
                    ) : (
                        <div className="space-y-3">
                            <div className="flex justify-between items-center">
                                <span className="text-xs text-[#888] font-mono">{containers?.count ?? 0} containers</span>
                                <button onClick={loadContainers} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><RefreshCw size={13}/></button>
                            </div>
                            {containers?.containers.map(c => (
                                <div key={c.id} className={`border rounded-xl p-3 ${c.isXyberah ? 'border-red-500/20 bg-red-500/5' : 'border-[#222] bg-[#111]'}`}>
                                    <div className="flex items-start justify-between gap-2">
                                        <div className="min-w-0">
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <span className="text-xs font-bold text-white font-mono truncate">{c.name}</span>
                                                {c.isXyberah && <span className="text-[9px] px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 text-red-500 rounded font-mono">ANTI.AI</span>}
                                                {containerStateBadge(c.state)}
                                            </div>
                                            <div className="text-[11px] text-[#888] font-mono mt-0.5">{c.image}</div>
                                            {c.ports.length > 0 && (
                                                <div className="text-[10px] text-neutral-600 font-mono mt-0.5">{c.ports.map(p => `${p.hostPort}→${p.containerPort}/${p.type}`).join(', ')}</div>
                                            )}
                                        </div>
                                        <div className="flex items-center gap-1 shrink-0">
                                            {can('infrastructure.containers.control') && (<button onClick={() => setLogTarget(c)} title="Logs" className="p-1.5 rounded hover:bg-[#1C1C1C] text-[#AAA] hover:text-white transition-colors"><Terminal size={13}/></button>)}
                                            {can('infrastructure.containers.control') && (c.state === 'running' ? (
                                                <>
                                                    <button onClick={() => doContainerAction(c, 'stop')} disabled={!!loadingAction} title="Stop" className="p-1.5 rounded hover:bg-[#1C1C1C] text-white hover:text-white transition-colors"><Square size={13}/></button>
                                                    <button onClick={() => doContainerAction(c, 'restart')} disabled={!!loadingAction} title="Restart" className="p-1.5 rounded hover:bg-[#1C1C1C] text-white hover:text-white transition-colors"><RotateCcw size={13}/></button>
                                                </>
                                            ) : (
                                                <button onClick={() => doContainerAction(c, 'start')} disabled={!!loadingAction} title="Start" className="p-1.5 rounded hover:bg-[#1C1C1C] text-white hover:text-white transition-colors"><Play size={13}/></button>
                                            ))}
                                            {can('infrastructure.containers.manage') && (<button onClick={() => doRemoveContainer(c)} disabled={!!loadingAction} title="Remove" className="p-1.5 rounded hover:bg-[#1C1C1C] text-red-400 hover:text-red-300 transition-colors"><Trash2 size={13}/></button>)}
                                        </div>
                                    </div>
                                    <div className="text-[10px] text-neutral-600 font-mono mt-1">{c.status}</div>
                                </div>
                            ))}
                        </div>
                    )
                )}

                {/* ── DEPLOYMENTS ── */}
                {tab === 'deployments' && !loading && (
                    <div className="space-y-3">
                        <div className="flex justify-between items-center">
                            <span className="text-xs text-[#888] font-mono">{deployments?.count ?? 0} deployments</span>
                            <div className="flex gap-2">
                                {can('infrastructure.deployments.manage') && isOnline && <button onClick={() => setShowDeploy(true)} className="flex items-center gap-1 px-3 py-1 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-xs font-mono hover:bg-red-500/20"><Plus size={11}/> Deploy</button>}
                                <button onClick={loadDeployments} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><RefreshCw size={13}/></button>
                            </div>
                        </div>
                        {deployments?.deployments.filter(d => d.Status !== 'removed').map(dep => (
                            <div key={dep.DeploymentId} className="bg-[#111] border border-[#222] rounded-xl p-3 space-y-1.5">
                                <div className="flex items-center justify-between">
                                    <div>
                                        <span className="text-xs font-bold text-white font-mono">{dep.StackName}</span>
                                        {dep.templateName && <span className="text-[10px] text-[#888] ml-2 font-mono">{dep.templateName}</span>}
                                    </div>
                                    <div className="flex items-center gap-2">
                                        {deployStatusBadge(dep.Status)}
                                        {can('infrastructure.deployments.manage') && dep.Status === 'active' && (
                                            <button onClick={() => doDeploymentAction(dep.DeploymentId, 'stop')} disabled={!!loadingAction} title="Stop Stack" className="p-1 rounded hover:bg-[#1C1C1C] text-white"><Square size={12}/></button>
                                        )}
                                        {can('infrastructure.deployments.manage') && dep.Status === 'stopped' && (
                                            <button onClick={() => doDeploymentAction(dep.DeploymentId, 'start')} disabled={!!loadingAction} title="Start Stack" className="p-1 rounded hover:bg-[#1C1C1C] text-white"><Play size={12}/></button>
                                        )}
                                        {can('infrastructure.deployments.manage') && (<button onClick={() => doRemoveDeployment(dep.DeploymentId, dep.StackName)} disabled={!!loadingAction} title="Remove" className="p-1 rounded hover:bg-[#1C1C1C] text-red-400"><Trash2 size={12}/></button>)}
                                    </div>
                                </div>
                                <div className="text-[10px] text-[#888] font-mono">Created {fmtDate(dep.CreatedAt)}</div>
                                {dep.ErrorMessage && <div className="text-[10px] text-red-400 font-mono">Error: {dep.ErrorMessage}</div>}
                            </div>
                        ))}
                    </div>
                )}

                {/* ── METRICS ── */}
                {tab === 'metrics' && !loading && metrics && (
                    <div className="space-y-4">
                        {metrics.note && (
                            <div className="flex items-center gap-2 text-xs text-white bg-neutral-500/10 border border-neutral-500/30 rounded-lg px-3 py-2">
                                <AlertTriangle size={13}/> Data from last snapshot — agent is currently unreachable.
                            </div>
                        )}
                        <div className="grid grid-cols-2 gap-3">
                            {[
                                { icon: Cpu, label: 'CPU Cores', value: String(metrics.resources.cpuCount), sub: metrics.docker.architecture ?? '' },
                                { icon: HardDrive, label: 'Memory', value: fmtBytes(metrics.resources.memoryTotalBytes) , sub: `${metrics.resources.memoryTotalMB} MB` },
                                { icon: Box, label: 'Containers', value: `${metrics.containers.running}/${metrics.containers.total}`, sub: `${metrics.containers.stopped} stopped` },
                                { icon: Package, label: 'Images', value: String(metrics.storage.images), sub: `${metrics.storage.volumes} volumes` },
                            ].map(m => (
                                <div key={m.label} className="bg-[#111] border border-[#222] rounded-xl p-3">
                                    <div className="flex items-center gap-1.5 mb-2"><m.icon size={14} className="text-red-500"/><span className="text-[10px] text-[#AAA] font-mono uppercase tracking-wider">{m.label}</span></div>
                                    <div className="text-xl font-bold text-white font-cyber">{m.value}</div>
                                    <div className="text-[10px] text-[#888] font-mono">{m.sub}</div>
                                </div>
                            ))}
                        </div>
                        <div className="bg-[#111] border border-[#222] rounded-xl p-4 space-y-2">
                            <h4 className="text-xs font-bold text-[#AAA] uppercase tracking-widest font-mono">Docker Engine</h4>
                            {[
                                ['Version', metrics.docker.version],
                                ['OS', metrics.docker.os ?? '—'],
                                ['Kernel', metrics.docker.kernelVersion ?? '—'],
                                ['Architecture', metrics.docker.architecture ?? '—'],
                                ['Last Heartbeat', fmtDate(metrics.lastHeartbeat)],
                            ].map(([k, v]) => (
                                <div key={k} className="flex justify-between text-xs font-mono">
                                    <span className="text-neutral-600">{k}</span><span className="text-neutral-200">{v}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </div>

            {/* Modals */}
            {logTarget && agentId && <ContainerLogsModal agentId={agentId} container={logTarget} onClose={() => setLogTarget(null)} />}
            {showDeploy && agentId && (
                <DeployModal agentId={agentId} templates={templates}
                    onSuccess={() => { setShowDeploy(false); setTab('deployments'); loadDeployments(); }}
                    onClose={() => setShowDeploy(false)}
                />
            )}
            {confirm && <ConfirmDialog {...confirm} onConfirm={confirm.action} danger onCancel={() => setConfirm(null)} />}
        </div>
    );
};

// ── Templates Panel ────────────────────────────────────────────────────────

const TemplatesPanel: React.FC<{ templates: DeploymentTemplate[]; loading: boolean; onRefresh: () => void }> = ({ templates, loading, onRefresh }) => {
    const can = useCan();
    const [filterCat, setFilterCat] = useState<TemplateCategory | 'all'>('all');
    const [editTarget, setEditTarget] = useState<DeploymentTemplate | null | undefined>(undefined); // undefined=closed, null=create
    const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => void } | null>(null);
    const [actionError, setActionError] = useState('');

    const displayed = filterCat === 'all' ? templates : templates.filter(t => t.Category === filterCat);

    const toggleActive = async (t: DeploymentTemplate) => {
        setActionError('');
        try { await agentService.updateTemplate(t.TemplateId, { IsActive: !t.IsActive }); onRefresh(); }
        catch (e: any) { setActionError(e?.response?.data?.message ?? 'Failed to update template'); }
    };

    const deleteTemplate = (t: DeploymentTemplate) => {
        setConfirm({
            title: 'Delete Template',
            message: `Delete template "${t.Name}"? This will fail if active deployments reference it.`,
            action: async () => {
                setConfirm(null); setActionError('');
                try { await agentService.deleteTemplate(t.TemplateId); onRefresh(); }
                catch (e: any) { setActionError(e?.response?.data?.message ?? 'Failed to delete template'); }
            }
        });
    };

    const catColors: Record<string, string> = {
        honeypot: 'text-white bg-neutral-500/10 border-neutral-500/30',
        utility:  'text-red-400   bg-[#151515]/10   border-neutral-500/30',
        monitoring:'text-red-400 bg-neutral-500/10 border-neutral-500/30',
    };

    return (
        <div className="flex flex-col h-full">
            <div className="p-4 border-b border-[#222] flex items-center justify-between shrink-0">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-[#111] rounded-lg border border-neutral-500/30 text-red-400"><Layers size={18}/></div>
                    <div>
                        <h3 className="text-base font-bold text-white font-cyber">DEPLOYMENT <span className="text-red-400">TEMPLATES</span></h3>
                        <p className="text-xs text-[#888] font-mono">{templates.length} templates</p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <div className="flex gap-1">
                        {(['all', 'honeypot', 'utility', 'monitoring'] as const).map(c => (
                            <button key={c} onClick={() => setFilterCat(c)} className={`px-2 py-1 rounded text-[10px] font-mono transition-colors ${filterCat === c ? 'bg-[#1C1C1C] text-white' : 'text-[#888] hover:text-neutral-300'}`}>{c}</button>
                        ))}
                    </div>
                    <button onClick={onRefresh} disabled={loading} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><RefreshCw size={14} className={loading ? 'animate-spin' : ''}/></button>
                    {can('infrastructure.templates.manage') && (<button onClick={() => setEditTarget(null)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-xs font-mono hover:bg-red-500/20"><Plus size={13}/> New</button>)}
                </div>
            </div>

            {actionError && (
                <div className="mx-4 mt-3 flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                    <AlertTriangle size={13}/>{actionError}
                    <button onClick={() => setActionError('')} className="ml-auto"><X size={12}/></button>
                </div>
            )}

            <div className="flex-1 overflow-y-auto custom-scrollbar p-4">
                {loading && <div className="flex items-center gap-2 text-xs text-[#888] font-mono"><Loader2 size={14} className="animate-spin"/>Loading templates...</div>}
                {!loading && displayed.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-40 gap-3 text-neutral-600">
                        <Layers size={28}/>
                        <p className="text-sm font-mono">No templates found. Create one to get started.</p>
                    </div>
                )}
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                    {displayed.map(t => (
                        <div key={t.TemplateId} className={`bg-[#111] border rounded-xl p-4 flex flex-col gap-3 ${t.IsActive ? 'border-[#333]' : 'border-[#222] opacity-60'}`}>
                            <div className="flex items-start justify-between gap-2">
                                <div className="min-w-0">
                                    <div className="text-sm font-bold text-white font-mono truncate">{t.Name}</div>
                                    <span className={`inline-block mt-1 px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${catColors[t.Category] ?? 'text-[#AAA] bg-[#1C1C1C] border-neutral-600'}`}>{t.Category}</span>
                                </div>
                                {can('infrastructure.templates.manage') && (<div className="flex items-center gap-1 shrink-0">
                                    <button onClick={() => setEditTarget(t)} title="Edit" className="p-1.5 rounded hover:bg-[#1C1C1C] text-[#AAA] hover:text-white transition-colors"><Edit2 size={13}/></button>
                                    <button onClick={() => toggleActive(t)} title={t.IsActive ? 'Deactivate' : 'Activate'} className={`p-1.5 rounded hover:bg-[#1C1C1C] transition-colors ${t.IsActive ? 'text-white' : 'text-neutral-600'}`}>{t.IsActive ? <ToggleRight size={15}/> : <ToggleLeft size={15}/>}</button>
                                    <button onClick={() => deleteTemplate(t)} title="Delete" className="p-1.5 rounded hover:bg-[#1C1C1C] text-red-400 hover:text-red-300 transition-colors"><Trash2 size={13}/></button>
                                </div>)}
                            </div>
                            {t.Description && <p className="text-xs text-[#888]">{t.Description}</p>}
                            {Object.keys(t.EnvTemplate ?? {}).length > 0 && (
                                <div className="text-[10px] text-neutral-600 font-mono">
                                    Env: {Object.keys(t.EnvTemplate).join(', ')}
                                </div>
                            )}
                            <div className="text-[10px] text-neutral-600 font-mono">Updated {fmtDate(t.UpdatedAt)}</div>
                        </div>
                    ))}
                </div>
            </div>

            {editTarget !== undefined && (
                <TemplateFormModal template={editTarget} onSuccess={() => { setEditTarget(undefined); onRefresh(); }} onClose={() => setEditTarget(undefined)} />
            )}
            {confirm && <ConfirmDialog {...confirm} onConfirm={confirm.action} danger onCancel={() => setConfirm(null)} />}
        </div>
    );
};

// ── Shippers Panel ────────────────────────────────────────────────────────

const ShippersPanel: React.FC<{
    shippers: Shipper[];
    loading: boolean;
    onRefresh: () => void;
}> = ({ shippers, loading, onRefresh }) => {
    const can = useCan();
    const [actionLoading, setActionLoading] = useState<string | null>(null);
    const [actionError, setActionError] = useState('');
    const [confirm, setConfirm] = useState<{ title: string; message: string; action: () => void } | null>(null);

    const toggle = async (s: Shipper) => {
        setActionLoading(s.ShipperId); setActionError('');
        try {
            if (s.Active) {
                await adminService.deactivateShipper({ ShipperId: s.ShipperId });
            } else {
                await adminService.reactivateShipper({ ShipperId: s.ShipperId });
            }
            onRefresh();
        } catch (e: any) {
            setActionError(e?.response?.data?.message ?? 'Action failed');
        } finally { setActionLoading(null); }
    };

    const doDelete = (s: Shipper) => {
        setConfirm({
            title: 'Delete Shipper',
            message: `Permanently delete shipper "${s.ShipperId}" for server "${s.ServerId}"? This cannot be undone.`,
            action: async () => {
                setConfirm(null); setActionLoading(s.ShipperId); setActionError('');
                try { await adminService.deleteShipper(s.ShipperId); onRefresh(); }
                catch (e: any) { setActionError(e?.response?.data?.message ?? 'Failed to delete shipper'); }
                finally { setActionLoading(null); }
            }
        });
    };

    return (
        <div className="flex flex-col h-full overflow-hidden">
            <div className="p-4 border-b border-[#222] flex items-center justify-between shrink-0">
                <div className="flex items-center gap-2">
                    <Radio size={16} className="text-white"/>
                    <h3 className="text-sm font-bold text-white font-cyber">LOG <span className="text-white">SHIPPERS</span></h3>
                    <span className="text-xs text-[#888] font-mono">{shippers.length} registered</span>
                </div>
                <button onClick={onRefresh} disabled={loading} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white">
                    <RefreshCw size={13} className={loading ? 'animate-spin' : ''}/>
                </button>
            </div>

            {actionError && (
                <div className="mx-4 mt-3 flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                    <AlertTriangle size={13}/>{actionError}
                    <button onClick={() => setActionError('')} className="ml-auto"><X size={12}/></button>
                </div>
            )}

            <div className="flex-1 overflow-y-auto custom-scrollbar">
                {loading && shippers.length === 0 && (
                    <div className="flex items-center gap-2 text-xs text-[#888] font-mono p-4"><Loader2 size={14} className="animate-spin"/>Loading shippers...</div>
                )}
                {!loading && shippers.length === 0 && (
                    <div className="flex flex-col items-center justify-center h-40 gap-2">
                        <Radio size={28} className="text-neutral-700"/>
                        <p className="text-sm text-[#888] font-mono">No log shippers registered.</p>
                        <p className="text-xs text-neutral-600 font-mono">Register a shipper from a server's detail panel.</p>
                    </div>
                )}
                {shippers.length > 0 && (
                    <div className="overflow-x-auto">
                        <table className="w-full text-xs font-mono">
                            <thead>
                                <tr className="border-b border-[#222] text-[10px] text-neutral-600 uppercase tracking-widest">
                                    <th className="text-left px-4 py-2">Shipper ID</th>
                                    <th className="text-left px-4 py-2">Server ID</th>
                                    <th className="text-left px-4 py-2">Allowed IP</th>
                                    <th className="text-left px-4 py-2">Status</th>
                                    <th className="text-left px-4 py-2">Last Seen</th>
                                    <th className="text-left px-4 py-2">Registered</th>
                                    <th className="px-4 py-2">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                {shippers.map(s => (
                                    <tr key={s.ShipperId} className="border-b border-[#222]/60 hover:bg-white/5 transition-colors">
                                        <td className="px-4 py-3 text-neutral-200">
                                            <div className="flex items-center gap-1.5">
                                                <span>{s.ShipperId.slice(0, 8)}...</span>
                                                <CopyButton text={s.ShipperId} className="text-neutral-600"/>
                                            </div>
                                        </td>
                                        <td className="px-4 py-3 text-neutral-300">{s.ServerId}</td>
                                        <td className="px-4 py-3 text-neutral-300">{s.AllowedIp}</td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-0.5 rounded border font-bold ${s.Active ? 'text-white bg-neutral-500/10 border-neutral-500/30' : 'text-[#AAA] bg-[#151515] border-[#333]'}`}>
                                                {s.Active ? 'ACTIVE' : 'INACTIVE'}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-[#888]">{s.LastSeenAt ? fmtDate(s.LastSeenAt) : '—'}</td>
                                        <td className="px-4 py-3 text-[#888]">{fmtDate(s.CreatedAt)}</td>
                                        <td className="px-4 py-3">
                                            {can('infrastructure.shippers.manage') && (<div className="flex items-center justify-center gap-1.5">
                                                <button
                                                    onClick={() => toggle(s)}
                                                    disabled={actionLoading === s.ShipperId}
                                                    className={`flex items-center gap-1 px-2.5 py-1 rounded border text-[10px] transition-colors disabled:opacity-50 ${
                                                        s.Active
                                                        ? 'text-red-400 bg-red-500/10 border-red-500/30 hover:bg-red-500/20'
                                                        : 'text-white bg-neutral-500/10 border-neutral-500/30 hover:bg-neutral-500/20'
                                                    }`}
                                                >
                                                    {actionLoading === s.ShipperId
                                                        ? <Loader2 size={10} className="animate-spin"/>
                                                        : s.Active ? <WifiOff size={10}/> : <Radio size={10}/>}
                                                    {s.Active ? 'Deactivate' : 'Reactivate'}
                                                </button>
                                                <button
                                                    onClick={() => doDelete(s)}
                                                    disabled={actionLoading === s.ShipperId}
                                                    title="Delete shipper"
                                                    className="p-1.5 rounded hover:bg-red-900/30 text-red-500/60 hover:text-red-400 transition-colors disabled:opacity-50"
                                                >
                                                    <Trash2 size={11}/>
                                                </button>
                                            </div>)}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
            {confirm && <ConfirmDialog {...confirm} onConfirm={confirm.action} danger onCancel={() => setConfirm(null)} />}
        </div>
    );
};

// ── Main InfrastructureView ────────────────────────────────────────────────

type InfraTab = 'servers' | 'templates' | 'shippers';

export const InfrastructureView: React.FC = () => {
    const can = useCan();
    const [infraTab, setInfraTab] = useState<InfraTab>('servers');
    const [overview, setOverview] = useState<ServersOverviewResponse | null>(null);
    const [templates, setTemplates] = useState<ListTemplatesResponse | null>(null);
    const [shippers, setShippers] = useState<Shipper[]>([]);
    const [loadingOverview, setLoadingOverview] = useState(false);
    const [loadingTemplates, setLoadingTemplates] = useState(false);
    const [loadingShippers, setLoadingShippers] = useState(false);
    const [overviewError, setOverviewError] = useState('');
    const [selectedServer, setSelectedServer] = useState<ServerOverviewItem | null>(null);
    const [portainerHealth, setPortainerHealth] = useState<'healthy' | 'unhealthy' | 'unknown'>('unknown');
    const [registerTarget, setRegisterTarget] = useState<RegisterAgentResponse | null>(null);
    const [registerLoading, setRegisterLoading] = useState(false);
    const [registerError, setRegisterError] = useState('');
    const [showRegisterServer, setShowRegisterServer] = useState(false);
    // Portainer health is a platform-staff endpoint (403 for customer accounts), so only query it for staff.
    const { admin, permissionsLoaded } = useAuth();
    const isPlatformUser = !admin?.CustomerID;

    const loadShippers = useCallback(async () => {
        if (isPublicDemo()) return;
        setLoadingShippers(true);
        try {
            const res = await adminService.listShippers();
            setShippers(res.shippers);
        } catch { /* silent */ }
        finally { setLoadingShippers(false); }
    }, []);

    const loadOverview = useCallback(async () => {
        if (isPublicDemo()) return;
        setLoadingOverview(true); setOverviewError('');
        try {
            const d = await agentService.getServersOverview();
            setOverview(d);
            // refresh selected server data if selected
            if (selectedServer) {
                const updated = d.servers.find(s => s.ServerId === selectedServer.ServerId);
                if (updated) setSelectedServer(updated);
            }
        } catch (e: any) {
            setOverviewError(e?.response?.data?.message ?? 'Failed to load server overview');
        } finally { setLoadingOverview(false); }
    }, [selectedServer]);

    const loadTemplates = useCallback(async () => {
        if (isPublicDemo()) return;
        setLoadingTemplates(true);
        try {
            const t = await agentService.listTemplates();
            setTemplates(t);
        } finally { setLoadingTemplates(false); }
    }, []);

    const checkPortainerHealth = useCallback(async () => {
        if (!permissionsLoaded || !isPlatformUser) return;
        try {
            const h = await agentService.getPortainerHealth();
            setPortainerHealth(h.status);
        } catch { setPortainerHealth('unhealthy'); }
    }, [permissionsLoaded, isPlatformUser]);

    useEffect(() => {
        loadOverview();
        loadTemplates();
        loadShippers();
    }, []);

    useEffect(() => {
        checkPortainerHealth();
    }, [checkPortainerHealth]);

    const handleRegisterAgent = async (serverId: string) => {
        setRegisterLoading(true); setRegisterError('');
        try {
            const res = await agentService.registerAgent({ ServerId: serverId });
            setRegisterTarget(res);
            await loadOverview();
        } catch (e: any) {
            setRegisterError(e?.response?.data?.message ?? 'Failed to register agent');
        } finally { setRegisterLoading(false); }
    };

    const onlineCount = overview?.servers.filter(s => s.agent.isRegistered && s.agent.status === 'online').length ?? 0;
    const pendingCount = overview?.servers.filter(s => s.agent.isRegistered && s.agent.status === 'pending').length ?? 0;
    const offlineCount = overview?.servers.filter(s => s.agent.isRegistered && s.agent.status === 'offline').length ?? 0;
    const totalServers = overview?.servers.length ?? 0;

    return (
        <div className="h-full flex flex-col bg-cyber-grid relative">
            {/* Top Header */}
            <div className="p-4 border-b border-[#222] bg-[#111]/40 backdrop-blur-sm flex items-center justify-between shrink-0">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-[#111] rounded-lg border border-neutral-500/30 text-red-400"><MonitorCog size={20}/></div>
                    <div>
                        <h2 className="text-lg font-bold text-white font-cyber flex items-center gap-2">
                            INFRASTRUCTURE <span className="text-red-500">MANAGER</span>
                        </h2>
                        <p className="text-xs text-[#888] font-mono">Servers · Agents · Shippers · Deployments</p>
                    </div>
                </div>
                <div className="flex items-center gap-4">
                    {/* Stats */}
                    <div className="hidden md:flex items-center gap-3 text-xs font-mono">
                        <span className="text-[#888]">{totalServers} servers</span>
                        {onlineCount > 0 && <span className="text-white">{onlineCount} online</span>}
                        {pendingCount > 0 && <span className="text-white">{pendingCount} pending</span>}
                        {offlineCount > 0 && <span className="text-red-400">{offlineCount} offline</span>}
                    </div>
                    {/* Portainer Health */}
                    {isPlatformUser && (
                        <div className={`flex items-center gap-1.5 px-2 py-1 rounded border text-[10px] font-mono ${
                            portainerHealth === 'healthy' ? 'text-white bg-neutral-500/10 border-neutral-500/30' :
                            portainerHealth === 'unhealthy' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
                            'text-[#888] bg-[#151515] border-[#333]'
                        }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${portainerHealth === 'healthy' ? 'bg-neutral-500 animate-pulse' : portainerHealth === 'unhealthy' ? 'bg-red-500' : 'bg-neutral-600'}`}/>
                            PORTAINER {portainerHealth.toUpperCase()}
                        </div>
                    )}
                    <button onClick={() => { loadOverview(); loadTemplates(); checkPortainerHealth(); }} disabled={loadingOverview} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white transition-colors" title="Refresh">
                        <RefreshCw size={15} className={loadingOverview ? 'animate-spin' : ''}/>
                    </button>
                </div>
            </div>

            {/* Section Tab Bar */}
            <div className="flex border-b border-[#222] bg-[#111]/30 shrink-0">
                {([
                    { id: 'servers' as InfraTab, label: 'SERVERS & AGENTS', icon: Server },
                    { id: 'shippers' as InfraTab, label: 'SHIPPERS', icon: Radio },
                    { id: 'templates' as InfraTab, label: 'TEMPLATES', icon: Layers },
                ] as const).map(t => (
                    <button key={t.id} onClick={() => setInfraTab(t.id)} className={`flex items-center gap-2 px-5 py-3 text-xs font-mono font-bold border-b-2 transition-colors ${infraTab === t.id ? 'text-red-500 border-red-500 bg-red-500/5' : 'text-[#888] border-transparent hover:text-neutral-300'}`}>
                        <t.icon size={14}/>{t.label}
                    </button>
                ))}
            </div>

            {/* register error banner */}
            {registerError && (
                <div className="mx-4 mt-3 flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                    <AlertTriangle size={13}/>{registerError}
                    <button onClick={() => setRegisterError('')} className="ml-auto"><X size={12}/></button>
                </div>
            )}

            {/* Servers Tab */}
            {infraTab === 'servers' && (
                <div className="flex flex-1 min-h-0">
                    {/* Server List */}
                    <div className={`flex flex-col ${selectedServer ? 'w-1/2' : 'w-full'} border-r border-[#222] transition-all duration-300`}>
                        <div className="p-3 border-b border-[#222] flex items-center justify-between shrink-0">
                            <span className="text-xs text-[#888] font-mono">{overview?.count ?? 0} servers registered</span>
                            <div className="flex items-center gap-2">
                                {can('infrastructure.servers.manage') && (<button
                                    onClick={() => setShowRegisterServer(true)}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-[11px] font-mono font-bold hover:bg-red-500/20 transition-colors"
                                >
                                    <Plus size={12}/> Register Server
                                </button>)}
                                <button onClick={loadOverview} disabled={loadingOverview} className="p-1.5 rounded hover:bg-[#151515] text-[#AAA] hover:text-white"><RefreshCw size={13} className={loadingOverview ? 'animate-spin' : ''}/></button>
                            </div>
                        </div>
                        {overviewError && (
                            <div className="m-3 flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
                                <AlertTriangle size={13}/>{overviewError}
                            </div>
                        )}
                        {loadingOverview && !overview && (
                            <div className="flex items-center gap-2 text-xs text-[#888] font-mono p-4"><Loader2 size={14} className="animate-spin"/>Loading servers...</div>
                        )}
                        <div className="flex-1 overflow-y-auto custom-scrollbar">
                            {/* Table Header */}
                            <div className="grid grid-cols-[1fr_auto_auto_auto] gap-3 px-4 py-2 text-[10px] text-neutral-600 font-mono font-bold uppercase tracking-widest border-b border-[#222] sticky top-0 bg-[#111]/80 backdrop-blur-sm">
                                <span>Server</span>
                                <span>Agent</span>
                                <span>Shipper</span>
                                <span>Deployments</span>
                            </div>
                            {overview?.servers.map(srv => (
                                <button key={srv.ServerId} onClick={() => setSelectedServer(selectedServer?.ServerId === srv.ServerId ? null : srv)} className={`w-full grid grid-cols-[1fr_auto_auto_auto] gap-3 items-center px-4 py-3 border-b border-[#222] text-left transition-colors hover:bg-white/5 ${selectedServer?.ServerId === srv.ServerId ? 'bg-red-500/5 border-l-2 border-l-red-500' : ''}`}>
                                    <div className="min-w-0">
                                        <div className="text-sm font-bold text-white font-mono truncate">{srv.Hostname}</div>
                                        <div className="text-[11px] text-[#888] font-mono">{srv.PublicIp} · {srv.Region} · {srv.Provider}</div>
                                    </div>
                                    <div>{agentStatusBadge(srv.agent.isRegistered ? srv.agent.status : 'none')}</div>
                                    <div>
                                        {srv.shipper.isRegistered ? (
                                            <span className={`px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${srv.shipper.active ? 'text-white bg-neutral-500/10 border-neutral-500/30' : 'text-[#AAA] bg-[#1C1C1C] border-neutral-600'}`}>
                                                {srv.shipper.active ? 'ACTIVE' : 'INACTIVE'}
                                            </span>
                                        ) : (
                                            <span className="px-2 py-0.5 rounded border text-[10px] font-mono text-neutral-600 bg-[#111] border-[#222]">NONE</span>
                                        )}
                                    </div>
                                    <div className="text-center">
                                        <span className="text-xs font-mono text-neutral-300">{srv.deployments.active}</span>
                                        <span className="text-[10px] text-neutral-600 font-mono">/{srv.deployments.total}</span>
                                    </div>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Server Detail Panel */}
                    {selectedServer && (
                        <div className="w-1/2 min-h-0 flex flex-col">
                            <ServerDetailPanel
                                key={selectedServer.ServerId}
                                server={selectedServer}
                                onClose={() => setSelectedServer(null)}
                                onRegisterAgent={handleRegisterAgent}
                                onRefreshList={loadOverview}
                                onShipperChanged={() => { loadOverview(); loadShippers(); }}
                                templates={templates?.templates ?? []}
                            />
                        </div>
                    )}
                </div>
            )}

            {/* Templates Tab */}
            {infraTab === 'templates' && (
                <div className="flex-1 min-h-0 overflow-hidden">
                    <TemplatesPanel
                        templates={templates?.templates ?? []}
                        loading={loadingTemplates}
                        onRefresh={loadTemplates}
                    />
                </div>
            )}

            {/* Shippers Tab */}
            {infraTab === 'shippers' && (
                <div className="flex-1 min-h-0 overflow-hidden">
                    <ShippersPanel
                        shippers={shippers}
                        loading={loadingShippers}
                        onRefresh={loadShippers}
                    />
                </div>
            )}

            {/* Register Agent Install Modal */}
            {registerTarget && (
                <InstallCommandModal result={registerTarget} onClose={() => { setRegisterTarget(null); loadOverview(); }} />
            )}

            {/* Register Server Modal */}
            {showRegisterServer && (
                <RegisterServerModal
                    onSuccess={() => { setShowRegisterServer(false); loadOverview(); }}
                    onClose={() => setShowRegisterServer(false)}
                />
            )}

            {registerLoading && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#111]/60 backdrop-blur-sm">
                    <div className="flex items-center gap-3 text-red-500 font-mono text-sm">
                        <Loader2 size={20} className="animate-spin"/> Registering agent with Portainer...
                    </div>
                </div>
            )}
        </div>
    );
};

