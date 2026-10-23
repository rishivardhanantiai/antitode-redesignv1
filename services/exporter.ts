
import { AnalyzedHost, WebCheckResult, StrideThreat } from '../types';
import type { HostV3 } from '../api/services';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import * as htmlToImage from 'html-to-image';

export const generateCSV = (data: AnalyzedHost[]): string => {
  const headers = [
    'IP Address', 
    'Country', 
    'Risk Level', 
    'Total Score', 
    'Signatures Count', 
    'Detected Behaviors', 
    'MITRE Tactics', 
    'MITRE Techniques',
    'Base Score',
    'Persistence Bonus',
    'Threat Intel Bonus',
    'APT Bonus',
    'RBL Penalty',
    'Multi-Source Bonus'
  ];

  const rows = data.map(host => {
    const behaviors = host.signatures.map(s => s.name).join('; ');
    const tactics = Array.from(new Set(host.signatures.map(s => s.mitreTactic))).join('; ');
    const techniques = Array.from(new Set(host.signatures.map(s => s.mitreId))).join('; ');
    
    const sb = host.scoreBreakdown || { 
        base: 0, 
        persistenceBonus: 0, 
        frequencyBonus: 0,
        rarityBonus: 0,
        tacticBonus: 0,
        aptBonus: 0, 
        threatIntelBonus: 0, 
        rblPenalty: 0,
        multiSourceBonus: 0
    };
    
    const safeStr = (str: string) => `"${str.replace(/"/g, '""')}"`;

    return [
      host.ip,
      host.country,
      host.riskLevel,
      host.totalScore,
      host.signatures.length,
      safeStr(behaviors),
      safeStr(tactics),
      safeStr(techniques),
      sb.base,
      sb.persistenceBonus,
      sb.threatIntelBonus || 0,
      sb.aptBonus || 0,
      sb.rblPenalty || 0,
      sb.multiSourceBonus || 0
    ].join(',');
  });

  return [headers.join(','), ...rows].join('\n');
};

export const generateIOCList = (data: AnalyzedHost[]): string => {
    return data.map(h => h.ip).join('\n');
};

export const generateSTIX = (data: AnalyzedHost[]): string => {
  const bundleId = `bundle--${crypto.randomUUID()}`;
  const timestamp = new Date().toISOString();
  
  const objects = data.map(host => {
    if (host.totalScore === 0) return null;

    const indicatorId = `indicator--${crypto.randomUUID()}`;
    
    return {
      type: "indicator",
      id: indicatorId,
      created: timestamp,
      modified: timestamp,
      name: `Malicious Activity detected from ${host.ip}`,
      description: `Detected behaviors: ${host.signatures.map(s => s.name).join(', ')}`,
      pattern: `[ipv4-addr:value = '${host.ip}']`,
      pattern_type: "stix",
      valid_from: timestamp,
      labels: ["malicious-activity", ...host.signatures.map(s => s.name.toLowerCase().replace(/\s+/g, '-'))],
      confidence: host.totalScore
    };
  }).filter(Boolean);

  const bundle = {
    type: "bundle",
    id: bundleId,
    objects: objects
  };

  return JSON.stringify(bundle, null, 2);
};

const csvEscape = (v: string | number | boolean | null | undefined): string => {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  const s = String(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
};

/** CSV export for Log Analysis (V3 host list). */
export const generateLogAnalysisCsvV3 = (hosts: HostV3[]): string => {
  const headers = [
    'IP Address',
    'First Seen',
    'Last Seen',
    'Last Updated',
    'Risk Level',
    'Threat Score',
    'Total Events',
    'Total Commands',
    'Unique Sessions',
    'Active Days',
    'Country',
    'City',
    'Latitude',
    'Longitude',
    'ASN Number',
    'ASN Organization',
    'Is Cloud',
    'Is Tor',
    'Is Private',
    'Detection Labels',
    'Honeypots Targeted',
    'DNS Hostname',
  ];
  const rows = hosts.map((h) =>
    [
      csvEscape(h.src_ip),
      csvEscape(h.first_seen),
      csvEscape(h.last_seen),
      csvEscape(h.last_updated),
      csvEscape(h.risk_level),
      h.threat_score,
      h.total_events,
      h.total_commands != null ? h.total_commands : '—',
      h.unique_sessions,
      h.active_days,
      csvEscape(h.geo_country),
      csvEscape(h.geo_city),
      h.geo_lat,
      h.geo_lon,
      h.asn_number,
      csvEscape(h.asn_org),
      h.ip_is_cloud,
      h.ip_is_tor,
      h.ip_is_private,
      csvEscape(h.detection_labels.join('; ')),
      csvEscape(h.honeypots_targeted.join('; ')),
      csvEscape(h.dns_hostname ?? ''),
    ].join(',')
  );
  return [headers.join(','), ...rows].join('\n');
};

/** Stable identity for `created_by_ref` on exported indicators (organization source). */
const STIX_EXPORT_IDENTITY_ID = 'identity--c1e4e7c0-8d9a-4b6e-9f2c-3a1b5e7d9c0f';

/** Normalize backend timestamps (e.g. `2026-04-05 03:19:12.409`) to RFC 3339 UTC. */
export const hostTimestampToRfc3339Utc = (s: string | null | undefined, fallbackIso: string): string => {
  if (!s || !String(s).trim()) return fallbackIso;
  const raw = String(s).trim();
  const normalized = raw.includes('T') ? raw : raw.replace(/^(\d{4}-\d{2}-\d{2})\s+(.+)$/, '$1T$2');
  const withZone = /[Zz]$|[+-]\d{2}:?\d{2}$/.test(normalized) ? normalized : `${normalized}Z`;
  const d = new Date(withZone);
  return Number.isNaN(d.getTime()) ? fallbackIso : d.toISOString();
};

/**
 * STIX 2.1 bundle (JSON): identity + indicators per host (threat_score > 0).
 */
export const generateStix21BundleJsonV3 = (hosts: HostV3[]): string => {
  const bundleId = `bundle--${crypto.randomUUID()}`;
  const timestamp = new Date().toISOString();
  const identityId = STIX_EXPORT_IDENTITY_ID;

  const identity = {
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: timestamp,
    modified: timestamp,
    name: 'ANTI.AI Honeypot System',
    identity_class: 'organization',
  };

  const indicators = hosts
    .filter((h) => h.threat_score > 0)
    .map((host) => {
      const indicatorId = `indicator--${crypto.randomUUID()}`;
      const validFrom = hostTimestampToRfc3339Utc(host.first_seen, timestamp);
      return {
        type: 'indicator',
        spec_version: '2.1',
        id: indicatorId,
        created: timestamp,
        modified: timestamp,
        created_by_ref: identityId,
        name: `Honeypot activity from ${host.src_ip}`,
        indicator_types: ['malicious-activity'],
        pattern: `[ipv4-addr:value = '${host.src_ip}']`,
        pattern_type: 'stix',
        valid_from: validFrom,
        confidence: Math.min(100, Math.max(0, Math.round(host.threat_score))),
        labels: ['honeypot', 'ip', 'scanner'],
        x_risk_level: host.risk_level,
        x_threat_score: host.threat_score,
        x_detections: [...host.detection_labels],
      };
    });

  const bundle = {
    type: 'bundle',
    spec_version: '2.1',
    id: bundleId,
    objects: [identity, ...indicators],
  };

  return JSON.stringify(bundle, null, 2);
};

export const downloadFile = (content: string | Blob, filename: string, mimeType: string) => {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

/**
 * Converts the Network Topology viewport to a Raster Image (PNG/JPEG).
 * Uses html-to-image to capture both SVG (edges) and HTML (nodes) layers correctly.
 */
export const exportTopologyImage = async (format: 'png' | 'jpeg' = 'png'): Promise<void> => {
    const rfElement = document.querySelector('.react-flow') as HTMLElement;
    if (!rfElement) {
        console.error("React Flow element not found");
        return;
    }

    try {
        // High fidelity capture settings with CORS mitigation
        const options = {
            backgroundColor: '#ffffff',
            quality: 0.95,
            pixelRatio: 2,
            cacheBust: true, // Bypass potential cached cross-origin errors
            filter: (node: HTMLElement) => {
                const exclusionClasses = ['react-flow__controls', 'react-flow__panel'];
                return !exclusionClasses.some(cls => node.classList?.contains(cls));
            }
        };

        let dataUrl = '';
        if (format === 'png') {
            dataUrl = await htmlToImage.toPng(rfElement, options);
        } else {
            dataUrl = await htmlToImage.toJpeg(rfElement, options);
        }

        const link = document.createElement('a');
        link.download = `network_topology_${Date.now()}.${format}`;
        link.href = dataUrl;
        link.click();

    } catch (error) {
        console.error('Failed to export topology image:', error);
        // Fallback for CORS issues: some browsers block rule reading even with headers
        // We warn the user to check browser console for detailed security blocks
        alert("Export failed due to browser security restrictions on external styles. Try reloading the application or ensure the diagram is fully rendered.");
    }
};

/**
 * Generates a Visio-compatible VDX (XML) file from the graph structure.
 * This is a simplified implementation of the Visio XML schema.
 */
export const exportToVisio = (nodes: any[], edges: any[]): void => {
    let xml = `<?xml version='1.0' encoding='utf-8' ?>
<VisioDocument xmlns='http://schemas.microsoft.com/visio/2003/core'>
    <Pages>
        <Page ID='0' Name='Network Topology'>
            <Shapes>`;

    nodes.forEach((node, i) => {
        const x = node.position.x / 50; // Visio uses inches/units, scale down
        const y = node.position.y / 50;
        xml += `
                <Shape ID='${i + 1}' Type='Group' Name='${node.data.label}'>
                    <XForm>
                        <PinX>${x}</PinX>
                        <PinY>${y}</PinY>
                        <W>2</W>
                        <H>1</H>
                    </XForm>
                    <Text>${node.data.label} (${node.type})</Text>
                </Shape>`;
    });

    edges.forEach((edge, i) => {
        const startIdx = nodes.findIndex(n => n.id === edge.source) + 1;
        const endIdx = nodes.findIndex(n => n.id === edge.target) + 1;
        xml += `
                <Shape ID='${nodes.length + i + 1}' Type='Edge' Name='Flow'>
                    <XForm>
                        <BeginX>0</BeginX>
                        <BeginY>0</BeginY>
                    </XForm>
                    <Connects>
                        <Connect FromSheet='${nodes.length + i + 1}' FromCell='BeginX' ToSheet='${startIdx}'/>
                        <Connect FromSheet='${nodes.length + i + 1}' FromCell='EndX' ToSheet='${endIdx}'/>
                    </Connects>
                </Shape>`;
    });

    xml += `
            </Shapes>
        </Page>
    </Pages>
</VisioDocument>`;

    downloadFile(xml, `topology_export_${Date.now()}.vdx`, 'application/vnd.visio');
};

export const generateAnalysisPDF = (data: AnalyzedHost[], logoUrl?: string) => {
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    const primaryColor = [67, 97, 238];
    const secondaryColor = [15, 23, 42];

    let yPos = 20;
    if (logoUrl) {
        try {
            doc.addImage(logoUrl, 'PNG', 14, 10, 15, 15);
            doc.setFontSize(22);
            doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
            doc.text("THREAT ANALYSIS REPORT", 35, 22);
            yPos = 35;
        } catch (e) {
            doc.setFontSize(22);
            doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
            doc.text("THREAT ANALYSIS REPORT", 14, 22);
            yPos = 35;
        }
    } else {
        doc.setFontSize(22);
        doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
        doc.text("THREAT ANALYSIS REPORT", 14, 22);
        yPos = 35;
    }

    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(`Generated: ${timestamp}`, 14, yPos);
    doc.text(`Total Objects Analyzed: ${data.length}`, 14, yPos + 5);
    
    const critical = data.filter(h => h.riskLevel === 'CRITICAL').length;
    const high = data.filter(h => h.riskLevel === 'HIGH').length;
    const medium = data.filter(h => h.riskLevel === 'MEDIUM').length;
    const low = data.filter(h => h.riskLevel === 'LOW').length;

    yPos += 15;
    const boxWidth = 40;
    const boxHeight = 20;
    const gap = 5;

    doc.setFillColor(239, 68, 68);
    doc.rect(14, yPos, boxWidth, boxHeight, 'F');
    doc.setTextColor(255);
    doc.setFontSize(14);
    doc.text(critical.toString(), 14 + (boxWidth/2), yPos + 10, { align: 'center' });
    doc.setFontSize(8);
    doc.text("CRITICAL", 14 + (boxWidth/2), yPos + 16, { align: 'center' });

    doc.setFillColor(249, 115, 22);
    doc.rect(14 + boxWidth + gap, yPos, boxWidth, boxHeight, 'F');
    doc.setTextColor(255);
    doc.setFontSize(14);
    doc.text(high.toString(), 14 + boxWidth + gap + (boxWidth/2), yPos + 10, { align: 'center' });
    doc.setFontSize(8);
    doc.text("HIGH", 14 + boxWidth + gap + (boxWidth/2), yPos + 16, { align: 'center' });

    doc.setFillColor(234, 179, 8);
    doc.rect(14 + (boxWidth + gap)*2, yPos, boxWidth, boxHeight, 'F');
    doc.setTextColor(255);
    doc.setFontSize(14);
    doc.text(medium.toString(), 14 + (boxWidth + gap)*2 + (boxWidth/2), yPos + 10, { align: 'center' });
    doc.setFontSize(8);
    doc.text("MEDIUM", 14 + (boxWidth + gap)*2 + (boxWidth/2), yPos + 16, { align: 'center' });

    doc.setFillColor(59, 130, 246);
    doc.rect(14 + (boxWidth + gap)*3, yPos, boxWidth, boxHeight, 'F');
    doc.setTextColor(255);
    doc.setFontSize(14);
    doc.text(low.toString(), 14 + (boxWidth + gap)*3 + (boxWidth/2), yPos + 10, { align: 'center' });
    doc.setFontSize(8);
    doc.text("LOW", 14 + (boxWidth + gap)*3 + (boxWidth/2), yPos + 16, { align: 'center' });

    yPos += 30;

    const tableData = data.map(h => [
        h.riskLevel,
        h.ip,
        h.country,
        h.enrichmentData?.asn?.name || 'N/A',
        h.totalScore.toString(),
        h.signatures.map(s => s.name).slice(0, 2).join(', ') + (h.signatures.length > 2 ? ` (+${h.signatures.length - 2})` : '')
    ]);

    autoTable(doc, {
        startY: yPos,
        head: [['Risk', 'Host IP', 'Loc', 'ASN', 'Score', 'Detections']],
        body: tableData,
        headStyles: { fillColor: secondaryColor as any },
        alternateRowStyles: { fillColor: [241, 245, 249] },
        styles: { fontSize: 8, cellPadding: 2 },
        columnStyles: {
            0: { fontStyle: 'bold' },
            5: { cellWidth: 'auto' }
        },
        didParseCell: function(data) {
            if (data.section === 'body' && data.column.index === 0) {
                const risk = data.cell.raw;
                if (risk === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
                if (risk === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
            }
        }
    });

    doc.save(`analysis_report_${Date.now()}.pdf`);
};

export const generateThreatModelPDF = (threats: StrideThreat[], nodes: any[], edges: any[], logoUrl?: string) => {
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    const primaryColor = [67, 97, 238];
    const secondaryColor = [15, 23, 42];

    let yPos = 20;
    if (logoUrl) {
        try {
            doc.addImage(logoUrl, 'PNG', 14, 10, 15, 15);
            doc.setFontSize(22);
            doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
            doc.text("STRIDE THREAT MODEL REPORT", 35, 22);
            yPos = 35;
        } catch (e) {
            doc.setFontSize(22);
            doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
            doc.text("STRIDE THREAT MODEL REPORT", 14, 22);
            yPos = 35;
        }
    } else {
        doc.setFontSize(20);
        doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
        doc.text("STRIDE THREAT MODEL REPORT", 14, 22);
        yPos = 35;
    }

    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(`Generated: ${timestamp}`, 14, yPos);
    doc.text(`Identified Threats: ${threats.length}`, 14, yPos + 5);
    doc.text(`Architecture Components: ${nodes.length} Nodes, ${edges.length} Data Flows`, 14, yPos + 10);

    yPos += 25;

    doc.setFontSize(14);
    doc.setTextColor(0);
    doc.text("Executive Summary", 14, yPos);
    yPos += 8;
    doc.setFontSize(10);
    doc.setTextColor(50);
    doc.text("The following report outlines potential architectural security risks identified using the STRIDE framework. Analysis was performed using automated intelligence context derived from the provided system graph.", 14, yPos, { maxWidth: 180 });
    
    yPos += 20;

    const tableData = threats.map(t => [
        t.category,
        t.riskLevel,
        t.description,
        t.recommendation
    ]);

    autoTable(doc, {
        startY: yPos,
        head: [['STRIDE Category', 'Risk', 'Threat Description', 'Remediation Recommendation']],
        body: tableData,
        headStyles: { fillColor: primaryColor as any },
        styles: { fontSize: 8, cellPadding: 3 },
        columnStyles: {
            0: { fontStyle: 'bold', cellWidth: 30 },
            1: { cellWidth: 20 },
            2: { cellWidth: 60 },
            3: { cellWidth: 'auto' }
        },
        didParseCell: function(data) {
            if (data.section === 'body' && data.column.index === 1) {
                const risk = String(data.cell.raw);
                if (risk === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
                if (risk === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
                if (risk === 'MEDIUM') data.cell.styles.textColor = [180, 150, 0];
            }
        }
    });

    doc.save(`threat_model_report_${Date.now()}.pdf`);
};

export const generateWebCheckPDF = (result: WebCheckResult, logoUrl?: string) => {
    const doc = new jsPDF();
    if (logoUrl) {
        try {
            doc.addImage(logoUrl, 'PNG', 14, 10, 15, 15);
            doc.setFontSize(16);
            doc.text("WEB RECONNAISSANCE REPORT", 35, 20);
        } catch(e) {
            doc.setFontSize(16);
            doc.text("WEB RECONNAISSANCE REPORT", 14, 20);
        }
    } else {
        doc.setFontSize(16);
        doc.text("WEB RECONNAISSANCE REPORT", 14, 20);
    }
    doc.setFontSize(10);
    doc.text(`Target: ${result.target}`, 14, 30);
    doc.text(`Date: ${new Date().toLocaleString()}`, 14, 35);
    doc.text(`Risk: ${result.blocklist?.summary || 'N/A'}`, 14, 40);
    let y = 50;
    if (result.ipInfo) {
        doc.setFontSize(12);
        doc.setTextColor(0, 0, 0);
        doc.text("Infrastructure", 14, y);
        y += 5;
        autoTable(doc, {
            startY: y,
            head: [['IP', 'Location', 'ASN', 'Org']],
            body: [[
                result.ipInfo.ip,
                `${result.ipInfo.city}, ${result.ipInfo.country_code}`,
                result.ipInfo.asn?.asn || 'N/A',
                result.ipInfo.company?.name || 'N/A'
            ]],
            headStyles: { fillColor: [59, 130, 246] }
        });
        y = (doc as any).lastAutoTable.finalY + 10;
    }
    if (result.dns.a.length || result.dns.mx.length) {
        doc.setFontSize(12);
        doc.text("DNS Records", 14, y);
        y += 5;
        const dnsRows = [
            ...result.dns.a.map(r => ['A', r]),
            ...result.dns.mx.map(r => ['MX', r]),
            ...result.dns.ns.map(r => ['NS', r])
        ];
        autoTable(doc, {
            startY: y,
            head: [['Type', 'Value']],
            body: dnsRows.slice(0, 15),
            headStyles: { fillColor: [147, 51, 234] }
        });
        y = (doc as any).lastAutoTable.finalY + 10;
    }
    if (Object.keys(result.http.headers).length > 0) {
        doc.setFontSize(12);
        doc.text("HTTP Headers", 14, y);
        y += 5;
        const headerRows = Object.entries(result.http.headers).map(([k, v]) => [k, v.substring(0, 60)]);
        autoTable(doc, {
            startY: y,
            head: [['Header', 'Value']],
            body: headerRows,
            headStyles: { fillColor: [34, 197, 94] },
            styles: { fontSize: 8 }
        });
        y = (doc as any).lastAutoTable.finalY + 10;
    }
    doc.save(`webcheck_${result.target.replace(/[^a-z0-9]/gi, '_')}.pdf`);
};

export const generateNetworkToolsPDF = (category: string, input: string, data: any, logoUrl?: string) => {
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    let yPos = 20;
    if (logoUrl) {
        try {
            doc.addImage(logoUrl, 'PNG', 14, 10, 15, 15);
            doc.setFontSize(18);
            doc.setTextColor(0, 0, 0);
            doc.text("NETWORK INTELLIGENCE REPORT", 35, 20);
            yPos = 35;
        } catch (e) {
            doc.setFontSize(18);
            doc.text("NETWORK INTELLIGENCE REPORT", 14, 20);
            yPos = 30;
        }
    } else {
        doc.setFontSize(18);
        doc.text("NETWORK INTELLIGENCE REPORT", 14, 20);
        yPos = 30;
    }
    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(`Module: ${category}`, 14, yPos);
    doc.text(`Target: ${input}`, 14, yPos + 5);
    doc.text(`Generated: ${timestamp}`, 14, yPos + 10);
    yPos += 20;
    if (category === 'SUPER_SCAN' && data.riskAnalysis) {
        const ra = data.riskAnalysis;
        doc.setFillColor(ra.level === 'CRITICAL' ? 220 : ra.level === 'HIGH' ? 249 : ra.level === 'MEDIUM' ? 234 : 34, 
                         ra.level === 'CRITICAL' ? 38 : ra.level === 'HIGH' ? 115 : ra.level === 'MEDIUM' ? 179 : 197, 
                         ra.level === 'CRITICAL' ? 38 : ra.level === 'HIGH' ? 22 : ra.level === 'MEDIUM' ? 8 : 94);
        doc.rect(14, yPos, 180, 20, 'F');
        doc.setTextColor(255);
        doc.setFontSize(14);
        doc.text(`RISK VERDICT: ${ra.verdict.toUpperCase()} (Score: ${ra.score}/100)`, 105, yPos + 13, { align: 'center' });
        yPos += 25;
        doc.setTextColor(0);
        doc.setFontSize(12);
        doc.text("Risk Factors", 14, yPos);
        yPos += 5;
        const factorRows = ra.factors.map((f: any) => [f.type, f.label, f.impact > 0 ? `+${f.impact}` : f.impact]);
        autoTable(doc, {
            startY: yPos,
            head: [['Type', 'Factor', 'Impact']],
            body: factorRows,
            headStyles: { fillColor: [50, 50, 50] },
            columnStyles: { 0: { fontStyle: 'bold' } }
        });
        yPos = (doc as any).lastAutoTable.finalY + 15;
    }
    if (data.enrichmentResult) {
        const d = data.enrichmentResult;
        doc.setFontSize(12);
        doc.setTextColor(0);
        doc.text("Network Identity", 14, yPos);
        yPos += 5;
        const identityData = [
            ['IP Address', d.ip],
            ['Location', `${d.city}, ${d.country_name} (${d.country_code})`],
            ['ASN', `${d.asn?.asn} - ${d.asn?.name}`],
            ['Threat Status', d.threat.is_known_attacker ? 'ATTACKER' : d.threat.is_bot ? 'BOT' : 'CLEAN'],
            ['Scores', `Threat: ${d.threat.scores?.threat_score || 0} / Trust: ${d.threat.scores?.trust_score || 0}`]
        ];
        autoTable(doc, {
            startY: yPos,
            body: identityData,
            theme: 'grid',
            styles: { fontSize: 9 }
        });
        yPos = (doc as any).lastAutoTable.finalY + 15;
    }
    if (data.dnsResults) {
        doc.setFontSize(12);
        doc.text("DNS Records", 14, yPos);
        yPos += 5;
        const dnsRows: any[] = [];
        Object.keys(data.dnsResults).forEach(provider => {
            data.dnsResults[provider].forEach((r: any) => {
                dnsRows.push([provider.toUpperCase(), r.type, r.name, String(r.data).substring(0, 50)]);
            });
        });
        if (dnsRows.length > 0) {
            autoTable(doc, {
                startY: yPos,
                head: [['Provider', 'Type', 'Name', 'Data']],
                body: dnsRows,
                headStyles: { fillColor: [100, 100, 200] }
            });
            yPos = (doc as any).lastAutoTable.finalY + 15;
        }
    }
    if (data.securityResults && data.securityResults.length > 0) {
        doc.setFontSize(12);
        doc.text("Threat Intelligence / Blocklists", 14, yPos);
        yPos += 5;
        const secRows = data.securityResults.map((s: any) => [s.provider, s.type, s.status, s.details || '-']);
        autoTable(doc, {
            startY: yPos,
            head: [['Source', 'Type', 'Status', 'Details']],
            body: secRows,
            headStyles: { fillColor: [200, 50, 50] }
        });
    }
    doc.save(`network_report_${category.toLowerCase()}_${Date.now()}.pdf`);
};

