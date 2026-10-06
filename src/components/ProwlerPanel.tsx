import React from 'react';
import { Globe } from 'lucide-react';
import { ProwlerMetrics, ProwlerFinding } from '../types';

interface ProwlerPanelProps {
  metrics: ProwlerMetrics;
  findings: ProwlerFinding[];
}

function severityBadgeClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'bg-red-900/50 text-red-300';
  if (s === 'high') return 'bg-amber-900/50 text-amber-300';
  if (s === 'medium') return 'bg-blue-900/50 text-blue-300';
  if (s === 'low' || s === 'informational') return 'bg-slate-800 text-slate-400';
  return 'bg-slate-800 text-slate-400';
}

export default function ProwlerPanel({ metrics, findings }: ProwlerPanelProps) {
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col h-[520px] shadow-sm">
      <div className="bg-slate-900/80 p-3 border-b border-slate-800 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Globe size={14} className="text-cyan-400" />
          <span className="text-[10px] font-bold tracking-wider uppercase text-slate-200">CLOUD / AZURE (PROWLER)</span>
        </div>
        <span className="text-[8px] text-blue-400 uppercase font-black bg-blue-950/40 px-2 py-0.5 border border-blue-900/30 rounded-full">AZ-EAST-US</span>
      </div>

      <div className="p-4 overflow-y-auto flex-1 font-mono">

        <div className="grid grid-cols-2 gap-3 mb-4">
          <div className="bg-emerald-950/20 border border-emerald-900/30 p-2 rounded-lg">
            <div className="text-[9px] text-emerald-500/70 font-bold uppercase mb-1">Passed Checks</div>
            <div className="text-xl text-emerald-400 font-black">{metrics.passes}</div>
          </div>
          <div className="bg-red-950/20 border border-red-900/30 p-2 rounded-lg">
            <div className="text-[9px] text-red-500/70 font-bold uppercase mb-1">Failed Checks</div>
            <div className="text-xl text-red-400 font-black">{metrics.fails}</div>
          </div>
        </div>

        <h3 className="text-[10px] font-bold uppercase text-slate-500 mb-3 border-b border-slate-800 pb-1">NSG Rule Violations</h3>

        {findings.length === 0 ? (
          <div className="text-[10px] text-slate-600 italic text-center py-8 border border-slate-800 rounded-lg">
            {metrics.updated_at ? 'Clean scan - no NSG violations found.' : 'No scan run yet.'}
          </div>
        ) : (
          <div className="overflow-x-auto border border-slate-800 rounded-lg">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-900 text-[8px] text-slate-400 uppercase tracking-widest border-b border-slate-800">
                  <th className="p-2 font-bold">NSG Name</th>
                  <th className="p-2 font-bold">Port</th>
                  <th className="p-2 font-bold">Source</th>
                  <th className="p-2 font-bold">Risk</th>
                </tr>
              </thead>
              <tbody className="text-[9px] text-slate-300">
                {findings.map((f, idx) => (
                  <tr
                    key={f.id}
                    className={idx < findings.length - 1 ? 'border-b border-slate-800/50 hover:bg-slate-900/30' : 'hover:bg-slate-900/30'}
                  >
                    <td className="p-2 truncate max-w-[140px]" title={f.check_title}>{f.resource_name}</td>
                    <td className="p-2 font-bold">{f.port || '-'}</td>
                    <td className="p-2">{f.source || '-'}</td>
                    <td className="p-2">
                      <span className={`px-1.5 py-0.5 rounded text-[8px] uppercase font-bold ${severityBadgeClass(f.severity)}`}>
                        {f.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      </div>
    </div>
  );
}
