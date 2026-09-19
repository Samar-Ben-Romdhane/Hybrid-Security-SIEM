import React from 'react';
import { Globe } from 'lucide-react';
import { ProwlerMetrics } from '../types';

interface ProwlerPanelProps {
  metrics: ProwlerMetrics;
}

export default function ProwlerPanel({ metrics }: ProwlerPanelProps) {
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

        {/*
          NOTE: The Prowler upload endpoint currently only persists aggregate
          pass/fail counts, not per-rule detail, so this table stays as
          illustrative sample data until per-finding storage is added.
        */}
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
              <tr className="border-b border-slate-800/50 hover:bg-slate-900/30">
                <td className="p-2">web-prod-nsg</td>
                <td className="p-2 text-red-400 font-bold">22</td>
                <td className="p-2">0.0.0.0/0</td>
                <td className="p-2"><span className="bg-red-900/50 text-red-300 px-1.5 py-0.5 rounded text-[8px] uppercase font-bold">CRITICAL</span></td>
              </tr>
              <tr className="border-b border-slate-800/50 hover:bg-slate-900/30">
                <td className="p-2">db-internal-nsg</td>
                <td className="p-2 text-amber-400 font-bold">3306</td>
                <td className="p-2">Any</td>
                <td className="p-2"><span className="bg-amber-900/50 text-amber-300 px-1.5 py-0.5 rounded text-[8px] uppercase font-bold">HIGH</span></td>
              </tr>
              <tr className="hover:bg-slate-900/30">
                <td className="p-2">jumpbox-nsg</td>
                <td className="p-2 text-blue-400 font-bold">3389</td>
                <td className="p-2">0.0.0.0/0</td>
                <td className="p-2"><span className="bg-red-900/50 text-red-300 px-1.5 py-0.5 rounded text-[8px] uppercase font-bold">CRITICAL</span></td>
              </tr>
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
}
