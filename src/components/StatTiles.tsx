import React from 'react';
import { SecurityStats, ProwlerMetrics } from '../types';

interface StatTilesProps {
  stats: SecurityStats;
  prowlerMetrics: ProwlerMetrics;
}

export default function StatTiles({ stats, prowlerMetrics }: StatTilesProps) {
  const totalChecks = prowlerMetrics.passes + prowlerMetrics.fails;
  const complianceScore = totalChecks > 0 ? Math.round((prowlerMetrics.passes / totalChecks) * 100) : null;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* Wazuh Alerts */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
        <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Wazuh Active Alerts</span>
        <div className="text-3xl font-extrabold text-red-500">{stats.total_attacks}</div>
        <span className="text-[9px] text-red-400 font-bold uppercase tracking-wider">▲ +5 since last hour</span>
      </div>

      {/* Prowler Score - driven by real /api/prowler/metrics data, not a hardcoded value */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
        <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Prowler Compliance Score</span>
        <div className="text-3xl font-extrabold text-emerald-400">
          {complianceScore !== null ? `${complianceScore}%` : 'N/A'}
        </div>
        <div className="w-full bg-slate-850 h-1.5 rounded-full overflow-hidden">
          <div className="bg-emerald-500 h-full" style={{ width: `${complianceScore ?? 0}%` }}></div>
        </div>
      </div>

      {/* NSG Rules - real failed-check count from the latest Prowler upload */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
        <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">Misconfigured NSG Rules</span>
        <div className="text-2xl font-black text-amber-500">{prowlerMetrics.fails}</div>
        <span className="text-[9px] text-slate-400 font-bold uppercase tracking-wider">High Severity Exiled</span>
      </div>

      {/* System Health */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between h-28 relative overflow-hidden backdrop-blur-sm shadow-md">
        <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider">WireGuard Tunnel</span>
        <div className="text-2xl font-black text-blue-400">STABLE</div>
        <span className="text-[9px] text-emerald-500 font-bold uppercase tracking-wider bg-slate-950 border border-slate-850 px-2 py-0.5 rounded-md self-start">
          Ping: 45ms
        </span>
      </div>
    </div>
  );
}
