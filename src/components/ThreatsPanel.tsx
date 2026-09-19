import React from 'react';
import { RefreshCw } from 'lucide-react';
import { ThreatActor } from '../types';

interface ThreatsPanelProps {
  threatActors: ThreatActor[];
  onSync: () => void;
  onTraceIP: (ip: string) => void;
}

export default function ThreatsPanel({ threatActors, onSync, onTraceIP }: ThreatsPanelProps) {
  return (
    <div className="space-y-4">

      <div className="bg-slate-900/30 border border-slate-800 p-5 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-300 mb-1">Host threat intelligence categorization</h3>
          <p className="text-[10px] font-mono text-slate-500 font-normal leading-relaxed uppercase">
            Aggregates incoming threat anomalies by IP origin address to formulate safety logs.
          </p>
        </div>
        <button
          onClick={onSync}
          type="button"
          className="flex items-center gap-2 px-3.5 py-2 border border-slate-850 bg-slate-950 font-mono text-[9px] font-black rounded-lg hover:bg-slate-900 hover:border-slate-750 text-slate-400 hover:text-slate-200 transition uppercase tracking-wider"
        >
          <RefreshCw size={11} /> Sync state anomalies
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {threatActors.length === 0 ? (
          <div className="border border-slate-800 bg-slate-950 p-12 text-center text-slate-500 font-mono text-[10px] rounded-xl uppercase tracking-widest">
            INTELLIGENCE DIRECTORY CURRENTLY STABLE. LAUNCH SIMULATIONS TO SCAN ASSETS.
          </div>
        ) : (
          threatActors.map((actor, idx) => {
            let badgeStyle = 'bg-slate-900 border-slate-800 text-slate-450';
            if (actor.level === 'HIGH') {
              badgeStyle = 'bg-red-950/60 border-red-900/30 text-red-400';
            } else if (actor.level === 'MEDIUM') {
              badgeStyle = 'bg-amber-950/60 border-amber-900/30 text-amber-400';
            }

            return (
              <div
                key={`${actor.ip}-${idx}`}
                className="border border-slate-850 bg-slate-900/20 p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 hover:border-slate-800 transition"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-extrabold text-slate-200">{actor.ip}</span>
                    <span className={`px-2 py-0.5 border text-[8px] font-mono font-black rounded-lg uppercase tracking-wider ${badgeStyle}`}>
                      {actor.level} LEVEL
                    </span>
                  </div>
                  <div className="text-slate-500 font-mono text-[10px] uppercase">
                    COUNTRY: <span className="font-semibold text-slate-300">{actor.country.toUpperCase()}</span> |
                    HITS COUNT: <span className="font-extrabold text-red-500 font-mono">{actor.count} TIMES</span>
                  </div>
                </div>

                <div className="flex items-center gap-4 self-stretch sm:self-auto justify-between sm:justify-start">
                  <div className="text-left sm:text-right">
                    <p className="text-[8px] uppercase font-mono tracking-wider font-bold text-slate-500">Last Seen</p>
                    <p className="text-[10px] font-mono font-medium text-slate-400">{new Date(actor.lastSeen).toISOString().replace('T', ' ').slice(0, 19)}</p>
                  </div>
                  <button
                    onClick={() => onTraceIP(actor.ip)}
                    type="button"
                    className="px-3 py-1.5 border border-slate-850 hover:border-red-900/40 hover:bg-slate-950 text-slate-400 hover:text-red-400 text-[9px] font-mono font-bold rounded-lg transition uppercase tracking-widest"
                  >
                    Trace IP
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
