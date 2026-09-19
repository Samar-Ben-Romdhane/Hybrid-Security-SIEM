import React from 'react';
import { Server } from 'lucide-react';
import { AttackEvent } from '../types';

interface WazuhPanelProps {
  events: AttackEvent[];
  timeStr: string;
}

export default function WazuhPanel({ events, timeStr }: WazuhPanelProps) {
  return (
    <div className="bg-slate-900/20 border border-slate-800 rounded-xl overflow-hidden relative flex flex-col h-[520px] shadow-sm">
      <div className="bg-slate-950 border-b border-slate-800 p-3 flex justify-between items-center z-10">
        <div className="flex items-center gap-2">
          <Server size={14} className="text-blue-400" />
          <span className="text-[10px] font-bold tracking-wider uppercase text-slate-200">ON-PREM / GNS3 (WAZUH)</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[8px] text-emerald-400 uppercase font-black bg-emerald-950/40 px-2 py-0.5 border border-emerald-900/30 rounded-full flex items-center gap-1"><div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></div> AGENT ACTIVE</span>
        </div>
      </div>

      <div className="p-4 flex-1 overflow-y-auto font-mono">
        <div className="mb-4 bg-slate-900/50 p-3 rounded-lg border border-slate-800 flex justify-between items-center">
          <div>
            <div className="text-[9px] text-slate-400 uppercase tracking-widest font-bold mb-1">Agent Status</div>
            <div className="text-[11px] text-emerald-400 font-bold">Connected (v4.3.10)</div>
          </div>
          <div className="text-right">
            <div className="text-[9px] text-slate-400 uppercase tracking-widest font-bold mb-1">Last Keepalive</div>
            <div className="text-[11px] text-slate-200">{timeStr}</div>
          </div>
        </div>

        <h3 className="text-[10px] font-bold uppercase text-slate-500 mb-3 border-b border-slate-800 pb-1">Recent Alerts</h3>

        <div className="flex flex-col gap-2">
          {events.slice(0, 10).map((evt, idx) => (
            <div key={idx} className="bg-slate-900/40 border border-slate-800 rounded-lg p-2.5 flex flex-col gap-1.5 hover:bg-slate-800/40 transition">
              <div className="flex justify-between items-start">
                <span className="text-red-400 text-[10px] font-bold">[Rule 5712] SSH Brute Force Attempt</span>
                <span className="text-[8px] text-slate-500">{new Date(evt.timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="flex justify-between text-[9px] text-slate-400">
                <span>Src: <span className="text-slate-200">{evt.ip}</span></span>
                <span className="text-blue-400">Action: Firewall Drop</span>
              </div>
            </div>
          ))}
          {events.length === 0 && (
            <div className="text-slate-600 text-[10px] py-8 text-center italic">No active Wazuh alerts on premises.</div>
          )}
        </div>
      </div>
    </div>
  );
}
