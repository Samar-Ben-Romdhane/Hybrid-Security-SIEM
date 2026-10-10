import React from 'react';
import { ShieldAlert, X } from 'lucide-react';
import { AttackEvent } from '../types';

interface AlertToastsProps {
  alerts: AttackEvent[];
  onClear: (index: number) => void;
  onClearAll: () => void;
}

export default function AlertToasts({ alerts, onClear, onClearAll }: AlertToastsProps) {
  return (
    <div className="fixed top-4 right-4 z-[9999] space-y-2 pointer-events-auto max-w-sm w-full">
      {alerts.length > 1 && (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClearAll}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-700 bg-slate-900/95 text-slate-400 hover:text-red-400 hover:border-red-900/50 text-[9px] font-mono font-bold uppercase tracking-widest shadow-lg backdrop-blur-md transition"
          >
            <X size={11} /> Clear all ({alerts.length})
          </button>
        </div>
      )}
      {alerts.map((alert, idx) => (
        <div
          key={`${alert.id}-${idx}`}
          className="border border-red-500/30 bg-slate-900/95 text-slate-100 rounded-xl p-3.5 shadow-2xl backdrop-blur-md animate-slide-in relative flex gap-3 overflow-hidden font-mono"
        >
          <div className="absolute top-0 left-0 w-1 bg-red-550 h-full"></div>
          <div className="flex-shrink-0 text-red-550 mt-0.5">
            <ShieldAlert size={18} className="animate-pulse" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex justify-between items-center mb-1">
              <span className="text-[10px] font-black tracking-widest text-red-400 uppercase">HIGH THREAT FLAG</span>
              <button
                onClick={() => onClear(idx)}
                className="text-slate-500 hover:text-slate-350 text-xs font-bold"
              >
                ×
              </button>
            </div>
            <p className="text-[10.5px] text-slate-300">
              IP <span className="font-extrabold text-red-400">{alert.ip}</span> passed security threshold frequency limits.
            </p>
            <div className="mt-1.5 text-[9.5px] text-slate-400 bg-black/50 px-2 py-1 rounded border border-slate-900 truncate">
              Origin: {alert.city}, {alert.country} ({alert.protocol})
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
