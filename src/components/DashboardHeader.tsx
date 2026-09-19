import React from 'react';

interface DashboardHeaderProps {
  sseStatus: 'connecting' | 'connected' | 'disconnected';
}

export default function DashboardHeader({ sseStatus }: DashboardHeaderProps) {
  return (
    <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-4 gap-4">
      <div className="flex items-center gap-3">
        <div className="w-3 h-3 bg-red-600 rounded-full animate-pulse"></div>
        <h1 className="text-lg md:text-xl font-bold tracking-tighter uppercase text-slate-100">
          Hybrid Security Posture & SIEM <span className="text-slate-650 text-[11px] font-mono select-none ml-2 bg-slate-900/60 border border-slate-800 px-2 py-0.5 rounded-md">v1.0.0-Hybrid</span>
        </h1>
      </div>
      <div className="flex flex-wrap gap-4 md:gap-6 text-[10px] uppercase tracking-widest">
        <div className="flex flex-col items-start md:items-end">
          <span className="text-slate-500">System Uptime</span>
          <span className="text-emerald-400 font-bold">142:12:09:44</span>
        </div>
        <div className="flex flex-col items-start md:items-end">
          <span className="text-slate-500">Azure Region</span>
          <span className="text-blue-400 font-bold">East-US-2</span>
        </div>
        <div className="flex flex-col items-start md:items-end">
          <span className="text-slate-500">Active Listeners</span>
          <span className="text-slate-200 font-bold">SSH | TELNET | HTTP</span>
        </div>
        <div className="flex flex-col items-start md:items-end">
          <span className="text-slate-500">Gateway Sockets</span>
          {sseStatus === 'connected' ? (
            <span className="text-emerald-400 font-bold animate-pulse">STREAMING_ACTIVE</span>
          ) : sseStatus === 'connecting' ? (
            <span className="text-amber-400 font-bold animate-pulse">HANDSHAKE</span>
          ) : (
            <span className="text-red-500 font-bold">DISCONNECTED</span>
          )}
        </div>
      </div>
    </header>
  );
}
