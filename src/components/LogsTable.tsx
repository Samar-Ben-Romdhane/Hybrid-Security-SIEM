import React from 'react';
import { Filter, ChevronLeft, ChevronRight } from 'lucide-react';
import { AttackEvent } from '../types';

interface LogsTableProps {
  logs: AttackEvent[];
  logFilterProto: string;
  logSearchQuery: string;
  logPage: number;
  logTotalPages: number;
  onFilterChange: (proto: string) => void;
  onSearchChange: (query: string) => void;
  onPageChange: (direction: 'next' | 'prev') => void;
  onFocusMap: (evt: AttackEvent) => void;
}

export default function LogsTable({
  logs,
  logFilterProto,
  logSearchQuery,
  logPage,
  logTotalPages,
  onFilterChange,
  onSearchChange,
  onPageChange,
  onFocusMap
}: LogsTableProps) {
  return (
    <div className="space-y-4">
      {/* Filter and search panel */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-slate-900/40 border border-slate-800 p-4 rounded-xl">
        <div className="flex flex-wrap items-center gap-2.5 w-full sm:w-auto">
          <Filter size={12} className="text-slate-500" />
          <span className="text-[10px] font-mono text-slate-500 font-bold uppercase tracking-wider">Filter Decoy:</span>
          <div className="flex gap-1 bg-slate-950 p-1 border border-slate-800 rounded-lg">
            {['ALL', 'SSH', 'TELNET', 'HTTP'].map((p) => (
              <button
                key={p}
                onClick={() => onFilterChange(p)}
                type="button"
                className={`px-3 py-1 text-[9px] uppercase font-bold font-mono rounded-md transition ${
                  logFilterProto === p
                    ? 'bg-red-950 border border-red-900/30 text-red-400 shadow-inner'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        <div className="w-full sm:w-72">
          <input
            type="text"
            placeholder="QUERY IP, REGION OR PAYLOAD..."
            value={logSearchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full bg-slate-950 border border-slate-805 text-[10px] px-3.5 py-2.5 rounded-lg font-mono text-slate-200 focus:outline-none focus:border-red-500 font-medium placeholder-slate-700 uppercase tracking-widest"
          />
        </div>
      </div>

      {/* Datagrid logs table */}
      <div className="border border-slate-800 bg-slate-950 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-[10px] text-slate-350">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 select-none">
                <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Timestamp</th>
                <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Origin Host IP</th>
                <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Decoy Target</th>
                <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Geographic Origin</th>
                <th className="p-4 uppercase font-bold tracking-wider text-[9px]">Captured Payload</th>
                <th className="p-4 text-right uppercase font-bold tracking-wider text-[9px]">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center p-8 text-slate-500 font-mono">
                    NO SECURITY INCIDENT PACKETS REGISTERED LOGS.
                  </td>
                </tr>
              ) : (
                logs.map((log, idx) => {
                  let protoBadge = 'text-cyan-455 bg-cyan-950/30 border-cyan-900/20';
                  if (log.protocol === 'HTTP') protoBadge = 'text-amber-455 bg-amber-950/30 border-amber-900/20';
                  if (log.protocol === 'TELNET') protoBadge = 'text-blue-455 bg-blue-950/30 border-blue-900/20';

                  return (
                    <tr key={`${log.id}-${idx}`} className="hover:bg-slate-900/30 transition-colors">
                      <td className="p-4 text-slate-500">
                        {new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                      </td>
                      <td className="p-4 font-black text-red-400 hover:underline cursor-pointer" onClick={() => onFocusMap(log)}>
                        {log.ip}
                      </td>
                      <td className="p-4">
                        <span className={`px-2 py-0.5 rounded font-black text-[9px] border uppercase ${protoBadge}`}>
                          {log.protocol} ({log.port})
                        </span>
                      </td>
                      <td className="p-4 text-slate-300">
                        {log.city}, {log.country}
                      </td>
                      <td className="p-4 max-w-xs truncate text-slate-400" title={log.payload}>
                        {log.payload}
                      </td>
                      <td className="p-4 text-right">
                        <button
                          onClick={() => onFocusMap(log)}
                          type="button"
                          className="px-3 py-1 select-none text-[9px] font-black border border-slate-800 hover:border-red-900/30 hover:bg-slate-900/50 rounded-lg text-slate-400 hover:text-red-400 transition"
                        >
                          LOCATE
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* logs pagination bar */}
        <div className="border-t border-slate-800 bg-slate-900/40 p-4 flex items-center justify-between font-mono">
          <p className="text-[10px] text-slate-550">
            PAGES <span className="text-slate-300 font-bold">{logPage}</span> / <span className="text-slate-300 font-bold">{logTotalPages}</span>
          </p>
          <div className="flex gap-1.5">
            <button
              disabled={logPage <= 1}
              onClick={() => onPageChange('prev')}
              type="button"
              className="p-1 px-3 border border-slate-800 rounded-lg text-slate-500 hover:text-slate-350 disabled:opacity-30"
            >
              <ChevronLeft size={13} />
            </button>
            <button
              disabled={logPage >= logTotalPages}
              onClick={() => onPageChange('next')}
              type="button"
              className="p-1 px-3 border border-slate-800 rounded-lg text-slate-500 hover:text-slate-350 disabled:opacity-30"
            >
              <ChevronRight size={13} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
