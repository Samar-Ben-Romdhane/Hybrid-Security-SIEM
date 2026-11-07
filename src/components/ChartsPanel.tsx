import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  PieChart,
  Pie
} from 'recharts';

interface ChartsPanelProps {
  chartPieData: Array<{ name: string; value: number }>;
  chartPieColors: Record<string, string>;
  sshPercent: number;
  sshVal: number;
  telnetPercent: number;
  telnetVal: number;
  httpPercent: number;
  httpVal: number;
  topAttackers: Array<{ ip: string; country: string; count: number }>;
  timelineChartData: Array<{ hour: string; Events: number }>;
}

export default function ChartsPanel({
  chartPieData,
  chartPieColors,
  sshPercent,
  sshVal,
  telnetPercent,
  telnetVal,
  httpPercent,
  httpVal,
  topAttackers,
  timelineChartData
}: ChartsPanelProps) {
  const maxAttackerCount = Math.max(1, ...topAttackers.map((a) => a.count));
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

      {/* Protocol breakdown */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between min-h-[300px]">
        <div>
          <h3 className="text-[10px] uppercase text-slate-500 mb-3 font-bold tracking-wider">Protocol distribution</h3>
          <div className="space-y-3">
            <div className="flex flex-col gap-1">
              <div className="flex justify-between text-[10px]">
                <span className="text-cyan-400 font-extrabold">SSH (Port 2222)</span>
                <span>{sshPercent}% ({sshVal})</span>
              </div>
              <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                <div className="bg-cyan-500 h-full" style={{ width: `${sshPercent}%` }}></div>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <div className="flex justify-between text-[10px]">
                <span className="text-purple-400 font-extrabold">TELNET (Port 2323)</span>
                <span>{telnetPercent}% ({telnetVal})</span>
              </div>
              <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                <div className="bg-purple-500 h-full" style={{ width: `${telnetPercent}%` }}></div>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <div className="flex justify-between text-[10px]">
                <span className="text-amber-400 font-extrabold">HTTP (Port 8080)</span>
                <span>{httpPercent}% ({httpVal})</span>
              </div>
              <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                <div className="bg-amber-400 h-full" style={{ width: `${httpPercent}%` }}></div>
              </div>
            </div>
          </div>
        </div>

        <div className="h-32 flex items-center justify-center mt-2">
          {chartPieData.some(pt => pt.value > 0) ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={28}
                  outerRadius={44}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {chartPieData.map((entry) => (
                    <Cell
                      key={`cell-${entry.name}`}
                      fill={chartPieColors[entry.name as 'SSH' | 'TELNET' | 'HTTP'] || '#94a3b8'}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#020617', border: '1px solid #1e293b', borderRadius: '4px' }}
                  itemStyle={{ fontFamily: 'monospace', fontSize: '10px', color: '#f1f5f9' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-[10px] text-slate-600">Syncing telemetry streams...</div>
          )}
        </div>
      </div>

      {/* Top attacker IPs */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between min-h-[300px]">
        <div>
          <h3 className="text-[10px] uppercase text-slate-500 mb-1 font-bold tracking-wider">Top attacker IPs</h3>
          <p className="text-[10px] font-mono text-slate-500 mb-3 leading-relaxed">
            Most active source IPs by real hit count.
          </p>
          <div className="space-y-3 font-mono text-[10px]">
            {topAttackers.map((a, idx) => (
              <div key={`${a.ip}-${idx}`} className="flex flex-col gap-1">
                <div className="flex justify-between">
                  <span className="text-red-400 font-extrabold">{a.ip}</span>
                  <span className="text-slate-400">{a.country} · {a.count}x</span>
                </div>
                <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                  <div className="bg-red-500 h-full" style={{ width: `${(a.count / maxAttackerCount) * 100}%` }}></div>
                </div>
              </div>
            ))}
            {topAttackers.length === 0 && (
              <div className="text-slate-600 text-[10px] py-6 text-center">No real traffic recorded yet.</div>
            )}
          </div>
        </div>
      </div>

      {/* Historical Timeline block */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex flex-col justify-between min-h-[300px]">
        <div>
          <h3 className="text-[10px] uppercase text-slate-500 mb-2 font-bold tracking-wider">Activity over the last 24h</h3>
          <p className="text-[10px] font-mono text-slate-500 mb-3 leading-relaxed">
            Real event count per 4-hour window.
          </p>
        </div>
        <div className="flex-1 h-36">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timelineChartData} margin={{ left: -25, right: 5, top: 10, bottom: 5 }}>
              <defs>
                <linearGradient id="glowBentoEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
              <XAxis dataKey="hour" stroke="#475569" style={{ fontSize: 8 }} />
              <YAxis stroke="#475569" style={{ fontSize: 8 }} />
              <Area type="monotone" dataKey="Events" stroke="#ef4444" strokeWidth={1.5} fillOpacity={1} fill="url(#glowBentoEvents)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
}
