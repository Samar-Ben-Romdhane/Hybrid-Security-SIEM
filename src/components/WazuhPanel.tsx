import React from 'react';
import { Server } from 'lucide-react';
import { AttackEvent, WazuhAgentStatus } from '../types';
import { formatLocalDateTime } from '../utils/time';
import Pagination, { usePagination } from './Pagination';

const PAGE_SIZE = 5;

interface WazuhPanelProps {
  events: AttackEvent[];
  agentStatus: WazuhAgentStatus;
}

// Turn the raw /api/wazuh/agent-status response into an honest badge + status
// line instead of a hardcoded "AGENT ACTIVE" that never reflected reality.
function describeAgentStatus(agentStatus: WazuhAgentStatus): { badge: string; badgeStyle: string; dotStyle: string; line: string } {
  if (!agentStatus.configured) {
    return { badge: 'NOT CONFIGURED', badgeStyle: 'text-slate-400 bg-slate-900/60 border-slate-700', dotStyle: 'bg-slate-500', line: 'Wazuh API not set up (WAZUH_API_URL / USER / PASSWORD)' };
  }
  if (!agentStatus.reachable) {
    return { badge: 'UNREACHABLE', badgeStyle: 'text-red-400 bg-red-950/40 border-red-900/30', dotStyle: 'bg-red-500', line: agentStatus.error || 'Could not reach the Wazuh Manager API' };
  }
  if (!agentStatus.found) {
    return { badge: 'AGENT NOT FOUND', badgeStyle: 'text-amber-400 bg-amber-950/40 border-amber-900/30', dotStyle: 'bg-amber-500', line: 'Check WAZUH_AGENT_ID' };
  }
  if (agentStatus.status === 'active') {
    return { badge: 'AGENT ACTIVE', badgeStyle: 'text-emerald-400 bg-emerald-950/40 border-emerald-900/30', dotStyle: 'bg-emerald-400 animate-pulse', line: `Connected${agentStatus.version ? ` (v${agentStatus.version})` : ''}` };
  }
  if (agentStatus.status === 'disconnected') {
    return { badge: 'DISCONNECTED', badgeStyle: 'text-red-400 bg-red-950/40 border-red-900/30', dotStyle: 'bg-red-500', line: `Disconnected${agentStatus.version ? ` (v${agentStatus.version})` : ''}` };
  }
  return { badge: (agentStatus.status || 'UNKNOWN').toUpperCase().replace('_', ' '), badgeStyle: 'text-amber-400 bg-amber-950/40 border-amber-900/30', dotStyle: 'bg-amber-500', line: agentStatus.version ? `v${agentStatus.version}` : 'Status unknown' };
}

export default function WazuhPanel({ events, agentStatus }: WazuhPanelProps) {
  // This panel is specifically labeled WAZUH - only show events that actually
  // came from a real forwarded Wazuh alert, not the synthetic generator or
  // decoy captures.
  const wazuhEvents = events.filter((e) => e.source === 'wazuh');
  const pg = usePagination(wazuhEvents, PAGE_SIZE);
  const agentInfo = describeAgentStatus(agentStatus);

  return (
    <div className="bg-slate-900/20 border border-slate-800 rounded-xl overflow-hidden relative flex flex-col h-[520px] shadow-sm">
      <div className="bg-slate-950 border-b border-slate-800 p-3 flex justify-between items-center z-10">
        <div className="flex items-center gap-2">
          <Server size={14} className="text-blue-400" />
          <span className="text-[10px] font-bold tracking-wider uppercase text-slate-200">ON-PREM / GNS3 (WAZUH)</span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-[8px] uppercase font-black px-2 py-0.5 border rounded-full flex items-center gap-1 ${agentInfo.badgeStyle}`}><div className={`w-1.5 h-1.5 rounded-full ${agentInfo.dotStyle}`}></div> {agentInfo.badge}</span>
        </div>
      </div>

      <div className="p-4 flex-1 overflow-y-auto font-mono">
        <div className="mb-4 bg-slate-900/50 p-3 rounded-lg border border-slate-800 flex justify-between items-center">
          <div>
            <div className="text-[9px] text-slate-400 uppercase tracking-widest font-bold mb-1">Agent Status</div>
            <div className="text-[11px] text-slate-200 font-bold">{agentInfo.line}</div>
          </div>
          <div className="text-right">
            <div className="text-[9px] text-slate-400 uppercase tracking-widest font-bold mb-1">Last Keepalive</div>
            <div className="text-[11px] text-slate-200">{agentStatus.lastKeepAlive ? formatLocalDateTime(agentStatus.lastKeepAlive) : '—'}</div>
          </div>
        </div>

        <h3 className="text-[10px] font-bold uppercase text-slate-500 mb-3 border-b border-slate-800 pb-1">Recent Alerts</h3>

        <div className="flex flex-col gap-2">
          {pg.pageItems.map((evt, idx) => (
            <div key={evt.id ?? pg.start + idx}className="bg-slate-900/40 border border-slate-800 rounded-lg p-2.5 flex flex-col gap-1.5 hover:bg-slate-800/40 transition">
              <div className="flex justify-between items-start gap-2">
                <span className="text-red-400 text-[10px] font-bold">{evt.payload}</span>
                <span className="text-[8px] text-slate-500 flex-shrink-0">{new Date(evt.timestamp).toLocaleTimeString()}</span>
              </div>
              <div className="flex justify-between text-[9px] text-slate-400">
                <span>Src: <span className="text-slate-200">{evt.ip}</span></span>
                <span className="text-blue-400">Action: Firewall Drop</span>
              </div>
            </div>
          ))}
          {wazuhEvents.length === 0 && (
            <div className="text-slate-600 text-[10px] py-8 text-center italic">No real Wazuh alerts forwarded yet.</div>
          )}
        </div>
      </div>

      <Pagination page={pg.page} totalPages={pg.totalPages} total={pg.total} pageSize={pg.pageSize} onPageChange={pg.setPage} />
    </div>
  );
}
