import React from 'react';
import { Zap, Globe, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';

interface SimulatorPanelProps {
  cloudScanStatus: 'idle' | 'running' | 'done' | 'failed';
  cloudScanError: string | null;
  onSimulateCloud: () => void;
}

export default function SimulatorPanel({
  cloudScanStatus,
  cloudScanError,
  onSimulateCloud
}: SimulatorPanelProps) {
  return (
    <div className="grid grid-cols-1 gap-4">

      {/* Simulated injection panel */}
      <div className="bg-slate-900/20 border border-slate-800 p-5 rounded-xl space-y-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Zap size={14} className="text-red-500" />
            <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-200">Safeguarded simulation system</h3>
          </div>
          <p className="text-[10px] font-mono text-slate-500 leading-relaxed font-normal uppercase">
            Test live firewall telemetry alerts and path geolocations under strict sandboxed rules.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 mt-6">
          {/* On-Prem (GNS3) is monitored live by Wazuh already - no simulate button needed,
              a real SSH/Telnet attempt against the monitored host shows up on its own. */}

          {/* Cloud Simulator - triggers a REAL Prowler scan against Azure via a Service Principal */}
          <div className="bg-slate-950 p-4 border border-slate-800 rounded-lg flex flex-col gap-3">
            <div className="flex items-center gap-2 mb-2">
              <Globe size={14} className="text-cyan-400" />
              <span className="text-[10px] uppercase font-bold tracking-widest text-slate-300">Azure Cloud Tenant</span>
            </div>
            <p className="text-[9px] text-slate-500 uppercase leading-relaxed mb-2">
              Runs a real Prowler scan against your Azure subscription (Service Principal auth). Takes a couple of minutes.
            </p>
            <button
              type="button"
              disabled={cloudScanStatus === 'running'}
              onClick={onSimulateCloud}
              className="w-full py-2.5 bg-cyan-900/40 hover:bg-cyan-900/60 disabled:bg-slate-800 disabled:text-slate-550 border border-cyan-900/50 text-cyan-400 font-bold uppercase tracking-widest text-[9px] rounded-lg transition flex items-center justify-center gap-2"
            >
              {cloudScanStatus === 'running' ? (
                <>
                  <Loader2 size={12} className="animate-spin" /> SCANNING AZURE...
                </>
              ) : (
                'Run Real Prowler Scan'
              )}
            </button>
          </div>
        </div>

        <div className="mt-4 space-y-2">
          {cloudScanStatus === 'done' && (
            <div className="border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 p-3 rounded-lg flex items-center gap-2.5">
              <CheckCircle2 size={13} className="text-emerald-400" />
              <span className="font-extrabold uppercase text-[9px] tracking-wider">SCAN COMPLETE: Real Azure compliance data updated!</span>
            </div>
          )}
          {cloudScanStatus === 'failed' && (
            <div className="border border-red-500/30 bg-red-950/20 text-red-400 p-3 rounded-lg flex items-start gap-2.5">
              <AlertCircle size={13} className="text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <div className="font-extrabold uppercase text-[9px] tracking-wider mb-1">SCAN FAILED</div>
                <div className="text-[9px] text-red-300/80 font-mono break-words max-w-md">{cloudScanError}</div>
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
