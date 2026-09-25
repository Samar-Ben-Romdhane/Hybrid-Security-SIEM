import React from 'react';
import { Zap, Server, Globe, CheckCircle2, AlertCircle, Sliders, Loader2 } from 'lucide-react';

interface SimulatorPanelProps {
  simulationStatus: string | null;
  cloudScanStatus: 'idle' | 'running' | 'done' | 'failed';
  cloudScanError: string | null;
  onSimulateOnPrem: () => void;
  onSimulateCloud: () => void;
}

export default function SimulatorPanel({
  simulationStatus,
  cloudScanStatus,
  cloudScanError,
  onSimulateOnPrem,
  onSimulateCloud
}: SimulatorPanelProps) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">

      {/* Simulated injection panel */}
      <div className="lg:col-span-7 bg-slate-900/20 border border-slate-800 p-5 rounded-xl space-y-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Zap size={14} className="text-red-500" />
            <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-200">Safeguarded simulation system</h3>
          </div>
          <p className="text-[10px] font-mono text-slate-500 leading-relaxed font-normal uppercase">
            Test live firewall telemetry alerts and path geolocations under strict sandboxed rules.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
          {/* On-Prem Simulator */}
          <div className="bg-slate-950 p-4 border border-slate-800 rounded-lg flex flex-col gap-3">
            <div className="flex items-center gap-2 mb-2">
              <Server size={14} className="text-blue-400" />
              <span className="text-[10px] uppercase font-bold tracking-widest text-slate-300">GNS3 Local Node</span>
            </div>
            <p className="text-[9px] text-slate-500 uppercase leading-relaxed mb-2">
              Trigger a mock Wazuh alert for a brute force attack originating from an external IP against the local router.
            </p>
            <button
              type="button"
              disabled={simulationStatus === 'queueing'}
              onClick={onSimulateOnPrem}
              className="w-full py-2.5 bg-blue-900/40 hover:bg-blue-900/60 disabled:bg-slate-800 disabled:text-slate-550 border border-blue-900/50 text-blue-400 font-bold uppercase tracking-widest text-[9px] rounded-lg transition"
            >
              {simulationStatus === 'queueing' ? 'INJECTING...' : 'Simulate On-Prem Attack'}
            </button>
          </div>

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
          {simulationStatus === 'compromised' && (
            <div className="border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 p-3 rounded-lg flex items-center gap-2.5">
              <CheckCircle2 size={13} className="text-emerald-400" />
              <span className="font-extrabold uppercase text-[9px] tracking-wider">INJECTION SUCCESS: Security telemetry updated!</span>
            </div>
          )}
          {simulationStatus === 'failed' && (
            <div className="border border-red-500/30 bg-red-950/20 text-red-400 p-3 rounded-lg flex items-center gap-2.5">
              <AlertCircle size={13} className="text-red-400" />
              <span className="font-extrabold uppercase text-[9px] tracking-wider">INJECTION ERROR: Port stream transmission crashed.</span>
            </div>
          )}
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

      {/* Instruction block */}
      <div className="lg:col-span-12 xl:col-span-5 bg-slate-900/20 border border-slate-800 p-5 rounded-xl flex flex-col justify-between space-y-4">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Sliders size={14} className="text-red-450" />
            <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-300">Terminal scan manual</h3>
          </div>

          <div className="space-y-2.5 font-mono text-[10px] text-slate-500 leading-relaxed uppercase">
            <p>
              Because endpoints simulate common exposed services, you can trigger connections using standard command-line tools:
            </p>

            <div className="bg-slate-950 p-2.5 border border-slate-850 rounded-lg text-[9px] text-slate-400 space-y-1.5 select-all font-mono">
              <div># Test open admin HTTP service target on port 8080:</div>
              <code className="text-red-450 font-extrabold block bg-slate-900/40 p-1.5 rounded-md text-center">
                curl http://localhost:8080/admin/dashboard.env
              </code>
            </div>

            <p>
              Host triggers are intercepted, details parsed from client headers, geolocated dynamically, and piped immediately into layout elements!
            </p>
          </div>
        </div>

        <div className="border-t border-slate-800 pt-3 text-[9px] text-slate-600 font-mono space-y-0.5 leading-relaxed uppercase">
          <p className="text-slate-550">⚠ SANDBOX COORDS RULE:</p>
          <p>Local actions (originating from standard loopback `127.0.0.1`) are programmatically translated across global clusters (Shanghai, Warsaw, Dublin, Virginia USA) for high fidelity visualisation.</p>
        </div>
      </div>

    </div>
  );
}
