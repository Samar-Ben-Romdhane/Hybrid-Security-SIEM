import React from 'react';

export default function Footer() {
  return (
    <footer className="flex flex-col sm:flex-row justify-between items-center text-[9px] font-mono text-slate-500 border-t border-slate-800 pt-3 mt-auto gap-2">
      <div className="flex flex-wrap gap-4 select-none">
        <span>Azure Key Vault: <span className="text-emerald-450 font-bold">CONNECTED</span></span>
        <span>DB Cluster: <span className="text-emerald-450 font-bold">OPTIMAL</span></span>
        <span>Telemetry: <span className="text-emerald-450 font-bold">ACTIVE</span></span>
      </div>
      <div className="flex gap-4">
        <span>Session ID: AX-40291-ZZ</span>
        <span className="text-slate-400 uppercase font-bold">Authorized Access Only</span>
      </div>
    </footer>
  );
}
