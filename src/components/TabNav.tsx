import React from 'react';

type TabId = 'dashboard' | 'logs' | 'threats' | 'simulator';

interface TabNavProps {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
}

const TABS: Array<{ id: TabId; label: string }> = [
  { id: 'dashboard', label: 'Overview Grid' },
  { id: 'logs', label: 'Telemetry Logs' },
  { id: 'threats', label: 'Threat Actors' },
  { id: 'simulator', label: 'Direct Simulator' }
];

export default function TabNav({ activeTab, onTabChange }: TabNavProps) {
  return (
    <nav className="flex flex-wrap gap-2 p-1 bg-slate-950 border border-slate-800 rounded-xl self-start">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onTabChange(tab.id)}
          type="button"
          className={`px-4 py-2 text-[10px] font-mono tracking-wider font-bold uppercase transition rounded-lg ${
            activeTab === tab.id
              ? 'bg-slate-900 border border-slate-800 text-slate-100 shadow-inner'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/10'
          }`}
        >
          {tab.label}
        </button>
      ))}
    </nav>
  );
}
