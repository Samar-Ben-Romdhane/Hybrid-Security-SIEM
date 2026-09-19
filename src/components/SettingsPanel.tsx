import React from 'react';
import { Sliders, Volume2, VolumeX } from 'lucide-react';
import { SystemSettings } from '../types';

interface SettingsPanelProps {
  settings: SystemSettings;
  soundEnabled: boolean;
  onUpdateSettings: (override: Partial<SystemSettings>) => void;
  onToggleSound: () => void;
}

export default function SettingsPanel({ settings, soundEnabled, onUpdateSettings, onToggleSound }: SettingsPanelProps) {
  return (
    <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-5 shadow-sm">
      <div className="flex items-center gap-2 mb-4 border-b border-slate-850 pb-3">
        <Sliders size={14} className="text-red-500" />
        <h3 className="text-[10px] font-mono font-bold tracking-wider uppercase text-slate-300">Active Security Engine Profiling Controls</h3>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <div>
          <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">Traffic simulation frequency</label>
          <div className="grid grid-cols-4 bg-slate-950 p-1 border border-slate-850 rounded-lg">
            {(['off', 'slow', 'normal', 'fast'] as const).map((spd) => (
              <button
                key={spd}
                onClick={() => onUpdateSettings({ simulationSpeed: spd })}
                type="button"
                className={`py-1.5 text-[9px] font-mono uppercase font-black rounded-md transition ${
                  settings.simulationSpeed === spd
                    ? 'bg-red-950/60 text-red-400 border border-red-900/30'
                    : 'text-slate-500 hover:text-slate-350 hover:bg-slate-900/50'
                }`}
              >
                {spd}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">High threat threshold limit</label>
          <div className="flex items-center gap-3">
            <input
              type="range"
              min={3}
              max={25}
              value={settings.alertThreshold}
              onChange={(e) => onUpdateSettings({ alertThreshold: Number(e.target.value) })}
              className="w-full h-1 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-red-500"
            />
            <span className="text-[11px] font-mono font-bold text-red-400 text-right min-w-[24px]">
              {settings.alertThreshold}x
            </span>
          </div>
        </div>

        <div>
          <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">Decoy Response Profile State</label>
          <div className="grid grid-cols-3 bg-slate-950 p-1 border border-slate-850 rounded-lg">
            {(['standard', 'aggressive', 'stealth'] as const).map((profile) => (
              <button
                key={profile}
                onClick={() => onUpdateSettings({ decoyProfile: profile })}
                type="button"
                className={`py-1.5 text-[9px] font-mono uppercase font-black rounded-md transition ${
                  settings.decoyProfile === profile
                    ? 'bg-red-950/60 text-red-400 border border-red-900/30'
                    : 'text-slate-500 hover:text-slate-350 hover:bg-slate-900/50'
                }`}
              >
                {profile}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-[10px] font-mono text-slate-500 mb-1.5 uppercase font-bold tracking-wider">Audio Alert notifications</label>
          <button
            onClick={onToggleSound}
            type="button"
            className={`flex items-center justify-between w-full bg-slate-950 p-1.5 border rounded-lg text-left text-[9px] font-mono transition h-8 ${
              soundEnabled
                ? 'border-emerald-900/40 text-emerald-400 bg-emerald-950/10'
                : 'border-slate-850 text-slate-550 hover:text-slate-400'
            }`}
          >
            <div className="flex items-center gap-1.5">
              {soundEnabled ? <Volume2 size={12} className="text-emerald-400 animate-pulse" /> : <VolumeX size={12} />}
              <span className="font-extrabold uppercase tracking-wide">
                {soundEnabled ? 'Pings On' : 'Pings Muted'}
              </span>
            </div>
            <span className={`text-[8px] px-1.5 py-0.5 rounded font-black border uppercase ${
              soundEnabled
                ? 'bg-emerald-950/50 border-emerald-900'
                : 'bg-slate-900 border-slate-850'
            }`}>
              {soundEnabled ? 'ACTIVE' : 'MUTED'}
            </span>
          </button>
        </div>
      </div>
    </div>
  );
}
