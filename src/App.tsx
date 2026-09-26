import React, { useState, useEffect, useRef } from 'react';
import { AttackEvent, SecurityStats, ThreatActor, SystemSettings, ProwlerMetrics } from './types';

import AlertToasts from './components/AlertToasts';
import DashboardHeader from './components/DashboardHeader';
import StatTiles from './components/StatTiles';
import TabNav from './components/TabNav';
import WazuhPanel from './components/WazuhPanel';
import ProwlerPanel from './components/ProwlerPanel';
import ChartsPanel from './components/ChartsPanel';
import SettingsPanel from './components/SettingsPanel';
import LogsTable from './components/LogsTable';
import ThreatsPanel from './components/ThreatsPanel';
import SimulatorPanel from './components/SimulatorPanel';
import Footer from './components/Footer';

type TabId = 'dashboard' | 'logs' | 'threats' | 'simulator';

export default function App() {
  // Main Telemetry States
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const [stats, setStats] = useState<SecurityStats>({
    total_attacks: 0,
    unique_ips: 0,
    top_port: '2222',
    protocol_stats: { SSH: 0, TELNET: 0, HTTP: 0 },
    top_attackers: [],
    top_payloads: [],
    source_breakdown: {},
    wazuh_alerts_last_hour: 0,
    hourly_timeline: []
  });
  const [threatActors, setThreatActors] = useState<ThreatActor[]>([]);
  const [settings, setSettings] = useState<SystemSettings>({
    simulationSpeed: 'normal',
    alertThreshold: 10,
    decoyProfile: 'standard'
  });
  const [prowlerMetrics, setProwlerMetrics] = useState<ProwlerMetrics>({
    total_nsg_checks: 0,
    fails: 0,
    passes: 0,
    updated_at: null
  });

  // UI Control States
  const [activeTab, setActiveTab] = useState<TabId>('dashboard');
  const [logFilterProto, setLogFilterProto] = useState<string>('ALL');
  const [logSearchQuery, setLogSearchQuery] = useState<string>('');
  const [logPage, setLogPage] = useState<number>(1);
  const [logTotalPages, setLogTotalPages] = useState<number>(1);
  const [sseStatus, setSseStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const [selectedEvent, setSelectedEvent] = useState<AttackEvent | null>(null);
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);
  const [cloudScanStatus, setCloudScanStatus] = useState<'idle' | 'running' | 'done' | 'failed'>('idle');
  const [cloudScanError, setCloudScanError] = useState<string | null>(null);
  const cloudScanPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [timeStr, setTimeStr] = useState<string>(new Date().toISOString());

  // Floating Warning Alerts Queue
  const [activeAlerts, setActiveAlerts] = useState<AttackEvent[]>([]);

  // Optional Audio Notifications
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const soundRef = useRef<boolean>(true);

  useEffect(() => {
    soundRef.current = soundEnabled;
  }, [soundEnabled]);

  const playPingSound = () => {
    try {
      const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
      if (!AudioContextClass) return;
      const ctx = new AudioContextClass();

      if (ctx.state === 'suspended') {
        ctx.resume();
      }

      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime); // A5 chime note
      osc.frequency.exponentialRampToValueAtTime(1320, ctx.currentTime + 0.12); // fast bright uprise

      gain.gain.setValueAtTime(0.06, ctx.currentTime); // polite volume
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.5); // decay over 0.5s

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.5);
    } catch (err) {
      console.warn('Audio feedback context playback failed:', err);
    }
  };

  // Leaflet references
  // NOTE: the map container div is not currently mounted anywhere in the JSX below,
  // so this initialization is inert (kept as-is during the component split to avoid
  // changing behavior; flagged separately as a pre-existing dead-code item).
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const markerGroupRef = useRef<any>(null);

  // Update dynamic timestamp clock
  useEffect(() => {
    const timer = setInterval(() => {
      setTimeStr(new Date().toUTCString());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchProwlerMetrics = async () => {
    try {
      const res = await fetch('/api/prowler/metrics');
      if (res.ok) {
        setProwlerMetrics(await res.json());
      }
    } catch (err) {
      console.error('Error fetching Prowler metrics:', err);
    }
  };

  // Fetch static stats periodically, fallback SSE real-time events
  const syncTelemetry = async () => {
    try {
      const statsRes = await fetch('/api/stats');
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      const threatRes = await fetch('/api/threats');
      if (threatRes.ok) {
        const threatData = await threatRes.json();
        setThreatActors(threatData);
      }

      const settingsRes = await fetch('/api/settings');
      if (settingsRes.ok) {
        const settingsData = await settingsRes.json();
        setSettings(settingsData);
      }

      await fetchProwlerMetrics();
    } catch (err) {
      console.error('Error fetching dashboard metrics:', err);
    }
  };

  // Fetch paginated events log
  const queryLogs = async (page = 1, proto = logFilterProto) => {
    try {
      let url = `/api/events?page=${page}&perPage=12`;
      if (proto !== 'ALL') {
        url += `&protocol=${proto}`;
      }
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events);
        setLogTotalPages(data.pages);
        setLogPage(data.current_page);
      }
    } catch (err) {
      console.error('Error fetching paginated events:', err);
    }
  };

  // Run Leaflet Geolocation Map Initializer
  useEffect(() => {
    const L = (window as any).L;
    if (!L || !mapContainerRef.current) return;

    // Build the Leaflet Map with CartoDB Dark Matter tiles
    if (!mapInstanceRef.current) {
      mapInstanceRef.current = L.map(mapContainerRef.current, {
        center: [20, 10],
        zoom: 2,
        zoomControl: false,
        attributionControl: false
      });

      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18
      }).addTo(mapInstanceRef.current);

      markerGroupRef.current = L.layerGroup().addTo(mapInstanceRef.current);
    }

    return () => {
      // Cleanup on hot module reloading
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  // Render nodes/markers on the Map
  const drawAttackerMarkers = (incidentList: AttackEvent[]) => {
    const L = (window as any).L;
    if (!L || !markerGroupRef.current || !mapInstanceRef.current) return;

    markerGroupRef.current.clearLayers();

    incidentList.forEach((evt) => {
      if (evt.lat && evt.lng) {
        // Red color for SSH, Amber for HTTP, Blue for TELNET
        let pulseColor = 'bg-red-500';
        let pointColor = 'bg-red-500 border border-slate-900';
        if (evt.protocol === 'HTTP') {
          pulseColor = 'bg-amber-400';
          pointColor = 'bg-amber-400 border border-slate-900';
        } else if (evt.protocol === 'TELNET') {
          pulseColor = 'bg-blue-400';
          pointColor = 'bg-blue-400 border border-slate-900';
        }

        const customMarkerIcon = L.divIcon({
          html: `<div class="relative flex items-center justify-center">
            <div class="absolute w-5 h-5 rounded-full ${pulseColor} animate-ping opacity-60"></div>
            <div class="relative w-2.5 h-2.5 rounded-full ${pointColor} shadow shadow-black"></div>
          </div>`,
          className: 'custom-pulsing-node',
          iconSize: [20, 20],
          iconAnchor: [10, 10]
        });

        const popupContent = `
          <div class="p-1 font-mono text-[11px] leading-relaxed">
            <div class="font-extrabold text-red-400 mb-1 border-b border-slate-800 pb-0.5">🔥 INTRUDER INCIDENT</div>
            <div><strong>IP:</strong> ${evt.ip}</div>
            <div><strong>Location:</strong> ${evt.city}, ${evt.country}</div>
            <div><strong>Protocol:</strong> <span class="text-indigo-400 px-1 py-0.5 bg-slate-950 rounded">${evt.protocol}</span></div>
            <div><strong>Target Port:</strong> ${evt.port}</div>
            <div class="mt-1 max-w-[170px] truncate text-slate-400"><strong>Payload:</strong> ${evt.payload}</div>
          </div>
        `;

        L.marker([evt.lat, evt.lng], { icon: customMarkerIcon })
          .bindPopup(popupContent)
          .addTo(markerGroupRef.current);
      }
    });
  };

  // Initialize SSE (Server-Sent Events) Live Update socket channel
  useEffect(() => {
    setSseStatus('connecting');
    const es = new EventSource('/api/live');

    es.onopen = () => {
      setSseStatus('connected');
    };

    es.onerror = () => {
      setSseStatus('disconnected');
    };

    es.onmessage = (event) => {
      try {
        const newEvent: AttackEvent = JSON.parse(event.data);

        // Append to local live ticker records list with duplicate check to prevent dual-key render warnings
        setEvents((prev) => {
          if (prev.some(evt => evt.id === newEvent.id)) {
            return prev;
          }
          const updated = [newEvent, ...prev];
          // Limit list inside state to 100
          const clipped = updated.slice(0, 100);
          drawAttackerMarkers(clipped);
          return clipped;
        });

        // Recalculate metrics incrementally without hammering the database.
        // (Corrected periodically by the resync interval below, since the
        // server caps stored events at 1000 - this optimistic count alone
        // would otherwise drift upward forever with no ceiling.)
        setStats((prev) => {
          const updatedProto = { ...prev.protocol_stats };
          updatedProto[newEvent.protocol] = (updatedProto[newEvent.protocol] || 0) + 1;

          const updatedSource = { ...prev.source_breakdown };
          const src = newEvent.source || 'generator';
          updatedSource[src] = (updatedSource[src] || 0) + 1;

          return {
            ...prev,
            total_attacks: prev.total_attacks + 1,
            protocol_stats: updatedProto,
            source_breakdown: updatedSource
          };
        });

        // Push alarm is triggered if IP attempts exceed configuration threshold
        // We track attempts of this IP
        setThreatActors((prev) => {
          const existing = prev.find(t => t.ip === newEvent.ip);
          const currentCount = existing ? existing.count + 1 : 1;

          if (currentCount >= settings.alertThreshold) {
            // Trigger red visual banner notification with duplicate check
            setActiveAlerts((prevAlerts) => {
              if (prevAlerts.some(alert => alert.id === newEvent.id)) {
                return prevAlerts;
              }
              return [newEvent, ...prevAlerts.slice(0, 4)];
            });

            // Trigger optional subtle ping sound only for transition to new HIGH threat status
            if (currentCount === settings.alertThreshold && soundRef.current) {
              playPingSound();
            }
          }

          const existingIndex = prev.findIndex(t => t.ip === newEvent.ip);
          let updatedThreats = [...prev];
          if (existingIndex !== -1) {
            updatedThreats[existingIndex] = {
              ...updatedThreats[existingIndex],
              count: currentCount,
              level: currentCount >= settings.alertThreshold ? 'HIGH' : currentCount > 4 ? 'MEDIUM' : 'LOW',
              lastSeen: newEvent.timestamp
            };
          } else {
            updatedThreats.push({
              ip: newEvent.ip,
              count: 1,
              country: newEvent.country,
              level: 'LOW',
              lastSeen: newEvent.timestamp
            });
          }
          return updatedThreats.sort((a, b) => b.count - a.count);
        });

      } catch (err) {
        console.error('SSE Payload Parsing Error:', err);
      }
    };

    // Load initial system stats on mounting
    syncTelemetry();
    queryLogs(1, 'ALL');

    // The SSE handler above increments counters optimistically for instant
    // feedback, but has no ceiling - periodically pull the server's real,
    // capped numbers to correct any drift automatically.
    const resyncTimer = setInterval(syncTelemetry, 15000);

    return () => {
      es.close();
      clearInterval(resyncTimer);
    };
  }, [settings.alertThreshold]);

  // Centering & Focusing on a specific intruder node coordinates
  const focusMapOnCoordinates = (evt: AttackEvent) => {
    setSelectedEvent(evt);
    if (mapInstanceRef.current && evt.lat && evt.lng) {
      mapInstanceRef.current.setView([evt.lat, evt.lng], 6, { animate: true });

      const L = (window as any).L;
      if (!L) return;

      // Draw custom popup immediately
      const popupContent = `
        <div class="p-1 font-mono text-[11px] leading-relaxed">
          <div class="font-bold text-red-500 mb-1 border-b border-slate-800 pb-0.5">⚠️ ACTIVE TRAFFIC NODE</div>
          <div><strong>IP:</strong> ${evt.ip}</div>
          <div><strong>Location:</strong> ${evt.city}, ${evt.country}</div>
          <div><strong>Port:</strong> ${evt.port}</div>
          <div class="mt-1 text-slate-400"><strong>Captured payload:</strong> ${evt.payload}</div>
        </div>
      `;

      L.popup()
        .setLatLng([evt.lat, evt.lng])
        .setContent(popupContent)
        .openOn(mapInstanceRef.current);
    }
  };

  // Trace an IP from the Threat Actors tab back to its most recent event and focus the map on it
  const handleTraceIP = (ip: string) => {
    const matched = events.find(e => e.ip === ip);
    if (matched) {
      setActiveTab('dashboard');
      setTimeout(() => focusMapOnCoordinates(matched), 200);
    }
  };

  // Trigger a same-origin demo Wazuh alert (unauthenticated /api/demo/* route -
  // the real /api/wazuh/webhook stays protected by the ingestion API key)
  const handleSimulateOnPrem = async () => {
    setSimulationStatus('queueing');
    try {
      const res = await fetch('/api/demo/wazuh-alert', { method: 'POST' });
      setSimulationStatus(res.ok ? 'compromised' : 'failed');
    } catch (err) {
      console.error(err);
      setSimulationStatus('failed');
    }
    setTimeout(() => setSimulationStatus(null), 3000);
  };

  // Trigger a real Prowler scan against Azure (Service Principal auth) and
  // poll until it finishes, since a real scan takes a couple of minutes.
  const handleSimulateCloud = async () => {
    setCloudScanError(null);
    try {
      const res = await fetch('/api/prowler/scan', { method: 'POST' });
      const body = await res.json();

      if (!res.ok) {
        setCloudScanStatus('failed');
        setCloudScanError(body.error || 'Failed to start scan');
        return;
      }

      setCloudScanStatus('running');

      if (cloudScanPollRef.current) clearInterval(cloudScanPollRef.current);
      cloudScanPollRef.current = setInterval(async () => {
        try {
          const statusRes = await fetch('/api/prowler/scan-status');
          const state = await statusRes.json();

          if (state.status === 'done') {
            clearInterval(cloudScanPollRef.current!);
            setCloudScanStatus('done');
            await fetchProwlerMetrics();
            setTimeout(() => setCloudScanStatus('idle'), 5000);
          } else if (state.status === 'failed') {
            clearInterval(cloudScanPollRef.current!);
            setCloudScanStatus('failed');
            setCloudScanError(state.error || 'Scan failed');
          }
        } catch (err) {
          console.error('Error polling scan status:', err);
        }
      }, 4000);
    } catch (err) {
      console.error(err);
      setCloudScanStatus('failed');
      setCloudScanError('Could not reach the server');
    }
  };

  // Stop polling if the component unmounts mid-scan
  useEffect(() => {
    return () => {
      if (cloudScanPollRef.current) clearInterval(cloudScanPollRef.current);
    };
  }, []);

  // Configure settings overrides
  const handleUpdateSettings = async (override: Partial<SystemSettings>) => {
    const nextSettings = { ...settings, ...override };
    setSettings(nextSettings);
    try {
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(nextSettings)
      });
      syncTelemetry();
    } catch (err) {
      console.error('Failed to sync settings with node database:', err);
    }
  };

  const clearAlert = (index: number) => {
    setActiveAlerts((prev) => prev.filter((_, idx) => idx !== index));
  };

  const handleTabChange = (tab: TabId) => {
    setActiveTab(tab);
    if (tab === 'logs') queryLogs(1, logFilterProto);
    if (tab === 'threats') syncTelemetry();
  };

  const handleToggleSound = () => {
    const next = !soundEnabled;
    setSoundEnabled(next);
    if (next) {
      playPingSound();
    }
  };

  // Setup charting datasets
  // 1. Line Traffic of Protocol distribution
  const chartPieData = Object.entries(stats.protocol_stats).map(([k, v]) => ({
    name: k,
    value: Number(v) || 0
  }));

  const chartPieColors = {
    SSH: '#f87171',    // red 400
    TELNET: '#60a5fa', // blue 400
    HTTP: '#fbbf24'   // amber 400
  };

  // 2. Bar chart of top credential attacks
  const barChartCredentials = stats.top_payloads.slice(0, 5).map(item => ({
    name: item.payload.length > 22 ? item.payload.slice(0, 22) + '...' : item.payload,
    Attempts: item.count
  }));

  // 3. Real hourly traffic density, computed server-side from actual event timestamps
  const timelineChartData = stats.hourly_timeline.map((b) => ({ hour: b.hour, Events: b.events }));

  // Paginated log change triggers
  const handleLogPageChange = (direction: 'next' | 'prev') => {
    const target = direction === 'next' ? logPage + 1 : logPage - 1;
    if (target > 0 && target <= logTotalPages) {
      queryLogs(target, logFilterProto);
    }
  };

  const handleLogFilterChange = (proto: string) => {
    setLogFilterProto(proto);
    queryLogs(1, proto);
  };

  // Filter local state ticker on logs
  const filteredSearchLogs = events.filter(e => {
    if (!logSearchQuery) return true;
    const query = logSearchQuery.toLowerCase();
    return (
      e.ip.toLowerCase().includes(query) ||
      e.payload.toLowerCase().includes(query) ||
      e.country.toLowerCase().includes(query) ||
      e.city.toLowerCase().includes(query)
    );
  });

  const totalCount = stats.total_attacks || 1;
  const sshVal = stats.protocol_stats.SSH || 0;
  const telnetVal = stats.protocol_stats.TELNET || 0;
  const httpVal = stats.protocol_stats.HTTP || 0;

  const sshPercent = Math.round((sshVal / totalCount) * 100);
  const telnetPercent = Math.round((telnetVal / totalCount) * 100);
  const httpPercent = Math.round((httpVal / totalCount) * 100);

  const topPayloadLogs = stats.top_payloads.length > 0
    ? stats.top_payloads.slice(0, 5)
    : [
        { payload: 'admin / admin', count: 42 },
        { payload: 'root / 123456', count: 31 },
        { payload: 'user / password', count: 18 },
        { payload: 'guest / guest', count: 12 },
        { payload: 'support / support', count: 5 }
      ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-mono p-4 md:p-6 flex flex-col gap-4 selection:bg-red-500 selection:text-white overflow-x-hidden">
      <AlertToasts alerts={activeAlerts} onClear={clearAlert} />

      <DashboardHeader sseStatus={sseStatus} />

      <StatTiles stats={stats} prowlerMetrics={prowlerMetrics} />

      <TabNav activeTab={activeTab} onTabChange={handleTabChange} />

      {/* Main Interactive Bento Layout */}
      <main className="flex-1 w-full">

        {/* TAB 1: DASHBOARD OVERVIEW GRID */}
        {activeTab === 'dashboard' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <WazuhPanel events={events} timeStr={timeStr} />
              <ProwlerPanel metrics={prowlerMetrics} />
            </div>

            <ChartsPanel
              chartPieData={chartPieData}
              chartPieColors={chartPieColors}
              sshPercent={sshPercent}
              sshVal={sshVal}
              telnetPercent={telnetPercent}
              telnetVal={telnetVal}
              httpPercent={httpPercent}
              httpVal={httpVal}
              barChartCredentials={barChartCredentials}
              topPayloadLogs={topPayloadLogs}
              timelineChartData={timelineChartData}
            />

            <SettingsPanel
              settings={settings}
              soundEnabled={soundEnabled}
              onUpdateSettings={handleUpdateSettings}
              onToggleSound={handleToggleSound}
            />
          </div>
        )}

        {/* TAB 2: PACKET DECOY STATS LOGS */}
        {activeTab === 'logs' && (
          <LogsTable
            logs={filteredSearchLogs}
            logFilterProto={logFilterProto}
            logSearchQuery={logSearchQuery}
            logPage={logPage}
            logTotalPages={logTotalPages}
            onFilterChange={handleLogFilterChange}
            onSearchChange={setLogSearchQuery}
            onPageChange={handleLogPageChange}
            onFocusMap={focusMapOnCoordinates}
          />
        )}

        {/* TAB 3: THREAT INTELLIGENCE PORTFOLIO */}
        {activeTab === 'threats' && (
          <ThreatsPanel threatActors={threatActors} onSync={syncTelemetry} onTraceIP={handleTraceIP} />
        )}

        {/* TAB 4: DIRECT DECOY ATTACK SIMULATOR */}
        {activeTab === 'simulator' && (
          <SimulatorPanel
            simulationStatus={simulationStatus}
            cloudScanStatus={cloudScanStatus}
            cloudScanError={cloudScanError}
            onSimulateOnPrem={handleSimulateOnPrem}
            onSimulateCloud={handleSimulateCloud}
          />
        )}

      </main>

      <Footer />
    </div>
  );
}
