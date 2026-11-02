import React, { useEffect, useState } from 'react';
import { ChevronRight, ChevronDown, Search, ExternalLink } from 'lucide-react';
import Pagination from './Pagination';
import { ProwlerFindingsPage, ProwlerScanFinding } from '../types';

interface ProwlerFindingsTableProps {
  // Changes whenever a new scan is uploaded, which triggers a reload.
  refreshKey: string | null;
}

const PER_PAGE = 25;
const STATUS_ORDER = ['FAIL', 'PASS', 'MANUAL'];

function severityClass(severity: string): string {
  const s = severity.toLowerCase();
  if (s === 'critical') return 'bg-red-900/50 text-red-300';
  if (s === 'high') return 'bg-amber-900/50 text-amber-300';
  if (s === 'medium') return 'bg-blue-900/50 text-blue-300';
  return 'bg-slate-800 text-slate-400';
}

function statusClass(status: string): string {
  if (status === 'FAIL') return 'bg-red-950/60 text-red-400 border-red-900/40';
  if (status === 'PASS') return 'bg-emerald-950/50 text-emerald-400 border-emerald-900/40';
  if (status === 'MANUAL') return 'bg-amber-950/50 text-amber-400 border-amber-900/40';
  return 'bg-slate-900 text-slate-400 border-slate-800';
}

// Scan files are untrusted input: only ever link to http(s) URLs (never javascript: etc).
function safeUrl(url: string | null): string | null {
  return url && /^https?:\/\//i.test(url) ? url : null;
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[8px] uppercase tracking-widest font-bold text-slate-500 mb-1">{label}</div>
      <div className="text-[10px] text-slate-300 leading-relaxed break-words whitespace-pre-wrap">{children}</div>
    </div>
  );
}

function FindingDetails({ f }: { f: ProwlerScanFinding }) {
  const link = safeUrl(f.remediation_url);
  const compliance = f.compliance ? Object.entries(f.compliance) : [];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-slate-900/40 border-t border-slate-800">
      <Detail label="Finding">{f.detail || '-'}</Detail>
      <Detail label="Check">
        {f.check_title}
        <div className="text-slate-500 mt-0.5">{f.check_id}</div>
      </Detail>
      {f.description && <Detail label="Description">{f.description}</Detail>}
      {f.risk && <Detail label="Risk">{f.risk}</Detail>}
      {(f.remediation || link) && (
        <Detail label="Remediation">
          {f.remediation}
          {link && (
            <a
              href={link}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 mt-1"
            >
              <ExternalLink size={10} /> Documentation
            </a>
          )}
        </Detail>
      )}
      <Detail label="Resource">
        {f.resource_name}
        {f.resource_type && <div className="text-slate-500 mt-0.5">{f.resource_type}</div>}
        {f.resource_uid && <div className="text-slate-500 mt-0.5 break-all">{f.resource_uid}</div>}
      </Detail>
      <Detail label="Scope">
        {f.account ? `Subscription: ${f.account}` : 'Subscription: -'}
        <div className="text-slate-500 mt-0.5">Region: {f.region || '-'}</div>
        <div className="text-slate-500 mt-0.5">Scanned: {new Date(f.scanned_at).toLocaleString()}</div>
      </Detail>
      {compliance.length > 0 && (
        <div className="md:col-span-2">
          <Detail label="Compliance frameworks">
            <div className="flex flex-wrap gap-1.5 mt-0.5">
              {compliance.map(([framework, reqs]) => (
                <span key={framework} className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[9px]">
                  <span className="text-slate-200 font-bold">{framework}</span>
                  <span className="text-slate-500"> {Array.isArray(reqs) ? reqs.slice(0, 6).join(', ') : String(reqs)}</span>
                </span>
              ))}
            </div>
          </Detail>
        </div>
      )}
    </div>
  );
}

export default function ProwlerFindingsTable({ refreshKey }: ProwlerFindingsTableProps) {
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [service, setService] = useState('');
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState(''); // debounced copy of `search`
  const [page, setPage] = useState(1);
  const [data, setData] = useState<ProwlerFindingsPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    const t = setTimeout(() => {
      setQuery(search);
      setPage(1);
    }, 300);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    const params = new URLSearchParams({ page: String(page), perPage: String(PER_PAGE) });
    if (status) params.set('status', status);
    if (severity) params.set('severity', severity);
    if (service) params.set('service', service);
    if (query) params.set('q', query);

    fetch(`/api/prowler/all-findings?${params.toString()}`)
      .then((res) => {
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        return res.json();
      })
      .then((json: ProwlerFindingsPage) => {
        if (cancelled) return;
        setData(json);
        setError(null);
        setExpanded(null);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load findings');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [status, severity, service, query, page, refreshKey]);

  const changeFilter = (setter: (v: string) => void) => (value: string) => {
    setter(value);
    setPage(1);
  };

  const statusFacets: Record<string, number> = data?.facets.status ?? {};
  const severityFacets: Record<string, number> = data?.facets.severity ?? {};
  const serviceFacets: Record<string, number> = data?.facets.service ?? {};
  const totalInScan = Object.values(statusFacets).reduce((a, b) => a + b, 0);
  const statusKeys = [
    ...STATUS_ORDER.filter((k) => k in statusFacets),
    ...Object.keys(statusFacets).filter((k) => !STATUS_ORDER.includes(k))
  ];

  const selectClass =
    'bg-slate-950 border border-slate-800 text-[10px] px-2.5 py-2 rounded-lg font-mono text-slate-300 focus:outline-none focus:border-red-500';

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col lg:flex-row gap-3 lg:items-center justify-between bg-slate-900/40 border border-slate-800 p-4 rounded-xl">
        <div className="flex flex-wrap items-center gap-1 bg-slate-950 p-1 border border-slate-800 rounded-lg self-start">
          <button
            type="button"
            onClick={() => changeFilter(setStatus)('')}
            className={`px-3 py-1 text-[9px] uppercase font-bold font-mono rounded-md transition ${
              status === '' ? 'bg-red-950 border border-red-900/30 text-red-400' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            All ({totalInScan})
          </button>
          {statusKeys.map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => changeFilter(setStatus)(k)}
              className={`px-3 py-1 text-[9px] uppercase font-bold font-mono rounded-md transition ${
                status === k ? 'bg-red-950 border border-red-900/30 text-red-400' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {k} ({statusFacets[k]})
            </button>
          ))}
        </div>

        <div className="flex flex-wrap gap-2 items-center">
          <select aria-label="Severity" className={selectClass} value={severity} onChange={(e) => changeFilter(setSeverity)(e.target.value)}>
            <option value="">All severities</option>
            {Object.entries(severityFacets).map(([k, n]) => (
              <option key={k} value={k.toLowerCase()}>{k} ({n})</option>
            ))}
          </select>
          <select aria-label="Service" className={selectClass} value={service} onChange={(e) => changeFilter(setService)(e.target.value)}>
            <option value="">All services</option>
            {Object.entries(serviceFacets).map(([k, n]) => (
              <option key={k} value={k}>{k} ({n})</option>
            ))}
          </select>
          <div className="relative">
            <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-600" />
            <input
              type="text"
              aria-label="Search findings"
              placeholder="SEARCH CHECK, RESOURCE, DETAIL..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-64 bg-slate-950 border border-slate-800 text-[10px] pl-7 pr-3 py-2 rounded-lg font-mono text-slate-200 focus:outline-none focus:border-red-500 placeholder-slate-700 uppercase tracking-wider"
            />
          </div>
        </div>
      </div>

      {error && (
        <div className="border border-red-500/30 bg-red-950/20 text-red-400 p-3 rounded-lg text-[10px] font-mono">
          Could not load findings: {error}
        </div>
      )}

      {/* Table */}
      <div className="border border-slate-800 bg-slate-950 rounded-xl overflow-hidden shadow-lg">
        {data && totalInScan === 0 ? (
          <div className="text-center p-10 text-slate-500 font-mono text-[10px] uppercase tracking-widest">
            No Prowler scan data yet. Run a scan and upload the results.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-[10px] text-slate-300">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 select-none">
                  <th className="p-3 w-6"></th>
                  <th className="p-3 uppercase font-bold tracking-wider text-[9px]">Status</th>
                  <th className="p-3 uppercase font-bold tracking-wider text-[9px]">Severity</th>
                  <th className="p-3 uppercase font-bold tracking-wider text-[9px]">Service</th>
                  <th className="p-3 uppercase font-bold tracking-wider text-[9px]">Check</th>
                  <th className="p-3 uppercase font-bold tracking-wider text-[9px]">Resource</th>
                  <th className="p-3 uppercase font-bold tracking-wider text-[9px]">Region</th>
                </tr>
              </thead>
              <tbody>
                {data?.findings.length === 0 && !loading && (
                  <tr>
                    <td colSpan={7} className="text-center p-8 text-slate-500">NO FINDINGS MATCH THESE FILTERS.</td>
                  </tr>
                )}
                {data?.findings.map((f) => {
                  const open = expanded === f.id;
                  return (
                    <React.Fragment key={f.id}>
                      <tr
                        data-testid="finding-row"
                        tabIndex={0}
                        aria-expanded={open}
                        onClick={() => setExpanded(open ? null : f.id)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            setExpanded(open ? null : f.id);
                          }
                        }}
                        className="border-b border-slate-900 hover:bg-slate-900/40 cursor-pointer transition-colors"
                      >
                        <td className="p-3 text-slate-600">
                          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded font-black text-[9px] border uppercase ${statusClass(f.status)}`}>{f.status}</span>
                        </td>
                        <td className="p-3">
                          <span className={`px-1.5 py-0.5 rounded text-[8px] uppercase font-bold ${severityClass(f.severity)}`}>{f.severity}</span>
                        </td>
                        <td className="p-3 text-slate-400">{f.service}</td>
                        <td className="p-3 max-w-[280px]">
                          <div className="truncate text-slate-200" title={f.check_title}>{f.check_title}</div>
                          <div className="truncate text-slate-600 text-[9px]">{f.check_id}</div>
                        </td>
                        <td className="p-3 max-w-[220px] truncate" title={f.resource_uid || f.resource_name}>{f.resource_name}</td>
                        <td className="p-3 text-slate-400">{f.region || '-'}</td>
                      </tr>
                      {open && (
                        <tr data-testid="finding-details">
                          <td colSpan={7} className="p-0">
                            <FindingDetails f={f} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {data && totalInScan > 0 && (
          <Pagination page={data.page} totalPages={data.pages} total={data.total} pageSize={PER_PAGE} onPageChange={setPage} />
        )}
      </div>
    </div>
  );
}
