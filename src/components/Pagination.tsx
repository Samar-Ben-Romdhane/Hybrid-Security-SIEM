import React, { useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

/**
 * Client-side pagination state. The current page is clamped on every render,
 * so it stays valid when the list shrinks (e.g. after a rescan or resync).
 */
export function usePagination<T>(items: T[], pageSize: number) {
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;
  const pageItems = items.slice(start, start + pageSize);
  return { page: safePage, setPage, totalPages, start, pageItems, total: items.length, pageSize };
}

interface PaginationProps {
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  onPageChange: (page: number) => void;
}

const btnClass =
  'flex items-center gap-1 px-2.5 py-1 border border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200 hover:border-slate-700 disabled:opacity-30 disabled:cursor-not-allowed text-[8px] font-mono font-bold rounded-md transition uppercase tracking-widest';

export default function Pagination({ page, totalPages, total, pageSize, onPageChange }: PaginationProps) {
  if (total <= pageSize) return null;
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  return (
    <div className="border-t border-slate-800 bg-slate-950/60 px-3 py-2 flex items-center justify-between gap-2 font-mono">
      <span className="text-[9px] text-slate-500 uppercase tracking-wider">
        {from}-{to} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button type="button" className={btnClass} onClick={() => onPageChange(page - 1)} disabled={page <= 1}>
          <ChevronLeft size={10} /> Prev
        </button>
        <span className="text-[9px] text-slate-400 uppercase tracking-wider">
          {page} / {totalPages}
        </span>
        <button type="button" className={btnClass} onClick={() => onPageChange(page + 1)} disabled={page >= totalPages}>
          Next <ChevronRight size={10} />
        </button>
      </div>
    </div>
  );
}
