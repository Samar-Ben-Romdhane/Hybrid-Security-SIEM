/**
 * Format a timestamp as "YYYY-MM-DD HH:mm:ss" in the viewer's local time zone.
 * (toISOString() always prints UTC, which shows the wrong hour for anyone not on UTC.)
 */
export function formatLocalDateTime(value: string | number | Date): string {
  const d = new Date(value);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
