function pad(value: number): string {
  return String(value).padStart(2, '0');
}

export function formatUtcOffset(minutes: number | null): string {
  if (minutes === null) return 'UTC+00:00';
  const sign = minutes < 0 ? '-' : '+';
  const absolute = Math.abs(minutes);
  return `UTC${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;
}

export function utcOffsetOptions(current?: number) {
  const values = Array.from({ length: (28 * 60) / 15 + 1 }, (_, index) => -14 * 60 + index * 15);
  if (current !== undefined && !values.includes(current)) values.push(current);
  return values
    .sort((left, right) => left - right)
    .map((value) => ({ value, label: formatUtcOffset(value) }));
}
