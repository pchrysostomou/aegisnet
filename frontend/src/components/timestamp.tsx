/** One timestamp format everywhere, in UTC.
 *
 * Deliberately not the reader's locale: an analyst comparing a case against a packet capture
 * or an audit row is comparing against UTC, and a dashboard that quietly shifted times would
 * make them do the arithmetic in their head at the wrong moment. */
export function formatUtc(iso: string): string {
  const moment = new Date(iso);
  if (Number.isNaN(moment.getTime())) return iso;
  return `${moment.toISOString().slice(0, 19).replace("T", " ")}Z`;
}

export function Timestamp({ value }: { value: string }) {
  return (
    <time dateTime={value} className="mono">
      {formatUtc(value)}
    </time>
  );
}
