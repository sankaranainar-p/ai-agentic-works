const STYLES = {
  'SEV-1': 'bg-red-900/60 text-red-300 border-red-700',
  'SEV-2': 'bg-orange-900/60 text-orange-300 border-orange-700',
  'SEV-3': 'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  'SEV-4': 'bg-emerald-900/60 text-emerald-300 border-emerald-700',
}

export default function SeverityBadge({ severity, size = 'sm' }) {
  const base = size === 'lg'
    ? 'px-3 py-1 text-sm font-bold rounded-md border'
    : 'px-2 py-0.5 text-xs font-bold rounded border'
  return (
    <span className={`inline-flex items-center ${base} ${STYLES[severity] ?? 'bg-slate-800 text-slate-400 border-slate-600'}`}>
      {severity ?? '—'}
    </span>
  )
}
