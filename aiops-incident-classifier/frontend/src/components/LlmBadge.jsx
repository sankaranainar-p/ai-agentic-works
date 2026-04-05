export default function LlmBadge({ status }) {
  const ok = status === 'ok'
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${
        ok
          ? 'bg-emerald-900/50 text-emerald-300 border-emerald-700'
          : 'bg-amber-900/50 text-amber-300 border-amber-700'
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-emerald-400' : 'bg-amber-400'}`} />
      {ok ? 'LLM Active' : 'ML Fallback'}
    </span>
  )
}
