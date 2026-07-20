import { useEffect, useRef, useState } from 'react'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || ''
const API_KEY = import.meta.env.VITE_API_KEY || ''
const AUTH = API_KEY ? { 'X-API-Key': API_KEY } : {}

// Stage detection: map event keywords → stage name
function detectStage(entry) {
  const ev = (entry.event || '').toLowerCase()
  if (ev.includes('monitor')) return 'monitor'
  if (ev.includes('ml_classified') || ev.includes('llm_classified') || ev.includes('ensemble')) return 'classify'
  if (ev.includes('rca')) return 'rca'
  if (ev.includes('remediation') || ev.includes('slack') || ev.includes('pagerduty')) return 'remediate'
  if (ev.includes('verification')) return 'verify'
  if (ev.includes('escalat')) return 'escalate'
  if (ev.includes('startup') || ev.includes('shutdown')) return 'system'
  return 'other'
}

const STAGE_STYLES = {
  monitor:   'bg-blue-900/40 text-blue-300 border-blue-800/50',
  classify:  'bg-violet-900/40 text-violet-300 border-violet-800/50',
  rca:       'bg-amber-900/40 text-amber-300 border-amber-800/50',
  remediate: 'bg-orange-900/40 text-orange-300 border-orange-800/50',
  verify:    'bg-teal-900/40 text-teal-300 border-teal-800/50',
  escalate:  'bg-red-900/40 text-red-300 border-red-800/50',
  system:    'bg-gray-800/60 text-gray-400 border-gray-700/50',
  other:     'bg-gray-800/40 text-gray-500 border-gray-700/30',
}

const STAGE_DOT = {
  monitor:   'bg-blue-400',
  classify:  'bg-violet-400',
  rca:       'bg-amber-400',
  remediate: 'bg-orange-400',
  verify:    'bg-teal-400',
  escalate:  'bg-red-400',
  system:    'bg-gray-500',
  other:     'bg-gray-600',
}

const ALL_STAGES = ['monitor', 'classify', 'rca', 'remediate', 'verify', 'escalate', 'system', 'other']

function entryMessage(entry) {
  const parts = []
  if (entry.category) parts.push(entry.category)
  if (entry.severity) parts.push(entry.severity)
  if (entry.action) parts.push(entry.action)
  if (entry.step) parts.push(entry.step)
  if (entry.reason) parts.push(entry.reason)
  if (entry.error) parts.push(`error: ${entry.error}`)
  if (entry.note) parts.push(entry.note)
  if (entry.checks !== undefined) parts.push(`${entry.checks} checks`)
  if (entry.status) parts.push(entry.status)
  if (entry.rca_source) parts.push(`rca_source: ${entry.rca_source}`)
  return parts.join(' · ') || entry.event
}

export default function AgentLog() {
  const [entries, setEntries] = useState([])
  const [stageFilter, setStageFilter] = useState('all')
  const [autoScroll, setAutoScroll] = useState(true)
  const bottomRef = useRef(null)
  const eventSourceRef = useRef(null)

  // Load existing entries on mount
  useEffect(() => {
    axios.get(`${API}/agent-log?n=200`, { headers: AUTH }).then((r) => setEntries(r.data)).catch(() => {})
  }, [])

  // SSE live feed
  useEffect(() => {
    const sseUrl = API_KEY
      ? `${API}/agent-log/stream?api_key=${API_KEY}`
      : `${API}/agent-log/stream`
    const es = new EventSource(sseUrl)
    eventSourceRef.current = es

    es.onmessage = (ev) => {
      try {
        const entry = JSON.parse(ev.data)
        setEntries((prev) => {
          const next = [...prev, entry]
          return next.length > 500 ? next.slice(next.length - 500) : next
        })
      } catch (_) {}
    }

    return () => es.close()
  }, [])

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [entries, autoScroll])

  const displayed = stageFilter === 'all'
    ? entries
    : entries.filter((e) => detectStage(e) === stageFilter)

  return (
    <div className="space-y-4 h-full">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-semibold text-gray-100">Agent Log</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-600">{entries.length} entries</span>
          <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            Auto-scroll
          </label>
        </div>
      </div>

      {/* Stage filter buttons */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setStageFilter('all')}
          className={`text-xs px-3 py-1 rounded-full border transition-colors ${
            stageFilter === 'all'
              ? 'border-gray-500 bg-gray-700 text-gray-200'
              : 'border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300'
          }`}
        >
          All
        </button>
        {ALL_STAGES.map((stage) => (
          <button
            key={stage}
            onClick={() => setStageFilter(stage)}
            className={`text-xs px-3 py-1 rounded-full border transition-colors capitalize ${
              stageFilter === stage
                ? `border-current ${STAGE_STYLES[stage]}`
                : 'border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300'
            }`}
          >
            {stage}
          </button>
        ))}
      </div>

      {/* Log feed */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="h-[60vh] overflow-y-auto p-2 font-mono text-xs space-y-0.5">
          {displayed.length === 0 ? (
            <p className="text-gray-600 text-center py-10 font-sans">
              No log entries yet. Submit an alert in Classify to see the agent loop in action.
            </p>
          ) : (
            displayed.map((entry, idx) => {
              const stage = detectStage(entry)
              return (
                <div
                  key={idx}
                  className={`flex items-start gap-2 px-3 py-1.5 rounded border ${STAGE_STYLES[stage]}`}
                >
                  {/* Dot */}
                  <span className={`mt-1 w-1.5 h-1.5 rounded-full flex-shrink-0 ${STAGE_DOT[stage]}`} />
                  {/* Timestamp */}
                  <span className="text-gray-600 flex-shrink-0 w-24">
                    {new Date(entry.ts).toLocaleTimeString()}
                  </span>
                  {/* Stage */}
                  <span className="flex-shrink-0 w-20 capitalize opacity-70">{stage}</span>
                  {/* Event */}
                  <span className="flex-shrink-0 w-36 text-current opacity-80">{entry.event}</span>
                  {/* ID */}
                  {entry.id && (
                    <span className="flex-shrink-0 w-20 text-indigo-400/70">{entry.id}</span>
                  )}
                  {/* Message */}
                  <span className="text-gray-400 truncate">{entryMessage(entry)}</span>
                </div>
              )
            })
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  )
}
