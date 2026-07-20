import { useEffect, useState } from 'react'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || ''
const API_KEY = import.meta.env.VITE_API_KEY || ''
const AUTH = API_KEY ? { 'X-API-Key': API_KEY } : {}

const SOURCES = ['api', 'prometheus', 'datadog', 'pagerduty', 'grafana', 'manual']

function SevBadge({ sev }) {
  const colors = {
    'SEV-1': 'bg-red-900/60 text-red-300',
    'SEV-2': 'bg-orange-900/60 text-orange-300',
    'SEV-3': 'bg-yellow-900/60 text-yellow-300',
    'SEV-4': 'bg-green-900/60 text-green-300',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-medium ${colors[sev] || 'bg-gray-800 text-gray-400'}`}>
      {sev}
    </span>
  )
}

function Section({ title, children }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
      <p className="text-sm font-semibold text-gray-300 border-b border-gray-800 pb-2">{title}</p>
      {children}
    </div>
  )
}

export default function Classify() {
  const [scenarios, setScenarios] = useState([])
  const [alertText, setAlertText] = useState('')
  const [source, setSource] = useState('api')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)

  useEffect(() => {
    axios.get(`${API}/scenarios`).then((r) => setScenarios(r.data)).catch(() => {})
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!alertText.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await axios.post(`${API}/trigger`, { alert_text: alertText, source }, { headers: AUTH })
      setResult(res.data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-100">Classify Alert</h1>

      {/* Scenario quick-fill */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
        <p className="text-sm font-medium text-gray-400">Quick-fill scenarios</p>
        <div className="flex flex-wrap gap-2">
          {scenarios.map((s) => (
            <button
              key={s.name}
              onClick={() => setAlertText(s.alert_text)}
              className="text-xs px-3 py-1.5 rounded-lg border border-gray-700 text-gray-300 hover:border-indigo-500 hover:text-indigo-300 hover:bg-indigo-950/30 transition-colors"
            >
              {s.name}
            </button>
          ))}
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
        <div>
          <label className="block text-xs text-gray-500 mb-1.5 uppercase tracking-wider">Alert Text</label>
          <textarea
            rows={4}
            value={alertText}
            onChange={(e) => setAlertText(e.target.value)}
            placeholder="Paste or type your alert text here…"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-indigo-500 resize-none"
          />
        </div>
        <div className="flex items-center gap-4">
          <div>
            <label className="block text-xs text-gray-500 mb-1.5 uppercase tracking-wider">Source</label>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-indigo-500"
            >
              {SOURCES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div className="flex-1" />
          <button
            type="submit"
            disabled={loading || !alertText.trim()}
            className="px-6 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
          >
            {loading ? 'Processing…' : 'Run Agent Loop →'}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </form>

      {/* Result panel */}
      {result && (
        <div className="space-y-4">
          {/* Classification */}
          <Section title="Classification">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
              <div>
                <p className="text-xs text-gray-500 mb-1">Category</p>
                <p className="text-indigo-300 font-medium">{result.classification?.category}</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Severity</p>
                <SevBadge sev={result.classification?.severity} />
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Confidence</p>
                <p className="text-gray-200">{((result.classification?.confidence ?? 0) * 100).toFixed(0)}%</p>
              </div>
              <div>
                <p className="text-xs text-gray-500 mb-1">Source</p>
                <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                  result.classification?.source === 'llm'
                    ? 'bg-violet-900/60 text-violet-300'
                    : 'bg-blue-900/60 text-blue-300'
                }`}>
                  {result.classification?.source === 'llm' ? 'LLM' : 'ML'}
                </span>
              </div>
            </div>
            {result.classification?.reasoning && (
              <p className="text-gray-400 text-xs mt-2 italic">"{result.classification.reasoning}"</p>
            )}
            <div className="flex gap-4 mt-2 text-xs text-gray-500">
              <span>Team: <span className="text-gray-300">{result.routing?.team}</span></span>
              {result.routing?.runbook && (
                <a href={result.routing.runbook} className="text-indigo-400 hover:underline">Runbook ↗</a>
              )}
            </div>
          </Section>

          {/* RCA */}
          <Section title={`Root Cause Analysis  ·  source: ${result.rca?.source}`}>
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-xs text-gray-500 mb-1">Probable Cause</p>
                <p className="text-gray-200">{result.rca?.probable_cause}</p>
              </div>
              {result.rca?.contributing_factors?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Contributing Factors</p>
                  <ul className="space-y-1">
                    {result.rca.contributing_factors.map((f, i) => (
                      <li key={i} className="text-gray-400 flex gap-2">
                        <span className="text-gray-600">•</span>{f}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {result.rca?.impact_assessment && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Blast Radius</p>
                  <p className="text-gray-400">{result.rca.impact_assessment}</p>
                </div>
              )}
              {result.rca?.estimated_resolution_time && (
                <p className="text-xs text-gray-500">
                  ETA: <span className="text-gray-300">{result.rca.estimated_resolution_time}</span>
                </p>
              )}
            </div>
          </Section>

          {/* Remediation */}
          <Section title="Remediation">
            <div className="space-y-3 text-sm">
              <div>
                <p className="text-xs text-gray-500 mb-1">Action Taken</p>
                <p className="text-gray-200">{result.remediation?.action_taken}</p>
              </div>
              <p className="text-gray-400 text-xs">{result.remediation?.details}</p>
              {result.rca?.immediate_actions?.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 mb-1">Immediate Actions</p>
                  <ol className="space-y-1 list-none">
                    {result.rca.immediate_actions.map((a, i) => (
                      <li key={i} className="text-gray-400 flex gap-2">
                        <span className="text-indigo-500 font-mono text-xs">{i + 1}.</span>{a}
                      </li>
                    ))}
                  </ol>
                </div>
              )}
              {result.remediation?.escalated && (
                <div className="flex items-center gap-2 text-xs text-red-400 bg-red-950/30 border border-red-900/40 rounded-lg px-3 py-2">
                  <span>⚠</span>
                  <span>Escalated — {result.remediation.escalation_reason}</span>
                </div>
              )}
            </div>
          </Section>

          {/* Verification */}
          <Section title="Verification">
            <div className="flex items-center gap-3">
              <span className={`text-sm font-semibold ${
                result.verification?.status === 'resolved' ? 'text-green-400' : 'text-red-400'
              }`}>
                {result.verification?.status === 'resolved' ? '✓ Resolved' : '✗ Unresolved'}
              </span>
              <span className="text-xs text-gray-500">
                (verified after {result.verification?.wait_seconds}s)
              </span>
            </div>
            <p className="text-gray-400 text-sm">{result.verification?.details}</p>
          </Section>
        </div>
      )}
    </div>
  )
}
