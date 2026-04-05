import { useState } from 'react'
import { classify } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import LlmBadge from '../components/LlmBadge'

const SOURCES = ['Datadog', 'Splunk', 'Dynatrace', 'PagerDuty', 'Prometheus', 'Grafana', 'CloudWatch']

const QUICK_FILLS = [
  {
    label: 'DDoS',
    payload: {
      alert_text:
        'Inbound request rate on payment-gateway exceeded 900k req/min. Traffic distributed across 52 countries. WAF flagging volumetric DDoS pattern. Source IPs rotating every 30 seconds.',
      source: 'Datadog',
    },
  },
  {
    label: '500 Spike',
    payload: {
      alert_text:
        'ALERT: HTTP 500 error rate spiked to 18% (normal baseline 0.2%). Payment-service pods entering CrashLoopBackOff — 3 of 5 pods down. Database connection pool exhausted at 200/200 connections. Upstream timeout errors flooding checkout-service logs. Customer-facing checkout broken.',
      source: 'Prometheus',
    },
  },
  {
    label: 'Availability Drop',
    payload: {
      alert_text:
        'SEV-1 CANDIDATE: Overall service availability dropped to 43%. SLA breach threshold is 99.9%. Health checks failing on 8 of 12 registered endpoints. Multiple services returning 503. PagerDuty escalation triggered. On-call engineer acknowledging. ETA to restore unknown.',
      source: 'PagerDuty',
    },
  },
]

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100)
  const color = pct >= 80 ? 'bg-emerald-500' : pct >= 60 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-slate-400">Confidence</span>
        <span className="text-white font-medium">{pct}%</span>
      </div>
      <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function Badge({ children, color = 'slate' }) {
  const map = {
    green:  'bg-emerald-900/50 text-emerald-300 border-emerald-700',
    red:    'bg-red-900/50 text-red-300 border-red-700',
    slate:  'bg-slate-800 text-slate-400 border-slate-600',
    violet: 'bg-violet-900/50 text-violet-300 border-violet-700',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${map[color]}`}>
      {children}
    </span>
  )
}

export default function Classify() {
  const [form, setForm]     = useState({ alert_text: '', source: '' })
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]   = useState(null)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const { data } = await classify(form)
      setResult(data)
    } catch (err) {
      setError(err.response?.data?.detail ?? err.message ?? 'Classification failed')
    } finally {
      setLoading(false)
    }
  }

  const applyQuickFill = (payload) => {
    setForm(payload)
    setResult(null)
    setError(null)
  }

  const fd = result?.final_decision

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white">Classify Incident</h1>
        <p className="text-sm text-slate-500 mt-0.5">Submit an alert for ML + LLM ensemble classification</p>
      </div>

      <div className="grid lg:grid-cols-2 gap-6 items-start">
        {/* Left — input */}
        <div className="space-y-4">
          {/* Quick fills */}
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wide mb-2">Quick-fill test alerts</p>
            <div className="flex gap-2 flex-wrap">
              {QUICK_FILLS.map(({ label, payload }) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => applyQuickFill(payload)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-500 text-slate-300 text-xs font-medium rounded-lg transition-colors"
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Alert text */}
            <div>
              <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1.5">
                Alert Text *
              </label>
              <textarea
                required
                rows={10}
                value={form.alert_text}
                onChange={e => setForm(f => ({ ...f, alert_text: e.target.value }))}
                placeholder="Paste the full alert body here — title, description, metrics, any context…"
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-slate-100 text-sm placeholder:text-slate-600 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 resize-none transition-colors"
              />
            </div>

            {/* Source */}
            <div>
              <label className="block text-xs font-medium text-slate-400 uppercase tracking-wide mb-1.5">
                Source
              </label>
              <select
                value={form.source}
                onChange={e => setForm(f => ({ ...f, source: e.target.value }))}
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 text-slate-100 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/20 transition-colors appearance-none"
              >
                <option value="">— Select source —</option>
                {SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-xl transition-colors text-sm flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Classifying…
                </>
              ) : 'Classify Incident'}
            </button>
          </form>

          {error && (
            <div className="flex items-start gap-2 bg-red-900/30 border border-red-700 rounded-xl px-4 py-3 text-red-300 text-sm">
              <svg className="w-4 h-4 mt-0.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              {error}
            </div>
          )}
        </div>

        {/* Right — result */}
        <div>
          {!result && !loading && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
              <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-3">
                <svg className="w-6 h-6 text-slate-600" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-slate-500 text-sm">Submit an alert to see the classification result</p>
            </div>
          )}

          {loading && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
              <svg className="w-8 h-8 animate-spin text-blue-500 mx-auto mb-3" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              <p className="text-slate-400 text-sm">Running ML + LLM ensemble…</p>
            </div>
          )}

          {result && fd && (
            <div className="space-y-4">
              {/* Final decision */}
              <div className="bg-slate-900 border border-blue-700/40 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="font-semibold text-white text-sm">Final Classification</h2>
                  <div className="flex items-center gap-2">
                    <LlmBadge status={result.llm_status} />
                    {fd.severity_override && (
                      <span className="text-xs px-2 py-0.5 rounded border bg-orange-900/40 text-orange-300 border-orange-700">
                        Override
                      </span>
                    )}
                  </div>
                </div>

                {/* Category + severity */}
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-lg bg-blue-900/40 border border-blue-700/40 flex items-center justify-center shrink-0">
                    <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A2 2 0 013 12V7a2 2 0 012-2z" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-white font-semibold capitalize">{fd.category.replace(/_/g, ' ')}</p>
                    <p className="text-xs text-slate-400">{fd.route_to}</p>
                  </div>
                  <div className="ml-auto">
                    <SeverityBadge severity={fd.severity} size="lg" />
                  </div>
                </div>

                {/* Confidence bar */}
                <div className="mb-4">
                  <ConfidenceBar value={fd.confidence} />
                </div>

                {/* Auto-remediation + escalation badges */}
                <div className="flex gap-2 mb-4">
                  <Badge color={fd.auto_remediation ? 'green' : 'slate'}>
                    {fd.auto_remediation ? '✓ Auto-remediation available' : 'Manual remediation required'}
                  </Badge>
                  {fd.escalation_required && <Badge color="red">Escalation required</Badge>}
                </div>

                {/* Recommended action */}
                <div className="bg-slate-800 rounded-lg px-4 py-3 mb-4">
                  <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Recommended Action</p>
                  <p className="text-slate-200 text-sm">{fd.recommended_action}</p>
                </div>

                {/* Reasoning */}
                {fd.reasoning && (
                  <p className="text-xs text-slate-500 italic mb-4">{fd.reasoning}</p>
                )}

                {/* Runbook */}
                {fd.runbook?.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-500 uppercase tracking-wide mb-2">Runbook Steps</p>
                    <ol className="space-y-1.5">
                      {fd.runbook.map((step, i) => (
                        <li key={i} className="flex gap-2.5 text-sm text-slate-300">
                          <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-900/50 border border-blue-700/50 text-blue-400 text-xs flex items-center justify-center font-medium">
                            {i + 1}
                          </span>
                          {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>

              {/* ML vs LLM comparison */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  ['ML Model', result.ml_result],
                  ['LLM (Claude)', result.llm_result],
                ].map(([label, r]) => (
                  <div key={label} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-wide mb-2">{label}</p>
                    {r ? (
                      <>
                        <p className="text-white text-sm font-medium capitalize">{r.category.replace(/_/g, ' ')}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <SeverityBadge severity={r.severity} />
                          <span className="text-xs text-slate-500">{Math.round(r.confidence * 100)}%</span>
                        </div>
                      </>
                    ) : (
                      <p className="text-slate-600 text-sm">Unavailable</p>
                    )}
                  </div>
                ))}
              </div>

              {/* Agreement indicator */}
              <div className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border text-xs font-medium ${
                result.agreement
                  ? 'bg-emerald-900/20 border-emerald-800 text-emerald-400'
                  : 'bg-amber-900/20 border-amber-800 text-amber-400'
              }`}>
                <span>{result.agreement ? '✓' : '⚠'}</span>
                {result.agreement ? 'ML and LLM models agreed on category' : 'ML and LLM models disagreed — LLM result used'}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
