import { useEffect, useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000/api/v1'

type ThreatGroupSummary = {
  threat_group: string | null
  count: number
}

type IntelSummaryResponse = {
  total_events: number
  malicious_events: number
  threat_groups: ThreatGroupSummary[]
}

type TechniqueSummary = {
  technique_id: string
  tactic?: string
  count: number
}

type MatrixResponse = {
  techniques: TechniqueSummary[]
}

type KillchainEvent = {
  event_id: string
  timestamp: string
  phase?: string
  mitre?: {
    tactic?: string
    technique_id?: string
    technique_name?: string
  }
  threat_intel?: {
    is_malicious?: boolean
    matched_ioc?: string | null
    threat_group?: string | null
  }
  action?: string
}

type KillchainResponse = {
  host_id: string
  kcps: number
  is_critical: boolean
  phases: Record<string, number>
  timeline: KillchainEvent[]
  ransomware_suspected?: boolean
  ransomware_reason?: string
}

type TabId = 'intel' | 'matrix' | 'killchain' | 'alerts'

function App() {
  const [activeTab, setActiveTab] = useState<TabId>('intel')

  const [intelSummary, setIntelSummary] = useState<IntelSummaryResponse | null>(null)
  const [intelLoading, setIntelLoading] = useState(false)
  const [intelError, setIntelError] = useState<string | null>(null)

  const [matrix, setMatrix] = useState<MatrixResponse | null>(null)
  const [matrixLoading, setMatrixLoading] = useState(false)
  const [matrixError, setMatrixError] = useState<string | null>(null)

  const [hostId, setHostId] = useState('')
  const [killchain, setKillchain] = useState<KillchainResponse | null>(null)
  const [killLoading, setKillLoading] = useState(false)
  const [killError, setKillError] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const [alertId, setAlertId] = useState('')
  const [alertStatus, setAlertStatus] = useState<'False Positive' | 'Investigating' | 'Resolved'>('Investigating')
  const [alertMessage, setAlertMessage] = useState<string | null>(null)
  const [alertError, setAlertError] = useState<string | null>(null)

  useEffect(() => {
    if (activeTab === 'intel' && !intelSummary && !intelLoading) {
      void fetchIntelSummary()
    }
    if (activeTab === 'matrix' && !matrix && !matrixLoading) {
      void fetchMatrix()
    }
  }, [activeTab])

  async function fetchIntelSummary() {
    try {
      setIntelLoading(true)
      setIntelError(null)
      const res = await fetch(`${API_BASE}/intel/summary`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as IntelSummaryResponse
      setIntelSummary(data)
    } catch (err) {
      setIntelError((err as Error).message)
    } finally {
      setIntelLoading(false)
    }
  }

  async function fetchMatrix() {
    try {
      setMatrixLoading(true)
      setMatrixError(null)
      const res = await fetch(`${API_BASE}/hunt/matrix`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as MatrixResponse
      setMatrix(data)
    } catch (err) {
      setMatrixError((err as Error).message)
    } finally {
      setMatrixLoading(false)
    }
  }

  async function handleKillchainLookup(e: React.FormEvent) {
    e.preventDefault()
    if (!hostId.trim()) return

    try {
      setKillLoading(true)
      setKillError(null)
      const res = await fetch(`${API_BASE}/hunt/killchain/${encodeURIComponent(hostId.trim())}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = (await res.json()) as KillchainResponse
      setKillchain(data)
    } catch (err) {
      setKillError((err as Error).message)
    } finally {
      setKillLoading(false)
    }
  }

  async function handleAlertUpdate(e: React.FormEvent) {
    e.preventDefault()
    if (!alertId.trim()) return

    try {
      setAlertError(null)
      setAlertMessage(null)
      const res = await fetch(`${API_BASE}/alerts/${encodeURIComponent(alertId.trim())}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: alertStatus }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setAlertMessage(`Updated alert ${data.alert_id} to "${data.status}"`)
    } catch (err) {
      setAlertError((err as Error).message)
    }
  }

  async function handleExportReport() {
    if (!hostId.trim()) return
    try {
      setExporting(true)
      setExportError(null)
      const res = await fetch(`${API_BASE}/hunt/killchain/${encodeURIComponent(hostId.trim())}/report`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const text = await res.text()
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${hostId.trim()}-incident-report.txt`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
    } catch (err) {
      setExportError((err as Error).message)
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Cyber Threat Hunter Pro</h1>
            <p className="text-sm text-slate-400">
              Unified CTI, MITRE ATT&amp;CK mapping, and Kill Chain analytics
            </p>
          </div>
          <span className="rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300 ring-1 ring-emerald-500/40">
            Early access dashboard
          </span>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-6">
        <nav className="mb-6 flex gap-2 rounded-lg bg-slate-900/70 p-1 text-sm">
          <TabButton id="intel" label="Intel Summary" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="matrix" label="MITRE Matrix" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="killchain" label="Kill Chain" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="alerts" label="Alert Status" activeTab={activeTab} setActiveTab={setActiveTab} />
        </nav>

        {activeTab === 'intel' && (
          <section className="space-y-6">
            <h2 className="text-lg font-semibold">Threat Intelligence Overview</h2>
            {intelLoading && <p className="text-sm text-slate-400">Loading threat intel…</p>}
            {intelError && <p className="text-sm text-red-400">Error: {intelError}</p>}
            {intelSummary && (
              <>
                <div className="grid gap-4 sm:grid-cols-3">
                  <SummaryCard
                    title="Total Events"
                    value={intelSummary.total_events.toLocaleString()}
                    description="All ingested normalized events"
                  />
                  <SummaryCard
                    title="Malicious Events"
                    value={intelSummary.malicious_events.toLocaleString()}
                    description="Events tagged as malicious"
                  />
                  <SummaryCard
                    title="Threat Groups"
                    value={intelSummary.threat_groups.length.toString()}
                    description="Distinct threat actor groups seen"
                  />
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/60">
                  <div className="border-b border-slate-800 px-4 py-3">
                    <h3 className="text-sm font-semibold text-slate-200">Threat groups by volume</h3>
                  </div>
                  <div className="divide-y divide-slate-800">
                    {intelSummary.threat_groups.length === 0 && (
                      <p className="px-4 py-3 text-sm text-slate-400">No threat groups detected yet.</p>
                    )}
                    {intelSummary.threat_groups.map((g) => (
                      <div key={g.threat_group ?? 'unknown'} className="flex items-center justify-between px-4 py-3">
                        <div>
                          <p className="text-sm font-medium">
                            {g.threat_group ?? <span className="text-slate-400">Unknown group</span>}
                          </p>
                          <p className="text-xs text-slate-400">Events linked to this actor</p>
                        </div>
                        <span className="rounded-full bg-slate-800 px-3 py-1 text-xs font-semibold text-slate-100">
                          {g.count.toLocaleString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </section>
        )}

        {activeTab === 'matrix' && (
          <section className="space-y-6">
            <h2 className="text-lg font-semibold">MITRE ATT&amp;CK Coverage</h2>
            {matrixLoading && <p className="text-sm text-slate-400">Loading matrix data…</p>}
            {matrixError && <p className="text-sm text-red-400">Error: {matrixError}</p>}
            {matrix && (
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                <p className="mb-4 text-sm text-slate-400">
                  Each cell represents a technique detected in your environment. Color intensity reflects
                  observation frequency.
                </p>
                <MatrixGrid techniques={matrix.techniques} />
              </div>
            )}
          </section>
        )}

        {activeTab === 'killchain' && (
          <section className="space-y-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold">Host Kill Chain Story</h2>
                <p className="text-sm text-slate-400">
                  Pivot on a host to see its chronological attack progression and Kill Chain score.
                </p>
              </div>
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <form onSubmit={handleKillchainLookup} className="flex flex-wrap gap-2">
                  <input
                    type="text"
                    value={hostId}
                    onChange={(e) => setHostId(e.target.value)}
                    placeholder="e.g. WIN-DC-01 or UBUNTU-WEB-01"
                    className="h-9 rounded-md border border-slate-700 bg-slate-900 px-3 text-sm outline-none ring-emerald-500/50 placeholder:text-slate-500 focus:border-emerald-500 focus:ring-1"
                  />
                  <button
                    type="submit"
                    className="h-9 rounded-md bg-emerald-500 px-4 text-sm font-medium text-emerald-950 shadow-sm hover:bg-emerald-400"
                  >
                    Hunt host
                  </button>
                </form>
                <button
                  type="button"
                  onClick={handleExportReport}
                  disabled={!hostId.trim() || exporting}
                  className="h-9 rounded-md border border-slate-600 bg-slate-900 px-3 text-xs font-medium text-slate-100 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {exporting ? 'Exporting…' : 'Export IR Report'}
                </button>
              </div>
            </div>

            {killLoading && <p className="text-sm text-slate-400">Building kill chain timeline…</p>}
            {killError && <p className="text-sm text-red-400">Error: {killError}</p>}
            {exportError && <p className="text-sm text-red-400">Export error: {exportError}</p>}

            {killchain && (
              <div className="space-y-6">
                <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">
                  <div>
                    <p className="text-xs uppercase tracking-wide text-slate-400">Host</p>
                    <p className="text-sm font-semibold">{killchain.host_id}</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-4">
                    <div className="text-right">
                      <p className="text-xs uppercase tracking-wide text-slate-400">KCPS</p>
                      <p className="text-lg font-semibold text-emerald-400">{killchain.kcps.toFixed(1)}</p>
                    </div>
                    <span
                      className={`rounded-full px-3 py-1 text-xs font-semibold ring-1 ${
                        killchain.is_critical
                          ? 'bg-red-500/10 text-red-300 ring-red-500/50'
                          : 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/40'
                      }`}
                    >
                      {killchain.is_critical ? 'Critical hunting lead' : 'Under threshold'}
                    </span>
                    {killchain.ransomware_suspected && (
                      <span className="rounded-full bg-orange-500/10 px-3 py-1 text-xs font-semibold text-orange-300 ring-1 ring-orange-500/60">
                        Ransomware pattern detected
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-4">
                  {Object.entries(killchain.phases).map(([phase, score]) => (
                    <div
                      key={phase}
                      className="rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs text-slate-300"
                    >
                      <p className="mb-1 font-semibold">{phase}</p>
                      <div className="flex items-center justify-between gap-2">
                        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                          <div
                            className="h-full bg-emerald-500"
                            style={{ width: `${Math.min(100, score * 4)}%` }}
                          />
                        </div>
                        <span className="font-mono text-[11px] text-slate-400">{score.toFixed(1)}</span>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/60">
                  <div className="border-b border-slate-800 px-4 py-3">
                    <h3 className="text-sm font-semibold text-slate-200">Timeline</h3>
                  </div>
                  <ol className="divide-y divide-slate-800">
                    {killchain.timeline.length === 0 && (
                      <li className="px-4 py-3 text-sm text-slate-400">
                        No events for this host yet. Ingest logs via the API to see activity.
                      </li>
                    )}
                    {killchain.timeline.map((ev) => (
                      <li key={ev.event_id} className="flex gap-3 px-4 py-3 text-sm">
                        <div className="mt-1 h-2 w-2 flex-shrink-0 rounded-full bg-emerald-400" />
                        <div className="flex flex-1 flex-col gap-1">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="font-medium text-slate-100">
                              {ev.mitre?.technique_id ?? 'Unmapped technique'}
                            </p>
                            <p className="text-xs text-slate-500">
                              {new Date(ev.timestamp).toLocaleString()} • {ev.phase ?? 'Unknown phase'}
                            </p>
                          </div>
                          <p className="text-xs text-slate-400">
                            {ev.mitre?.technique_name ?? 'No technique name available'}
                          </p>
                          <div className="flex flex-wrap gap-2 text-[11px] text-slate-300">
                            {ev.action && (
                              <span className="rounded-full bg-slate-800 px-2 py-0.5">Action: {ev.action}</span>
                            )}
                            {ev.threat_intel?.threat_group && (
                              <span className="rounded-full bg-purple-900/40 px-2 py-0.5 text-purple-200">
                                Actor: {ev.threat_intel.threat_group}
                              </span>
                            )}
                            {ev.threat_intel?.matched_ioc && (
                              <span className="rounded-full bg-amber-900/40 px-2 py-0.5 text-amber-100">
                                IoC: {ev.threat_intel.matched_ioc}
                              </span>
                            )}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
              </div>
            )}
          </section>
        )}

        {activeTab === 'alerts' && (
          <section className="space-y-6">
            <h2 className="text-lg font-semibold">Alert Lifecycle</h2>
            <p className="text-sm text-slate-400">
              Use this view to synchronize alert status with external tooling like ticketing or chat systems.
            </p>
            <form
              onSubmit={handleAlertUpdate}
              className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4 sm:flex-row sm:items-end"
            >
              <div className="flex-1 space-y-1">
                <label className="block text-xs font-medium text-slate-300">Alert ID</label>
                <input
                  type="text"
                  value={alertId}
                  onChange={(e) => setAlertId(e.target.value)}
                  placeholder="e.g. alert-1234"
                  className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm outline-none ring-emerald-500/50 placeholder:text-slate-500 focus:border-emerald-500 focus:ring-1"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">Status</label>
                <select
                  value={alertStatus}
                  onChange={(e) =>
                    setAlertStatus(e.target.value as 'False Positive' | 'Investigating' | 'Resolved')
                  }
                  className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm outline-none ring-emerald-500/50 focus:border-emerald-500 focus:ring-1"
                >
                  <option value="False Positive">False Positive</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Resolved">Resolved</option>
                </select>
              </div>
              <button
                type="submit"
                className="h-9 rounded-md bg-emerald-500 px-4 text-sm font-medium text-emerald-950 shadow-sm hover:bg-emerald-400"
              >
                Update
              </button>
            </form>
            {alertMessage && <p className="text-sm text-emerald-300">{alertMessage}</p>}
            {alertError && <p className="text-sm text-red-400">Error: {alertError}</p>}
          </section>
        )}
      </main>
    </div>
  )
}

type TabButtonProps = {
  id: TabId
  label: string
  activeTab: TabId
  setActiveTab: (id: TabId) => void
}

function TabButton({ id, label, activeTab, setActiveTab }: TabButtonProps) {
  const isActive = activeTab === id
  return (
    <button
      type="button"
      onClick={() => setActiveTab(id)}
      className={`flex-1 rounded-md px-3 py-2 text-xs font-medium transition ${
        isActive
          ? 'bg-slate-800 text-slate-50 shadow-sm'
          : 'bg-transparent text-slate-400 hover:bg-slate-800/60 hover:text-slate-100'
      }`}
    >
      {label}
    </button>
  )
}

type SummaryCardProps = {
  title: string
  value: string
  description: string
}

function SummaryCard({ title, value, description }: SummaryCardProps) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-400">{title}</p>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
      <p className="mt-1 text-xs text-slate-400">{description}</p>
    </div>
  )
}

type MatrixGridProps = {
  techniques: TechniqueSummary[]
}

function MatrixGrid({ techniques }: MatrixGridProps) {
  if (techniques.length === 0) {
    return <p className="text-sm text-slate-400">No MITRE techniques mapped yet.</p>
  }

  const byTactic = techniques.reduce<Record<string, TechniqueSummary[]>>((acc, t) => {
    const key = t.tactic || 'Unmapped'
    acc[key] = acc[key] ?? []
    acc[key].push(t)
    return acc
  }, {})

  const tactics = Object.keys(byTactic).sort()

  const maxCount = Math.max(...techniques.map((t) => t.count))

  return (
    <div className="grid gap-4 md:grid-cols-4">
      {tactics.map((tactic) => (
        <div key={tactic} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{tactic}</p>
          <div className="space-y-1">
            {byTactic[tactic].map((t) => {
              const intensity = maxCount === 0 ? 0 : t.count / maxCount
              const bgClass =
                intensity > 0.66 ? 'bg-emerald-400' : intensity > 0.33 ? 'bg-emerald-500/70' : 'bg-emerald-500/40'
              return (
                <div
                  key={t.technique_id}
                  className="flex items-center justify-between gap-2 rounded-md bg-slate-900/80 px-2 py-1"
                >
                  <div className="flex-1">
                    <p className="text-xs font-medium text-slate-100">{t.technique_id}</p>
                    <p className="text-[11px] text-slate-400">{t.count.toLocaleString()} events</p>
                  </div>
                  <div className="flex h-6 w-6 items-center justify-center rounded-md bg-slate-900">
                    <div className={`h-4 w-4 rounded ${bgClass}`} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

export default App
