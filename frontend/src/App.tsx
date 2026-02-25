import { useEffect, useState, useCallback } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000/api/v1'

/* ─── Types ────────────────────────────────────────────────────────────── */

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
  severity?: string
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

type AlertFeedItem = {
  event_id: string
  timestamp: string
  host_id?: string
  host_ip?: string
  action?: string
  severity: string
  kill_chain_phase?: string
  mitre_technique?: string
  mitre_tactic?: string
  threat_group?: string
  is_malicious: boolean
}

type SeverityStats = {
  Critical: number
  High: number
  Medium: number
  Low: number
}

type HeatmapCountry = {
  country_code: string
  country_name: string
  lat: number
  lon: number
  count: number
}

type TabId = 'intel' | 'matrix' | 'killchain' | 'siem' | 'heatmap'

/* ─── Severity helpers ─────────────────────────────────────────────────── */

const SEV_COLORS: Record<string, { bg: string; text: string; ring: string; dot: string }> = {
  Critical: { bg: 'bg-red-500/10', text: 'text-red-300', ring: 'ring-red-500/50', dot: 'bg-red-400' },
  High:     { bg: 'bg-orange-500/10', text: 'text-orange-300', ring: 'ring-orange-500/50', dot: 'bg-orange-400' },
  Medium:   { bg: 'bg-yellow-500/10', text: 'text-yellow-300', ring: 'ring-yellow-500/50', dot: 'bg-yellow-400' },
  Low:      { bg: 'bg-slate-500/10', text: 'text-slate-300', ring: 'ring-slate-500/50', dot: 'bg-slate-400' },
}

function sevStyle(sev: string) {
  return SEV_COLORS[sev] ?? SEV_COLORS.Low
}

/* ─── World map SVG paths (simplified) ─────────────────────────────────── */

const COUNTRY_PATHS: Record<string, { d: string; cx: number; cy: number; name: string }> = {
  RU: { d: 'M480,60 L560,55 590,70 600,90 580,100 560,95 520,90 500,80 490,70Z', cx: 540, cy: 77, name: 'Russia' },
  CN: { d: 'M540,120 L570,115 585,125 580,140 565,150 545,145 535,135Z', cx: 558, cy: 132, name: 'China' },
  US: { d: 'M100,100 L170,95 180,110 175,130 150,135 120,130 105,120Z', cx: 140, cy: 115, name: 'United States' },
  KP: { d: 'M575,108 L585,105 590,112 585,118 578,115Z', cx: 582, cy: 112, name: 'North Korea' },
  IR: { d: 'M470,130 L490,125 500,135 495,145 480,148 470,140Z', cx: 483, cy: 137, name: 'Iran' },
  GB: { d: 'M370,75 L378,70 382,78 380,86 374,88 370,82Z', cx: 376, cy: 79, name: 'United Kingdom' },
  DE: { d: 'M390,78 L400,75 405,83 402,92 395,94 390,87Z', cx: 397, cy: 84, name: 'Germany' },
  ID: { d: 'M550,190 L580,185 590,195 575,205 555,200Z', cx: 570, cy: 195, name: 'Indonesia' },
  IN: { d: 'M510,135 L530,128 535,145 525,165 510,160 505,148Z', cx: 520, cy: 148, name: 'India' },
  BR: { d: 'M200,190 L230,175 245,195 235,220 210,225 195,210Z', cx: 220, cy: 200, name: 'Brazil' },
  AU: { d: 'M570,220 L610,215 620,235 605,250 575,245 565,232Z', cx: 593, cy: 233, name: 'Australia' },
  JP: { d: 'M590,105 L597,100 600,108 596,115 590,112Z', cx: 595, cy: 108, name: 'Japan' },
  FR: { d: 'M378,88 L390,85 394,94 388,100 380,98 376,93Z', cx: 385, cy: 93, name: 'France' },
  ZA: { d: 'M420,230 L440,225 445,240 435,250 420,245Z', cx: 432, cy: 238, name: 'South Africa' },
  CA: { d: 'M90,55 L180,50 190,70 175,85 100,90 85,75Z', cx: 140, cy: 70, name: 'Canada' },
  MX: { d: 'M100,135 L135,130 140,145 125,155 105,150Z', cx: 120, cy: 143, name: 'Mexico' },
  KR: { d: 'M580,115 L588,112 592,120 586,125 580,122Z', cx: 585, cy: 118, name: 'South Korea' },
  UA: { d: 'M425,78 L445,75 450,85 442,92 428,90Z', cx: 438, cy: 84, name: 'Ukraine' },
  SA: { d: 'M460,145 L478,140 482,155 470,162 458,156Z', cx: 470, cy: 151, name: 'Saudi Arabia' },
  NG: { d: 'M395,175 L410,170 415,182 405,190 395,185Z', cx: 405, cy: 180, name: 'Nigeria' },
}

/* ─── Main App ─────────────────────────────────────────────────────────── */

function App() {
  const [activeTab, setActiveTab] = useState<TabId>('intel')

  // Intel Summary
  const [intelSummary, setIntelSummary] = useState<IntelSummaryResponse | null>(null)
  const [intelLoading, setIntelLoading] = useState(false)
  const [intelError, setIntelError] = useState<string | null>(null)

  // MITRE Matrix
  const [matrix, setMatrix] = useState<MatrixResponse | null>(null)
  const [matrixLoading, setMatrixLoading] = useState(false)
  const [matrixError, setMatrixError] = useState<string | null>(null)

  // Kill Chain
  const [hostId, setHostId] = useState('')
  const [killchain, setKillchain] = useState<KillchainResponse | null>(null)
  const [killLoading, setKillLoading] = useState(false)
  const [killError, setKillError] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  // SIEM Alerts
  const [alertFeed, setAlertFeed] = useState<AlertFeedItem[]>([])
  const [sevStats, setSevStats] = useState<SeverityStats | null>(null)
  const [siemLoading, setSiemLoading] = useState(false)
  const [siemError, setSiemError] = useState<string | null>(null)
  const [alertId, setAlertId] = useState('')
  const [alertStatus, setAlertStatus] = useState<'False Positive' | 'Investigating' | 'Resolved'>('Investigating')
  const [alertMessage, setAlertMessage] = useState<string | null>(null)
  const [alertError, setAlertError] = useState<string | null>(null)

  // Heatmap
  const [heatmapData, setHeatmapData] = useState<HeatmapCountry[]>([])
  const [heatmapLoading, setHeatmapLoading] = useState(false)
  const [heatmapError, setHeatmapError] = useState<string | null>(null)
  const [hoveredCountry, setHoveredCountry] = useState<HeatmapCountry | null>(null)

  // Simulation
  const [simulating, setSimulating] = useState(false)
  const [simMessage, setSimMessage] = useState<string | null>(null)

  /* ── Data fetchers ──────────────────────────────────────────────────── */

  const fetchIntelSummary = useCallback(async () => {
    try {
      setIntelLoading(true)
      setIntelError(null)
      const res = await fetch(`${API_BASE}/intel/summary`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setIntelSummary(await res.json())
    } catch (err) {
      setIntelError((err as Error).message)
    } finally {
      setIntelLoading(false)
    }
  }, [])

  const fetchMatrix = useCallback(async () => {
    try {
      setMatrixLoading(true)
      setMatrixError(null)
      const res = await fetch(`${API_BASE}/hunt/matrix`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setMatrix(await res.json())
    } catch (err) {
      setMatrixError((err as Error).message)
    } finally {
      setMatrixLoading(false)
    }
  }, [])

  const fetchSiemData = useCallback(async () => {
    try {
      setSiemLoading(true)
      setSiemError(null)
      const [feedRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/alerts/feed`),
        fetch(`${API_BASE}/alerts/stats`),
      ])
      if (!feedRes.ok) throw new Error(`Feed HTTP ${feedRes.status}`)
      if (!statsRes.ok) throw new Error(`Stats HTTP ${statsRes.status}`)
      const feedData = await feedRes.json()
      setAlertFeed(feedData.alerts)
      setSevStats(await statsRes.json())
    } catch (err) {
      setSiemError((err as Error).message)
    } finally {
      setSiemLoading(false)
    }
  }, [])

  const fetchHeatmap = useCallback(async () => {
    try {
      setHeatmapLoading(true)
      setHeatmapError(null)
      const res = await fetch(`${API_BASE}/hunt/heatmap`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setHeatmapData(data.countries)
    } catch (err) {
      setHeatmapError((err as Error).message)
    } finally {
      setHeatmapLoading(false)
    }
  }, [])

  /* ── Tab-driven data loading ────────────────────────────────────────── */

  useEffect(() => {
    if (activeTab === 'intel') void fetchIntelSummary()
    if (activeTab === 'matrix') void fetchMatrix()
    if (activeTab === 'siem') void fetchSiemData()
    if (activeTab === 'heatmap') void fetchHeatmap()
  }, [activeTab])

  // Auto-refresh SIEM tab every 10s
  useEffect(() => {
    if (activeTab !== 'siem') return
    const id = setInterval(() => void fetchSiemData(), 10_000)
    return () => clearInterval(id)
  }, [activeTab, fetchSiemData])

  /* ── Handlers ───────────────────────────────────────────────────────── */

  async function handleKillchainLookup(e: React.FormEvent) {
    e.preventDefault()
    if (!hostId.trim()) return
    try {
      setKillLoading(true)
      setKillError(null)
      const res = await fetch(`${API_BASE}/hunt/killchain/${encodeURIComponent(hostId.trim())}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setKillchain(await res.json())
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

  async function handleSimulate() {
    try {
      setSimulating(true)
      setSimMessage(null)
      const res = await fetch(`${API_BASE}/simulate/ransomware`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setSimMessage(data.message)
      // Refresh current tab data
      if (activeTab === 'intel') void fetchIntelSummary()
      if (activeTab === 'siem') void fetchSiemData()
      if (activeTab === 'heatmap') void fetchHeatmap()
    } catch (err) {
      setSimMessage(`Error: ${(err as Error).message}`)
    } finally {
      setSimulating(false)
    }
  }

  /* ── Render ─────────────────────────────────────────────────────────── */

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Cyber Threat Hunter Pro</h1>
            <p className="text-sm text-slate-400">
              Unified CTI, MITRE ATT&amp;CK mapping, and Kill Chain analytics
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleSimulate}
              disabled={simulating}
              className="rounded-md bg-red-600 px-4 py-2 text-xs font-semibold text-white shadow-sm transition hover:bg-red-500 disabled:opacity-50"
            >
              {simulating ? '⏳ Simulating…' : '⚡ Simulate Ransomware'}
            </button>
            <span className="rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300 ring-1 ring-emerald-500/40">
              Live dashboard
            </span>
          </div>
        </div>
        {simMessage && (
          <div className="border-t border-slate-800 bg-slate-900/90 px-6 py-2">
            <p className="mx-auto max-w-7xl text-xs text-amber-300">{simMessage}</p>
          </div>
        )}
      </header>

      <main className="mx-auto max-w-7xl px-6 py-6">
        <nav className="mb-6 flex gap-1 rounded-lg bg-slate-900/70 p-1 text-sm">
          <TabButton id="intel" label="Intel Summary" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="matrix" label="MITRE Matrix" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="killchain" label="Kill Chain" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="siem" label="SIEM Alerts" activeTab={activeTab} setActiveTab={setActiveTab} />
          <TabButton id="heatmap" label="Attacker Map" activeTab={activeTab} setActiveTab={setActiveTab} />
        </nav>

        {/* ── Intel Summary ──────────────────────────────────────────── */}
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

        {/* ── MITRE Matrix ───────────────────────────────────────────── */}
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

        {/* ── Kill Chain ─────────────────────────────────────────────── */}
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
                    placeholder="e.g. VICTIM-PC-01"
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
                        🔒 Ransomware pattern detected
                      </span>
                    )}
                  </div>
                </div>

                {killchain.ransomware_suspected && killchain.ransomware_reason && (
                  <div className="rounded-lg border border-orange-500/30 bg-orange-500/5 px-4 py-3">
                    <p className="text-xs font-semibold text-orange-300">⚠ Ransomware Analysis</p>
                    <p className="mt-1 text-sm text-orange-200/80">{killchain.ransomware_reason}</p>
                  </div>
                )}

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
                    {killchain.timeline.map((ev) => {
                      const s = sevStyle(ev.severity ?? 'Low')
                      return (
                        <li key={ev.event_id} className="flex gap-3 px-4 py-3 text-sm">
                          <div className={`mt-1 h-2 w-2 flex-shrink-0 rounded-full ${s.dot}`} />
                          <div className="flex flex-1 flex-col gap-1">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <p className="font-medium text-slate-100">
                                {ev.mitre?.technique_id ?? 'Unmapped technique'}
                              </p>
                              <div className="flex items-center gap-2">
                                <span className={`rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 ${s.bg} ${s.text} ${s.ring}`}>
                                  {ev.severity ?? 'Low'}
                                </span>
                                <p className="text-xs text-slate-500">
                                  {new Date(ev.timestamp).toLocaleString()} • {ev.phase ?? 'Unknown phase'}
                                </p>
                              </div>
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
                      )
                    })}
                  </ol>
                </div>
              </div>
            )}
          </section>
        )}

        {/* ── SIEM Alerts ────────────────────────────────────────────── */}
        {activeTab === 'siem' && (
          <section className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold">SIEM Alert Dashboard</h2>
                <p className="text-sm text-slate-400">
                  Real-time alert feed with severity levels. Auto-refreshes every 10 seconds.
                </p>
              </div>
              <button
                type="button"
                onClick={() => void fetchSiemData()}
                className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
              >
                ↻ Refresh
              </button>
            </div>

            {siemLoading && !sevStats && <p className="text-sm text-slate-400">Loading SIEM data…</p>}
            {siemError && <p className="text-sm text-red-400">Error: {siemError}</p>}

            {/* Severity summary cards */}
            {sevStats && (
              <div className="grid gap-4 sm:grid-cols-4">
                {(['Critical', 'High', 'Medium', 'Low'] as const).map((level) => {
                  const s = sevStyle(level)
                  const count = sevStats[level]
                  return (
                    <div key={level} className={`rounded-xl border p-4 ${s.bg} border-slate-800`}>
                      <div className="flex items-center gap-2">
                        <div className={`h-2.5 w-2.5 rounded-full ${s.dot}`} />
                        <p className={`text-xs font-semibold uppercase tracking-wide ${s.text}`}>{level}</p>
                      </div>
                      <p className="mt-2 text-2xl font-bold text-slate-50">{count.toLocaleString()}</p>
                      <p className="text-xs text-slate-400">events</p>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Alert feed table */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
              <div className="border-b border-slate-800 px-4 py-3 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-200">Recent Alerts</h3>
                <span className="text-[10px] text-slate-500">{alertFeed.length} shown</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-left text-[10px] uppercase tracking-wider text-slate-500">
                      <th className="px-4 py-2">Severity</th>
                      <th className="px-4 py-2">Timestamp</th>
                      <th className="px-4 py-2">Host</th>
                      <th className="px-4 py-2">Action</th>
                      <th className="px-4 py-2">Technique</th>
                      <th className="px-4 py-2">Kill Chain</th>
                      <th className="px-4 py-2">Actor</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {alertFeed.length === 0 && (
                      <tr>
                        <td colSpan={7} className="px-4 py-6 text-center text-slate-400">
                          No events yet. Use the "Simulate Ransomware" button to generate data.
                        </td>
                      </tr>
                    )}
                    {alertFeed.map((a) => {
                      const s = sevStyle(a.severity)
                      return (
                        <tr key={a.event_id} className="hover:bg-slate-800/30 transition">
                          <td className="px-4 py-2">
                            <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 ${s.bg} ${s.text} ${s.ring}`}>
                              <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
                              {a.severity}
                            </span>
                          </td>
                          <td className="px-4 py-2 text-slate-300 whitespace-nowrap">
                            {new Date(a.timestamp).toLocaleString()}
                          </td>
                          <td className="px-4 py-2">
                            <span className="text-slate-100 font-medium">{a.host_id ?? '—'}</span>
                            <br />
                            <span className="text-slate-500">{a.host_ip ?? ''}</span>
                          </td>
                          <td className="px-4 py-2 text-slate-300">{a.action ?? '—'}</td>
                          <td className="px-4 py-2">
                            <span className="text-slate-100">{a.mitre_technique ?? '—'}</span>
                            {a.mitre_tactic && (
                              <span className="ml-1 text-slate-500">({a.mitre_tactic})</span>
                            )}
                          </td>
                          <td className="px-4 py-2 text-slate-300">{a.kill_chain_phase ?? '—'}</td>
                          <td className="px-4 py-2">
                            {a.threat_group ? (
                              <span className="rounded-full bg-purple-900/40 px-2 py-0.5 text-purple-200">
                                {a.threat_group}
                              </span>
                            ) : (
                              <span className="text-slate-500">—</span>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Alert status update (existing functionality) */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-slate-200">Update Alert Status</h3>
              <form
                onSubmit={handleAlertUpdate}
                className="flex flex-col gap-3 sm:flex-row sm:items-end"
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
            </div>
          </section>
        )}

        {/* ── Attacker Heatmap ───────────────────────────────────────── */}
        {activeTab === 'heatmap' && (
          <section className="space-y-6">
            <div>
              <h2 className="text-lg font-semibold">Attacker Activity Heatmap</h2>
              <p className="text-sm text-slate-400">
                Geographic distribution of attack origins. Intensity reflects event volume.
              </p>
            </div>

            {heatmapLoading && <p className="text-sm text-slate-400">Loading heatmap…</p>}
            {heatmapError && <p className="text-sm text-red-400">Error: {heatmapError}</p>}

            {heatmapData.length === 0 && !heatmapLoading && (
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-6 py-12 text-center">
                <p className="text-slate-400 text-sm">No geo-tagged events yet. Run the ransomware simulation to generate data.</p>
              </div>
            )}

            {heatmapData.length > 0 && (
              <>
                {/* SVG World Map */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 relative">
                  <svg viewBox="0 0 700 300" className="w-full h-auto" style={{ minHeight: '300px' }}>
                    {/* Ocean background */}
                    <rect width="700" height="300" fill="#0f172a" rx="8" />

                    {/* Grid lines */}
                    {[0, 100, 200, 300, 400, 500, 600, 700].map((x) => (
                      <line key={`vg-${x}`} x1={x} y1="0" x2={x} y2="300" stroke="#1e293b" strokeWidth="0.5" />
                    ))}
                    {[0, 75, 150, 225, 300].map((y) => (
                      <line key={`hg-${y}`} x1="0" y1={y} x2="700" y2={y} stroke="#1e293b" strokeWidth="0.5" />
                    ))}

                    {/* Continent outlines */}
                    {Object.entries(COUNTRY_PATHS).map(([code, info]) => {
                      const country = heatmapData.find((c) => c.country_code === code)
                      const maxCount = Math.max(...heatmapData.map((c) => c.count), 1)
                      const intensity = country ? country.count / maxCount : 0

                      let fill = '#1e293b'
                      if (intensity > 0.7) fill = '#dc2626'
                      else if (intensity > 0.4) fill = '#ea580c'
                      else if (intensity > 0.15) fill = '#d97706'
                      else if (intensity > 0) fill = '#854d0e'

                      return (
                        <g key={code}>
                          <path
                            d={info.d}
                            fill={fill}
                            stroke="#334155"
                            strokeWidth="0.8"
                            className="transition-all duration-300 cursor-pointer"
                            onMouseEnter={() => country && setHoveredCountry(country)}
                            onMouseLeave={() => setHoveredCountry(null)}
                            opacity={intensity > 0 ? 0.9 : 0.4}
                          />
                          {/* Pulse dot for active countries */}
                          {country && (
                            <>
                              <circle cx={info.cx} cy={info.cy} r={Math.max(3, Math.min(10, intensity * 12))} fill={fill} opacity="0.4">
                                <animate attributeName="r" values={`${Math.max(3, intensity * 8)};${Math.max(6, intensity * 14)};${Math.max(3, intensity * 8)}`} dur="2s" repeatCount="indefinite" />
                                <animate attributeName="opacity" values="0.4;0.1;0.4" dur="2s" repeatCount="indefinite" />
                              </circle>
                              <circle
                                cx={info.cx} cy={info.cy}
                                r={Math.max(2, Math.min(6, intensity * 8))}
                                fill={fill}
                                stroke="#fff"
                                strokeWidth="0.5"
                                className="cursor-pointer"
                                onMouseEnter={() => setHoveredCountry(country)}
                                onMouseLeave={() => setHoveredCountry(null)}
                              />
                            </>
                          )}
                        </g>
                      )
                    })}
                  </svg>

                  {/* Tooltip */}
                  {hoveredCountry && (
                    <div className="absolute top-4 right-4 rounded-lg border border-slate-700 bg-slate-900/95 px-4 py-3 shadow-xl backdrop-blur">
                      <p className="text-sm font-semibold text-slate-100">{hoveredCountry.country_name}</p>
                      <p className="text-xs text-slate-400">Code: {hoveredCountry.country_code}</p>
                      <p className="mt-1 text-lg font-bold text-red-400">{hoveredCountry.count.toLocaleString()}</p>
                      <p className="text-[10px] text-slate-500">attack events</p>
                    </div>
                  )}
                </div>

                {/* Country table */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60">
                  <div className="border-b border-slate-800 px-4 py-3">
                    <h3 className="text-sm font-semibold text-slate-200">Attack Origins by Country</h3>
                  </div>
                  <div className="divide-y divide-slate-800">
                    {heatmapData.map((c) => {
                      const maxCount = Math.max(...heatmapData.map((x) => x.count), 1)
                      const pct = (c.count / maxCount) * 100
                      return (
                        <div key={c.country_code} className="flex items-center gap-4 px-4 py-3">
                          <div className="w-8 text-center">
                            <span className="text-sm">{countryFlag(c.country_code)}</span>
                          </div>
                          <div className="flex-1">
                            <p className="text-sm font-medium text-slate-100">{c.country_name}</p>
                            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                              <div
                                className="h-full rounded-full bg-gradient-to-r from-orange-500 to-red-500 transition-all duration-500"
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                          <span className="rounded-full bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-300 ring-1 ring-red-500/40">
                            {c.count.toLocaleString()}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              </>
            )}
          </section>
        )}
      </main>
    </div>
  )
}

/* ─── Utility: country code → flag emoji ───────────────────────────────── */

function countryFlag(code: string): string {
  const codePoints = code
    .toUpperCase()
    .split('')
    .map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)
  return String.fromCodePoint(...codePoints)
}

/* ─── Sub-components ───────────────────────────────────────────────────── */

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
