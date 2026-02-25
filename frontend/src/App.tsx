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
  High: { bg: 'bg-orange-500/10', text: 'text-orange-300', ring: 'ring-orange-500/50', dot: 'bg-orange-400' },
  Medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-300', ring: 'ring-yellow-500/50', dot: 'bg-yellow-400' },
  Low: { bg: 'bg-slate-500/10', text: 'text-slate-300', ring: 'ring-slate-500/50', dot: 'bg-slate-400' },
}

function sevStyle(sev: string) {
  return SEV_COLORS[sev] ?? SEV_COLORS.Low
}

/* ─── World map: continent SVG paths + country centers ────────────────── */
/* Equirectangular projection – viewBox 0 0 1000 500 */
/* x = (lon + 180) / 360 * 1000,  y = (90 - lat) / 180 * 500 */

const CONTINENT_PATHS = [
  // North America
  'M38,69 L48,97 72,103 111,83 153,114 172,158 194,186 233,203 250,211 267,214 275,228 278,214 278,181 292,153 306,133 319,119 342,103 347,89 319,78 306,56 264,42 222,42 139,53 125,58Z',
  // Greenland
  'M303,33 L333,19 361,22 372,33 367,50 342,58 319,53Z',
  // South America
  'M222,222 L236,211 264,219 292,222 319,214 350,217 394,250 403,264 394,292 381,319 356,344 328,369 311,389 292,392 283,378 289,356 292,342 278,314 264,283 244,256 228,242Z',
  // Europe
  'M444,58 L458,53 472,58 486,56 497,61 514,64 525,56 542,50 558,50 578,56 592,64 583,78 581,92 572,103 569,119 564,128 556,131 544,139 531,142 522,133 514,125 508,117 497,114 489,119 486,128 478,131 472,136 467,131 458,131 453,122 453,114 444,106 439,97 439,89 433,81 433,72 439,64Z',
  // Africa
  'M453,147 L464,142 481,142 500,150 514,153 528,156 539,161 547,172 556,186 561,200 567,214 569,228 564,244 558,261 553,278 544,292 536,303 528,314 519,328 508,336 497,342 486,344 478,339 467,331 458,325 450,319 439,311 431,300 425,289 419,281 414,267 411,253 408,242 411,228 414,217 419,206 425,194 431,183 439,172 444,158Z',
  // Asia mainland
  'M564,128 L575,119 583,108 592,97 600,83 611,75 625,69 636,64 650,58 669,56 689,56 706,58 722,64 742,69 758,72 775,69 789,64 806,58 822,53 836,50 853,47 869,47 881,50 892,56 900,64 908,72 917,78 925,86 928,97 925,106 917,117 908,125 903,136 903,147 897,158 889,164 881,172 872,178 864,183 856,186 847,189 836,192 825,194 808,194 794,194 783,197 772,200 764,203 753,208 747,214 742,219 736,222 725,222 714,219 706,214 700,206 694,200 689,194 681,189 672,183 661,175 650,167 644,158 636,147 625,139 614,136 603,133 592,131 578,131Z',
  // India
  'M636,147 L642,158 650,167 658,178 667,186 675,192 681,200 686,211 689,222 686,233 681,242 675,250 667,253 658,250 650,244 647,236 644,228 642,219 639,208 636,197 631,183 628,172 625,161 628,153Z',
  // SE Asia peninsula
  'M700,206 L706,214 711,222 714,228 717,236 714,244 711,250 706,256 700,253 697,247 694,239 694,231 694,222 697,214Z',
  // Japan
  'M856,103 L861,97 867,92 872,97 875,106 872,117 867,125 861,119 858,111Z',
  // Indonesian archipelago
  'M731,264 L744,258 758,256 772,258 786,261 797,264 808,267 803,275 792,278 778,278 764,275 750,272 739,269Z',
  // Australia
  'M808,292 L822,283 839,278 858,278 878,281 897,286 911,292 919,303 922,319 917,336 906,350 892,358 875,361 858,361 842,356 828,347 817,336 811,322 808,308Z',
  // UK + Ireland
  'M442,83 L447,78 453,75 456,81 453,89 447,92 442,89Z',
  // New Zealand
  'M933,356 L936,347 939,342 942,350 939,361 936,364Z',
]

// Country center coordinates (projected) for markers & arcs
const COUNTRY_CENTERS: Record<string, { x: number; y: number; name: string }> = {
  US: { x: 153, y: 119, name: 'United States' },
  CA: { x: 175, y: 69, name: 'Canada' },
  MX: { x: 194, y: 175, name: 'Mexico' },
  BR: { x: 328, y: 308, name: 'Brazil' },
  GB: { x: 447, y: 83, name: 'United Kingdom' },
  FR: { x: 478, y: 122, name: 'France' },
  DE: { x: 492, y: 103, name: 'Germany' },
  UA: { x: 556, y: 92, name: 'Ukraine' },
  RU: { x: 756, y: 64, name: 'Russia' },
  CN: { x: 792, y: 153, name: 'China' },
  IN: { x: 658, y: 200, name: 'India' },
  JP: { x: 864, y: 108, name: 'Japan' },
  KR: { x: 847, y: 131, name: 'South Korea' },
  KP: { x: 842, y: 119, name: 'North Korea' },
  IR: { x: 625, y: 150, name: 'Iran' },
  SA: { x: 586, y: 172, name: 'Saudi Arabia' },
  AU: { x: 872, y: 322, name: 'Australia' },
  ID: { x: 772, y: 267, name: 'Indonesia' },
  ZA: { x: 492, y: 328, name: 'South Africa' },
  NG: { x: 458, y: 225, name: 'Nigeria' },
  NL: { x: 481, y: 94, name: 'Netherlands' },
  CH: { x: 486, y: 111, name: 'Switzerland' },
  KE: { x: 544, y: 253, name: 'Kenya' },
  SG: { x: 767, y: 247, name: 'Singapore' },
  AT: { x: 497, y: 106, name: 'Austria' },
  PK: { x: 636, y: 164, name: 'Pakistan' },
  TN: { x: 458, y: 158, name: 'Tunisia' },
  RO: { x: 528, y: 100, name: 'Romania' },
  HK: { x: 806, y: 175, name: 'Hong Kong' },
}

// Our network target (center of our org for attack arcs)
const TARGET_POS = { x: 153, y: 119 } // US-based org

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
    if (activeTab === 'heatmap') { void fetchHeatmap(); void fetchSiemData() }
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
                      className={`rounded-full px-3 py-1 text-xs font-semibold ring-1 ${killchain.is_critical
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

        {/* ── Attacker Heatmap — Check Point-style ─────────────────── */}
        {activeTab === 'heatmap' && (
          <section>
            {heatmapLoading && !heatmapData.length && <p className="text-sm text-slate-400 py-4">Loading threat map…</p>}
            {heatmapError && <p className="text-sm text-red-400 py-4">Error: {heatmapError}</p>}

            {/* Header */}
            <div className="text-center mb-4">
              <h2 className="text-xl font-bold tracking-wider text-slate-100">LIVE CYBER THREAT MAP</h2>
              <p className="text-sm font-semibold text-rose-400 mt-1">
                {heatmapData.reduce((s, c) => s + c.count, 0).toLocaleString()} ATTACKS TRACKED
              </p>
            </div>

            {/* 3 column layout: Feed | Map | Stats */}
            <div className="grid gap-4" style={{ gridTemplateColumns: '260px 1fr 230px' }}>

              {/* ─ Left panel: Recent Attacks ─ */}
              <div className="rounded-xl border border-slate-800 bg-slate-900/80 flex flex-col overflow-hidden">
                <div className="border-b border-slate-800 px-3 py-2">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-rose-400">Recent Attacks</p>
                </div>
                <div className="flex-1 overflow-y-auto max-h-[420px] divide-y divide-slate-800/50">
                  {alertFeed.slice(0, 20).map((a, i) => {
                    const s = sevStyle(a.severity)
                    return (
                      <div key={a.event_id ?? i} className="px-3 py-2 hover:bg-slate-800/40 transition">
                        <div className="flex items-center gap-1.5">
                          <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
                          <p className="text-[11px] font-semibold text-slate-100 truncate">{a.action ?? 'unknown'}</p>
                        </div>
                        <p className="text-[10px] text-slate-500 mt-0.5 truncate">
                          {new Date(a.timestamp).toLocaleTimeString()}{' '}
                          {a.host_id ?? '—'}
                          {a.threat_group ? ` → ${a.threat_group}` : ''}
                        </p>
                      </div>
                    )
                  })}
                  {alertFeed.length === 0 && (
                    <p className="px-3 py-6 text-[10px] text-slate-500 text-center">No recent alerts</p>
                  )}
                </div>
              </div>

              {/* ─ Center: World Map SVG ─ */}
              <div className="rounded-xl border border-slate-800 bg-[#0a0e1a] relative overflow-hidden" style={{ minHeight: '420px' }}>
                <svg viewBox="0 0 1000 500" className="w-full h-full" preserveAspectRatio="xMidYMid meet">
                  <defs>
                    {/* Dot pattern for continents */}
                    <pattern id="landDots" x="0" y="0" width="10" height="10" patternUnits="userSpaceOnUse">
                      <circle cx="5" cy="5" r="1.2" fill="rgba(148,163,184,0.35)" />
                    </pattern>
                    {/* Glow filter for attack markers */}
                    <filter id="attackGlow" x="-100%" y="-100%" width="300%" height="300%">
                      <feGaussianBlur stdDeviation="6" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                    <filter id="arcGlow" x="-50%" y="-50%" width="200%" height="200%">
                      <feGaussianBlur stdDeviation="2" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                    {/* Subtle grid pattern for ocean */}
                    <pattern id="oceanGrid" x="0" y="0" width="20" height="20" patternUnits="userSpaceOnUse">
                      <circle cx="10" cy="10" r="0.4" fill="rgba(51,65,85,0.3)" />
                    </pattern>
                  </defs>

                  {/* Ocean background with subtle dot grid */}
                  <rect width="1000" height="500" fill="#0a0e1a" />
                  <rect width="1000" height="500" fill="url(#oceanGrid)" />

                  {/* Continents filled with dot pattern */}
                  {CONTINENT_PATHS.map((d, i) => (
                    <path key={i} d={d} fill="url(#landDots)" stroke="rgba(100,116,139,0.15)" strokeWidth="0.5" />
                  ))}

                  {/* Attack arcs from each country to target */}
                  {heatmapData.map((c) => {
                    const src = COUNTRY_CENTERS[c.country_code]
                    if (!src) return null
                    const tgt = TARGET_POS
                    // Skip if source is the target
                    if (Math.abs(src.x - tgt.x) < 20 && Math.abs(src.y - tgt.y) < 20) return null
                    const maxCount = Math.max(...heatmapData.map((x) => x.count), 1)
                    const intensity = c.count / maxCount
                    // Quadratic bezier arc control point (curve upward)
                    const mx = (src.x + tgt.x) / 2
                    const my = Math.min(src.y, tgt.y) - 40 - intensity * 60
                    const arcPath = `M${src.x},${src.y} Q${mx},${my} ${tgt.x},${tgt.y}`
                    const dur = (2 + Math.random() * 3).toFixed(1)
                    return (
                      <g key={`arc-${c.country_code}`} filter="url(#arcGlow)">
                        {/* Faint trail */}
                        <path d={arcPath} fill="none" stroke="rgba(251,146,60,0.15)" strokeWidth="1" />
                        {/* Animated dot along path */}
                        <circle r="3" fill="#fb923c">
                          <animateMotion dur={`${dur}s`} repeatCount="indefinite" path={arcPath} />
                          <animate attributeName="opacity" values="1;0.3;1" dur={`${dur}s`} repeatCount="indefinite" />
                        </circle>
                        {/* Second dot staggered */}
                        <circle r="2" fill="#fbbf24">
                          <animateMotion dur={`${dur}s`} repeatCount="indefinite" path={arcPath} begin={`${(parseFloat(dur) / 2).toFixed(1)}s`} />
                          <animate attributeName="opacity" values="0.8;0.2;0.8" dur={`${dur}s`} repeatCount="indefinite" begin={`${(parseFloat(dur) / 2).toFixed(1)}s`} />
                        </circle>
                      </g>
                    )
                  })}

                  {/* Country attack markers */}
                  {heatmapData.map((c) => {
                    const pos = COUNTRY_CENTERS[c.country_code]
                    if (!pos) return null
                    const maxCount = Math.max(...heatmapData.map((x) => x.count), 1)
                    const intensity = c.count / maxCount
                    const r = 3 + intensity * 8
                    const color = intensity > 0.6 ? '#ef4444' : intensity > 0.3 ? '#f97316' : '#eab308'
                    return (
                      <g
                        key={`marker-${c.country_code}`}
                        filter="url(#attackGlow)"
                        className="cursor-pointer"
                        onMouseEnter={() => setHoveredCountry(c)}
                        onMouseLeave={() => setHoveredCountry(null)}
                      >
                        {/* Pulse ring */}
                        <circle cx={pos.x} cy={pos.y} r={r} fill="none" stroke={color} strokeWidth="0.8" opacity="0.5">
                          <animate attributeName="r" values={`${r};${r + 8};${r}`} dur="2.5s" repeatCount="indefinite" />
                          <animate attributeName="opacity" values="0.5;0;0.5" dur="2.5s" repeatCount="indefinite" />
                        </circle>
                        {/* Solid center */}
                        <circle cx={pos.x} cy={pos.y} r={Math.max(2.5, r * 0.5)} fill={color} opacity="0.9" />
                        {/* Country label */}
                        <text x={pos.x} y={pos.y - r - 4} textAnchor="middle" fill="#e2e8f0" fontSize="8" fontWeight="500" opacity="0.8">
                          {c.country_code}
                        </text>
                      </g>
                    )
                  })}

                  {/* Target marker (our network) */}
                  <g filter="url(#attackGlow)">
                    <circle cx={TARGET_POS.x} cy={TARGET_POS.y} r="6" fill="none" stroke="#22d3ee" strokeWidth="1.5" opacity="0.7">
                      <animate attributeName="r" values="6;14;6" dur="3s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.7;0;0.7" dur="3s" repeatCount="indefinite" />
                    </circle>
                    <circle cx={TARGET_POS.x} cy={TARGET_POS.y} r="4" fill="#22d3ee" opacity="0.9" />
                    <text x={TARGET_POS.x} y={TARGET_POS.y - 12} textAnchor="middle" fill="#22d3ee" fontSize="7" fontWeight="600">TARGET</text>
                  </g>
                </svg>

                {/* Tooltip overlay */}
                {hoveredCountry && (
                  <div className="absolute top-3 left-3 rounded-lg border border-rose-500/30 bg-slate-950/95 px-4 py-3 shadow-2xl backdrop-blur-sm">
                    <p className="text-sm font-bold text-slate-100">{hoveredCountry.country_name}</p>
                    <p className="mt-1 text-xl font-black text-rose-400">{hoveredCountry.count.toLocaleString()}</p>
                    <p className="text-[10px] text-slate-500">attack events</p>
                  </div>
                )}

                {/* Legend */}
                <div className="absolute bottom-3 left-1/2 -translate-x-1/2 flex items-center gap-5 rounded-full bg-slate-950/80 px-5 py-1.5 backdrop-blur-sm border border-slate-800">
                  <span className="flex items-center gap-1.5 text-[10px] text-slate-300">
                    <span className="h-2 w-2 rounded-full bg-red-500" /> Critical
                  </span>
                  <span className="flex items-center gap-1.5 text-[10px] text-slate-300">
                    <span className="h-2 w-2 rounded-full bg-orange-500" /> High
                  </span>
                  <span className="flex items-center gap-1.5 text-[10px] text-slate-300">
                    <span className="h-2 w-2 rounded-full bg-yellow-500" /> Medium
                  </span>
                  <span className="flex items-center gap-1.5 text-[10px] text-slate-300">
                    <span className="h-2 w-2 rounded-full bg-cyan-400" /> Target
                  </span>
                </div>
              </div>

              {/* ─ Right panel: Stats ─ */}
              <div className="space-y-4">
                {/* Top attacker countries */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
                  <div className="border-b border-slate-800 px-3 py-2">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-rose-400">Top Attacker Countries</p>
                  </div>
                  <div className="divide-y divide-slate-800/50">
                    {[...heatmapData].sort((a, b) => b.count - a.count).slice(0, 8).map((c) => (
                      <div key={c.country_code} className="flex items-center gap-2 px-3 py-2">
                        <span className="text-xs">{countryFlag(c.country_code)}</span>
                        <span className="flex-1 text-[11px] text-slate-200 truncate">{c.country_name}</span>
                        <span className="text-[10px] font-bold text-rose-300">{c.count.toLocaleString()}</span>
                      </div>
                    ))}
                    {heatmapData.length === 0 && (
                      <p className="px-3 py-4 text-[10px] text-slate-500 text-center">No data</p>
                    )}
                  </div>
                </div>

                {/* Top attack types (from alert feed) */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
                  <div className="border-b border-slate-800 px-3 py-2">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-rose-400">Top Attack Types</p>
                  </div>
                  <div className="divide-y divide-slate-800/50">
                    {(() => {
                      const counts: Record<string, number> = {}
                      alertFeed.forEach((a) => {
                        const k = a.action ?? 'unknown'
                        counts[k] = (counts[k] || 0) + 1
                      })
                      return Object.entries(counts)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 6)
                        .map(([action, count]) => (
                          <div key={action} className="flex items-center gap-2 px-3 py-2">
                            <span className="h-1.5 w-1.5 rounded-full bg-orange-400" />
                            <span className="flex-1 text-[11px] text-slate-200 truncate">{action.replace(/_/g, ' ')}</span>
                            <span className="text-[10px] font-bold text-orange-300">{count}</span>
                          </div>
                        ))
                    })()}
                  </div>
                </div>

                {/* Top threat groups */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
                  <div className="border-b border-slate-800 px-3 py-2">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-rose-400">Top Threat Groups</p>
                  </div>
                  <div className="divide-y divide-slate-800/50">
                    {(() => {
                      const counts: Record<string, number> = {}
                      alertFeed.forEach((a) => {
                        if (a.threat_group) counts[a.threat_group] = (counts[a.threat_group] || 0) + 1
                      })
                      return Object.entries(counts)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 6)
                        .map(([group, count]) => (
                          <div key={group} className="flex items-center gap-2 px-3 py-2">
                            <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
                            <span className="flex-1 text-[11px] text-slate-200 truncate">{group}</span>
                            <span className="text-[10px] font-bold text-purple-300">{count}</span>
                          </div>
                        ))
                    })()}
                  </div>
                </div>
              </div>
            </div>
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
      className={`flex-1 rounded-md px-3 py-2 text-xs font-medium transition ${isActive
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
