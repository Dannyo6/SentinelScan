import React, { useState, useEffect, useRef, useCallback } from 'react'
import {
  Shield,
  Terminal,
  Activity,
  Cpu,
  Globe,
  CheckCircle2,
  Download,
  RefreshCw,
  Play,
  Layers,
  Radio,
  Server,
  Zap
} from 'lucide-react'
import ScanTerminal from './components/ScanTerminal/ScanTerminal.jsx'
import MagicBento from './components/MagicBento/MagicBento.jsx'
import GooeyNav from './components/GooeyNav/GooeyNav.jsx'
import SpecularButton from './components/SpecularButton/SpecularButton.jsx'

// Worker registry metadata for the 11 diagnostic workers
const WORKER_REGISTRY = [
  { id: 'dns_lookup', name: 'DNS Lookup', category: 'Topology', desc: 'A/AAAA/MX/TXT/NS resolution & DNSSEC verification' },
  { id: 'reverse_dns_lookup', name: 'Reverse DNS', category: 'Topology', desc: 'PTR record verification and hostname correlation' },
  { id: 'whois_lookup', name: 'WHOIS Lookup', category: 'Reconnaissance', desc: 'Registrar, creation, and domain ownership records' },
  { id: 'port_scan', name: 'Port Availability', category: 'Reconnaissance', desc: 'Non-intrusive TCP port state & service identification' },
  { id: 'ssl_check', name: 'SSL/TLS Inspection', category: 'Web Surface', desc: 'X.509 certificate validity, cipher suites, & expiry' },
  { id: 'http_headers', name: 'Security Headers', category: 'Web Surface', desc: 'HSTS, CSP, X-Frame-Options, & policy auditing' },
  { id: 'cookie_analysis', name: 'Cookie Security', category: 'Web Surface', desc: 'Secure, HttpOnly, and SameSite attribute verification' },
  { id: 'robots_txt_parse', name: 'robots.txt Parser', category: 'Exposure', desc: 'Crawl directives & sensitive endpoint exposure checks' },
  { id: 'sitemap_parse', name: 'Sitemap Parser', category: 'Exposure', desc: 'sitemap.xml parsing & structural endpoint enumeration' },
  { id: 'ddos_resilience_check', name: 'DDoS Resilience', category: 'Resilience', desc: 'Passive CDN, WAF, and rate-limiting resilience analysis' },
  { id: 'calculate_cvss', name: 'CVSS v3.1 Scoring', category: 'Scoring', desc: 'Quantitative severity calculation & risk vectorization' }
]

const DEMO_EVENTS = [
  { tool_name: 'dns_lookup', phase: 'selected', reasoning: 'Resolving target infrastructure and DNS zone configuration.' },
  { tool_name: 'dns_lookup', phase: 'completed', worker_status: 'COMPLETED', summary: 'Found 2 A records, 4 MX records, SPF configured, DNSSEC active.' },
  { tool_name: 'reverse_dns_lookup', phase: 'selected', reasoning: 'Correlating IP address to reverse PTR hostname.' },
  { tool_name: 'reverse_dns_lookup', phase: 'completed', worker_status: 'COMPLETED', summary: 'PTR record correctly aligned with root nameserver domain.' },
  { tool_name: 'whois_lookup', phase: 'selected', reasoning: 'Checking domain registration and expiration status.' },
  { tool_name: 'whois_lookup', phase: 'completed', worker_status: 'COMPLETED', summary: 'Domain registered via Cloudflare, renewal valid through 2028.' },
  { tool_name: 'ssl_check', phase: 'selected', reasoning: 'Auditing SSL/TLS certificate validity, cipher suites, and protocol version.' },
  { tool_name: 'ssl_check', phase: 'completed', worker_status: 'COMPLETED', summary: 'TLS 1.3 enforced. Valid wildcard cert, 280 days remaining, Grade A+.' },
  { tool_name: 'http_headers', phase: 'selected', reasoning: 'Verifying strict transport security and browser defense headers.' },
  { tool_name: 'http_headers', phase: 'completed', worker_status: 'COMPLETED', summary: 'HSTS max-age=31536000 with preload; CSP and X-Frame-Options present.' },
  { tool_name: 'cookie_analysis', phase: 'selected', reasoning: 'Inspecting session cookie flags and tracking tokens.' },
  { tool_name: 'cookie_analysis', phase: 'completed', worker_status: 'COMPLETED', summary: 'All cookies enforce HttpOnly, Secure, and SameSite=Strict.' },
  { tool_name: 'robots_txt_parse', phase: 'selected', reasoning: 'Analyzing crawl directives for unintentional administrative leaks.' },
  { tool_name: 'robots_txt_parse', phase: 'completed', worker_status: 'COMPLETED', summary: 'Clean robots.txt found; no sensitive admin paths disclosed.' },
  { tool_name: 'sitemap_parse', phase: 'selected', reasoning: 'Mapping public attack surface from XML sitemap index.' },
  { tool_name: 'sitemap_parse', phase: 'completed', worker_status: 'COMPLETED', summary: 'Sitemap indexed 48 canonical endpoints with valid HTTPS URIs.' },
  { tool_name: 'port_scan', phase: 'selected', reasoning: 'Performing non-intrusive port availability audit on core services.' },
  { tool_name: 'port_scan', phase: 'completed', worker_status: 'COMPLETED', summary: 'Only ports 80/tcp (HTTP redirect) and 443/tcp (HTTPS) accessible.' },
  { tool_name: 'ddos_resilience_check', phase: 'selected', reasoning: 'Evaluating edge CDN caching and rate-limiting posture.' },
  { tool_name: 'ddos_resilience_check', phase: 'completed', worker_status: 'COMPLETED', summary: 'Cloudflare Anycast edge detected, WAF challenges active.' },
  { tool_name: 'calculate_cvss', phase: 'selected', reasoning: 'Synthesizing worker findings into CVSS v3.1 quantitative severity vectors.' },
  { tool_name: 'calculate_cvss', phase: 'completed', worker_status: 'COMPLETED', summary: 'Aggregate CVSS Score: 1.2 (Low Risk). No high-severity vulnerabilities.' }
]

export default function App() {
  const [activeTab, setActiveTab] = useState('console')
  const [target, setTarget] = useState('https://example.com')
  const [scanId, setScanId] = useState('scan_demo_live')
  const [scanStatus, setScanStatus] = useState('IDLE')
  const [isScanning, setIsScanning] = useState(false)
  const [statusMessage, setStatusMessage] = useState('Platform ready for audit execution.')
  const [backendConnected, setBackendConnected] = useState(false)
  const [completedWorkers, setCompletedWorkers] = useState({})
  const [activeStage, setActiveStage] = useState('Standby')
  const [stats, setStats] = useState({
    workersDispatched: 0,
    findingsCount: 0,
    cvssScore: '0.0',
    securityGrade: 'A+'
  })

  const pollIntervalRef = useRef(null)

  // Verify backend connectivity on mount
  useEffect(() => {
    let isMounted = true
    const checkBackend = async () => {
      try {
        const res = await fetch('/api/v1/scans', { method: 'GET' })
        if (res.ok && isMounted) {
          setBackendConnected(true)
          setStatusMessage('Connected to Flask backend telemetry service.')
        }
      } catch {
        if (isMounted) {
          setBackendConnected(false)
          setStatusMessage('Operating in client preview mode. Flask backend offline.')
        }
      }
    }
    checkBackend()
    return () => {
      isMounted = false
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current)
    }
  }, [])

  // Telemetry emission helper
  const emitTelemetryEvent = useCallback(async (eventType, data = {}) => {
    try {
      await fetch('/api/v1/telemetry', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          batch: [
            {
              event: eventType,
              timestamp: new Date().toISOString(),
              target,
              scan_id: scanId,
              ...data
            }
          ]
        })
      })
    } catch {
      // Non-blocking telemetry
    }
  }, [target, scanId])

  // Initiate scan against Flask backend or fallback simulation
  const handleStartScan = async () => {
    if (!target.trim()) return
    setIsScanning(true)
    setScanStatus('IN_PROGRESS')
    setActiveStage('Initializing Workers')
    setCompletedWorkers({})
    setStatusMessage(`Initiating security audit against ${target}...`)

    emitTelemetryEvent('scan_initiated', { target })

    try {
      const response = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() })
      })

      if (response.ok) {
        const data = await response.json()
        const newScanId = data.scan_id || `scan_${Date.now()}`
        setScanId(newScanId)
        setBackendConnected(true)
        setStatusMessage(`Scan ${newScanId} active. Polling telemetry stream...`)

        // Start polling real backend
        startPolling(newScanId)
        return
      }
    } catch (err) {
      console.warn('Backend not responding to POST /api/v1/scans, executing local client demo simulation:', err)
    }

    // Fallback: Run realistic client simulation so ScanTerminal & Bento cards update live
    runClientSimulation()
  }

  const startPolling = (id) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current)

    pollIntervalRef.current = setInterval(async () => {
      try {
        const res = await fetch(`/api/v1/scans/${id}`)
        if (!res.ok) return

        const scanData = await res.json()
        setScanStatus(scanData.status || 'IN_PROGRESS')

        // Dispatch event to ScanTerminal component
        window.dispatchEvent(new CustomEvent('sentinelscan:scan-update', { detail: scanData }))

        // Update worker status map
        if (scanData.events) {
          const completed = {}
          scanData.events.forEach(evt => {
            if (evt.phase === 'completed' && evt.tool_name) {
              completed[evt.tool_name] = evt.worker_status || 'COMPLETED'
            }
          })
          setCompletedWorkers(completed)
          setStats(prev => ({
            ...prev,
            workersDispatched: Object.keys(completed).length
          }))
        }

        if (scanData.status === 'COMPLETED' || scanData.status === 'FAILED') {
          clearInterval(pollIntervalRef.current)
          setIsScanning(false)
          setStatusMessage(scanData.status === 'COMPLETED' ? 'Audit scan successfully completed.' : 'Audit scan halted with errors.')
          setActiveStage('Audit Finalized')
          emitTelemetryEvent('scan_completed', { scan_id: id, status: scanData.status })
        }
      } catch (err) {
        console.error('Error polling scan status:', err)
      }
    }, 1500)
  }

  // Client demonstration simulation with realistic staggered telemetry
  const runClientSimulation = () => {
    const demoId = `scan_${Date.now().toString(36)}`
    setScanId(demoId)

    const accumulatedEvents = []
    let step = 0

    // Initial update
    window.dispatchEvent(new CustomEvent('sentinelscan:scan-update', {
      detail: {
        scan_id: demoId,
        target,
        status: 'IN_PROGRESS',
        events: []
      }
    }))

    const timer = setInterval(() => {
      if (step >= DEMO_EVENTS.length) {
        clearInterval(timer)
        setIsScanning(false)
        setScanStatus('COMPLETED')
        setActiveStage('Audit Complete')
        setStatusMessage('Demonstration audit completed. 11 workers dispatched.')
        setStats({
          workersDispatched: 11,
          findingsCount: 3,
          cvssScore: '1.2',
          securityGrade: 'A'
        })

        window.dispatchEvent(new CustomEvent('sentinelscan:scan-update', {
          detail: {
            scan_id: demoId,
            target,
            status: 'COMPLETED',
            events: accumulatedEvents
          }
        }))
        return
      }

      const evt = DEMO_EVENTS[step]
      accumulatedEvents.push(evt)

      if (evt.phase === 'completed') {
        setCompletedWorkers(prev => ({ ...prev, [evt.tool_name]: 'COMPLETED' }))
      }
      setActiveStage(evt.tool_name.replace(/_/g, ' ').toUpperCase())

      window.dispatchEvent(new CustomEvent('sentinelscan:scan-update', {
        detail: {
          scan_id: demoId,
          target,
          status: 'IN_PROGRESS',
          events: [...accumulatedEvents]
        }
      }))

      setStats(prev => ({
        ...prev,
        workersDispatched: Math.min(11, Math.floor(step / 2) + 1)
      }))

      step++
    }, 750)
  }

  const exportReportJson = async () => {
    try {
      const res = await fetch(`/api/v1/reports/${scanId}/json`)
      if (res.ok) {
        const blob = await res.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `sentinelscan_audit_${scanId}.json`
        a.click()
        return
      }
    } catch {
      // Fallback export of current client state
    }

    const reportData = {
      platform: 'SentinelScan Autonomous Web Security Auditing & Compliance Telemetry Platform',
      version: '2.4.0',
      timestamp: new Date().toISOString(),
      scan_id: scanId,
      target,
      status: scanStatus,
      statistics: stats,
      completedWorkers,
      workerRegistry: WORKER_REGISTRY.map(w => ({
        ...w,
        status: completedWorkers[w.id] || 'STANDBY'
      }))
    }
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(reportData, null, 2))
    const a = document.createElement('a')
    a.href = dataStr
    a.download = `sentinelscan_audit_${scanId}.json`
    a.click()
  }

  const navItems = [
    { label: 'Audit Console', href: '#console', onClick: () => setActiveTab('console') },
    { label: 'Compliance Bento', href: '#bento', onClick: () => setActiveTab('bento') },
    { label: 'Worker Diagnostics', href: '#workers', onClick: () => setActiveTab('workers') },
    { label: 'System Architecture', href: '#arch', onClick: () => setActiveTab('arch') }
  ]

  const complianceCards = [
    {
      label: 'Cryptographic Hygiene',
      title: 'SSL / TLS Verification',
      description: 'Enforces TLS 1.3/1.2 forward secrecy, OCSP stapling, SHA-256 certificate chains, and HSTS preload policies.'
    },
    {
      label: 'Network Topology',
      title: 'DNS & Zone Records',
      description: 'Resolves A/AAAA records, detects subdomains, confirms MX email routing, and audits DNSSEC validation.'
    },
    {
      label: 'Browser Defenses',
      title: 'HTTP Security Headers',
      description: 'Validates Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.'
    },
    {
      label: 'Identity & State',
      title: 'Cookie Policy Analysis',
      description: 'Evaluates Secure, HttpOnly, and SameSite attributes to eliminate session hijacking and CSRF vectors.'
    },
    {
      label: 'Surface Mapping',
      title: 'Crawl & Sitemap Parser',
      description: 'Inspects robots.txt directives and XML sitemaps to detect unintended administrative endpoint leaks.'
    },
    {
      label: 'Quantitative Scoring',
      title: 'CVSS v3.1 Calculator',
      description: 'Applies mathematical base metrics to worker discoveries to yield objective, reproducible severity scorecards.'
    }
  ]

  return (
    <div className="min-h-screen bg-[#07090E] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background Cyber Grid */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#1f293708_1px,transparent_1px),linear-gradient(to_bottom,#1f293708_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

      {/* Top Header */}
      <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#07090E]/90 backdrop-blur-md px-6 py-3.5">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Shield className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-wider text-white">SENTINELSCAN</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  v2.4 TELEMETRY
                </span>
              </div>
              <p className="text-xs text-slate-400">Autonomous Web Security Auditing & Compliance Platform</p>
            </div>
          </div>

          {/* Navigation with GooeyNav */}
          <div className="hidden lg:flex items-center">
            <GooeyNav items={navItems} animationTime={500} />
          </div>

          {/* Connection Indicator */}
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
              backendConnected
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
            }`}>
              <div className={`w-2 h-2 rounded-full ${backendConnected ? 'bg-emerald-400 animate-ping' : 'bg-amber-400'}`} />
              {backendConnected ? 'Flask API Online' : 'Client Mode'}
            </div>
            <SpecularButton size="sm" onClick={exportReportJson}>
              <Download className="w-3.5 h-3.5 inline mr-1.5" />
              Export JSON
            </SpecularButton>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6 flex flex-col gap-6 relative z-10">
        {/* Target Input & Orchestrator Control Bar */}
        <section className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur-md shadow-2xl flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex-1 w-full flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-slate-800/70 border border-slate-700/60 text-slate-400">
              <Globe className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="flex-1 relative">
              <input
                type="text"
                value={target}
                onChange={e => setTarget(e.target.value)}
                placeholder="Enter audit target (e.g., https://example.com or scanme.nmap.org)"
                className="w-full bg-slate-950/80 border border-slate-800 focus:border-cyan-500 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none transition-colors"
                disabled={isScanning}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto justify-end">
            <SpecularButton
              size="md"
              onClick={handleStartScan}
              disabled={isScanning}
              className={isScanning ? 'opacity-50 cursor-not-allowed' : ''}
            >
              <Play className="w-4 h-4 inline mr-1.5 fill-current" />
              {isScanning ? 'Auditing Target...' : 'Initiate Audit'}
            </SpecularButton>

            <button
              onClick={runClientSimulation}
              disabled={isScanning}
              className="px-4 py-2 rounded-xl text-xs font-medium border border-slate-700/80 bg-slate-800/60 hover:bg-slate-700/70 text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Run Demo Telemetry
            </button>
          </div>
        </section>

        {/* Live Metrics Ribbon */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 backdrop-blur-sm">
            <div className="text-xs text-slate-400 font-mono uppercase tracking-wider mb-1">Audit Status</div>
            <div className="flex items-center gap-2">
              <span className={`text-base font-bold ${
                scanStatus === 'COMPLETED' ? 'text-emerald-400' :
                scanStatus === 'IN_PROGRESS' ? 'text-cyan-400' : 'text-slate-300'
              }`}>
                {scanStatus}
              </span>
              {isScanning && <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 backdrop-blur-sm">
            <div className="text-xs text-slate-400 font-mono uppercase tracking-wider mb-1">Active Stage</div>
            <div className="text-base font-bold text-white truncate">{activeStage}</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 backdrop-blur-sm">
            <div className="text-xs text-slate-400 font-mono uppercase tracking-wider mb-1">Workers Executed</div>
            <div className="text-base font-bold text-cyan-400 font-mono">
              {stats.workersDispatched} / {WORKER_REGISTRY.length}
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 backdrop-blur-sm">
            <div className="text-xs text-slate-400 font-mono uppercase tracking-wider mb-1">Security Score</div>
            <div className="flex items-center justify-between">
              <span className="text-base font-bold text-emerald-400 font-mono">CVSS {stats.cvssScore}</span>
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono">
                {stats.securityGrade}
              </span>
            </div>
          </div>
        </section>

        {/* Tab Content 1: Audit Console */}
        {activeTab === 'console' && (
          <section className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase">
                  Real-Time Orchestrator Telemetry Terminal
                </h2>
              </div>
              <div className="text-xs text-slate-400 font-mono">
                Session: <span className="text-slate-300">{scanId}</span>
              </div>
            </div>

            {/* Terminal Component with SpecularFrame */}
            <div className="w-full">
              <ScanTerminal />
            </div>
          </section>
        )}

        {/* Tab Content 2: Compliance Bento Grid */}
        {activeTab === 'bento' && (
          <section className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase">
                  Defensive Audit Compliance Scorecards (MagicBento)
                </h2>
              </div>
              <p className="text-xs text-slate-400">Structured telemetry domains evaluated by AI Orchestrator</p>
            </div>

            <div className="w-full py-4">
              <MagicBento cards={complianceCards} />
            </div>
          </section>
        )}

        {/* Tab Content 3: Worker Diagnostics */}
        {activeTab === 'workers' && (
          <section className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase">
                  Multi-Worker Diagnostic Capabilities (11 Single-Purpose Workers)
                </h2>
              </div>
              <span className="text-xs text-slate-400 font-mono">Zero Business Logic Dumb Workers</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {WORKER_REGISTRY.map((worker) => {
                const isDone = completedWorkers[worker.id] === 'COMPLETED'
                return (
                  <div
                    key={worker.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isDone
                        ? 'bg-slate-900/60 border-emerald-500/40 shadow-lg shadow-emerald-500/5'
                        : 'bg-slate-900/30 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div>
                        <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider">{worker.category}</div>
                        <h3 className="font-semibold text-slate-100 text-sm mt-0.5">{worker.name}</h3>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
                        isDone
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                          : 'bg-slate-800 border-slate-700 text-slate-400'
                      }`}>
                        {isDone ? 'COMPLETED' : 'STANDBY'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{worker.desc}</p>
                    <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
                      <span>id: {worker.id}</span>
                      {isDone && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                    </div>
                  </div>
                )
              })}
            </div>
          </section>
        )}

        {/* Tab Content 4: System Architecture */}
        {activeTab === 'arch' && (
          <section className="flex flex-col gap-4">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold tracking-wider text-slate-200 uppercase">
                SentinelScan Core Multi-Tier Architecture
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800/80 flex flex-col gap-3">
                <div className="flex items-center gap-2 text-cyan-400 font-semibold text-sm">
                  <Activity className="w-4 h-4" />
                  Frontend Layer (React 19)
                </div>
                <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
                  <li>Vite-powered React 19 interactive telemetry client</li>
                  <li>Real-time event stream terminal with Word-Reveal spring mechanics</li>
                  <li>MagicBento cards with global spotlight and cursor magnetism</li>
                  <li>Dual-mode operation: live REST telemetry & client demonstration</li>
                </ul>
              </div>

              <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800/80 flex flex-col gap-3">
                <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
                  <Cpu className="w-4 h-4" />
                  AI Orchestrator (Google Gemini)
                </div>
                <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
                  <li>Autonomous decision loop in <code className="text-indigo-300">orchestrator.py</code></li>
                  <li>Dynamic worker sequencing based on evolving scan evidence</li>
                  <li>CVSS v3.1 qualitative and quantitative severity assessment</li>
                  <li>Zero hardcoded scan orders: Gemini is the sole decision maker</li>
                </ul>
              </div>

              <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-800/80 flex flex-col gap-3">
                <div className="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
                  <Radio className="w-4 h-4" />
                  Backend Workers & Observability
                </div>
                <ul className="text-xs text-slate-300 space-y-2 list-disc list-inside">
                  <li>Flask REST API (<code className="text-emerald-300">/api/v1/scans</code>, <code className="text-emerald-300">/api/v1/telemetry</code>)</li>
                  <li>11 single-purpose diagnostic workers returning structured JSON</li>
                  <li>Firestore event pipeline sink with correlation trace IDs</li>
                  <li>Non-blocking worker dispatch with thread-isolated execution</li>
                </ul>
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#07090E] px-6 py-4 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500 font-mono">
          <div>
            SENTINELSCAN &copy; 2026 &mdash; Autonomous AI-Driven Security Auditing Platform
          </div>
          <div className="flex items-center gap-4">
            <span className="text-slate-400">{statusMessage}</span>
            <span className="w-1.5 h-1.5 rounded-full bg-slate-700" />
            <span>Target: <span className="text-cyan-400">{target}</span></span>
          </div>
        </div>
      </footer>
    </div>
  )
}
