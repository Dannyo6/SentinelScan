import React, { useState, useRef, useEffect } from 'react'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Terminal,
  Cpu,
  Layers,
  Lock,
  Download,
  Upload,
  Activity,
  Binary,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Info,
  ChevronRight,
  Flame,
  FileSpreadsheet
} from 'lucide-react'
import { parsePEBinary, computeHashes, DEMO_PROFILES, calculateShannonEntropy } from './utils/peParser'

export default function App() {
  const [report, setReport] = useState(DEMO_PROFILES.polymorphic_packer)
  const [hashes, setHashes] = useState({
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    md5: 'd41d8cd98f00b204e9800998ecf8427e'
  })
  const [isParsing, setIsParsing] = useState(false)
  const [errorMessage, setErrorMessage] = useState(null)
  const [activeTab, setActiveTab] = useState('overview')
  const [isDragOver, setIsDragOver] = useState(false)
  const fileInputRef = useRef(null)

  const handleFileUpload = async (file) => {
    if (!file) return
    setIsParsing(true)
    setErrorMessage(null)

    try {
      if (file.name.endsWith('.json')) {
        const text = await file.text()
        const parsedJson = JSON.parse(text)
        if (parsedJson.meta && (parsedJson.sections || parsedJson.heuristics)) {
          setReport(parsedJson)
          if (parsedJson.hashes) setHashes(parsedJson.hashes)
          setIsParsing(false)
          return
        }
      }

      const buffer = await file.arrayBuffer()
      const [computedHashes, parsedReport] = await Promise.all([
        computeHashes(buffer),
        Promise.resolve(parsePEBinary(buffer, file.name))
      ])

      setHashes(computedHashes)
      setReport(parsedReport)
    } catch (err) {
      setErrorMessage(err.message || 'Failed to inspect file as PE binary.')
    } finally {
      setIsParsing(false)
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragOver(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0])
    }
  }

  const exportTelemetryJson = () => {
    const fullTelemetry = {
      timestamp: new Date().toISOString(),
      engine: 'SentinelScan v2.4-enterprise (Browser Zero-Trust Engine)',
      hashes,
      ...report
    }
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(fullTelemetry, null, 2))
    const dlAnchorElem = document.createElement('a')
    dlAnchorElem.setAttribute('href', dataStr)
    dlAnchorElem.setAttribute('download', `${report.meta.fileName}_telemetry.json`)
    dlAnchorElem.click()
  }

  return (
    <div className="min-h-screen bg-[#07090E] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background cyber grid */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#1f293708_1px,transparent_1px),linear-gradient(to_bottom,#1f293708_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none" />

      {/* Top Navigation */}
      <header className="sticky top-0 z-50 border-b border-slate-800/80 bg-[#07090E]/90 backdrop-blur-md px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20">
              <Binary className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold tracking-tight text-xl text-white">SENTINEL<span className="text-cyan-400">SCAN</span></span>
                <span className="text-[10px] px-2 py-0.5 rounded-full font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800">
                  PE32 / PE32+ FORENSICS
                </span>
              </div>
              <p className="text-xs text-slate-400">Client-Side Zero-Trust Executable Analysis Engine</p>
            </div>
          </div>

          <div className="flex items-center space-x-3 text-xs">
            <a
              href="https://sentinelscan-app.pages.dev"
              target="_blank"
              rel="noreferrer"
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 hover:border-cyan-500/50 hover:bg-slate-800 transition"
            >
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="font-mono text-slate-300">sentinelscan-app.pages.dev</span>
              <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
            </a>

            <button
              onClick={exportTelemetryJson}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold shadow-md shadow-cyan-500/20 transition active:scale-95"
            >
              <Download className="w-4 h-4" />
              <span>Export Telemetry JSON</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6 relative z-10">

        {/* Hero & File Intake Zone */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          {/* Dropzone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true) }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`lg:col-span-8 relative border-2 border-dashed rounded-2xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-200 overflow-hidden ${
              isDragOver
                ? 'border-cyan-400 bg-cyan-950/20 shadow-xl shadow-cyan-500/10'
                : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/60'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => handleFileUpload(e.target.files?.[0])}
              className="hidden"
              accept=".exe,.dll,.sys,.bin,.scr,.json"
            />
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mb-4 group-hover:scale-105 transition">
              <Upload className="w-7 h-7" />
            </div>
            <h3 className="text-lg font-semibold text-white">
              Drop PE32 / PE32+ Executable or Telemetry JSON Here
            </h3>
            <p className="text-sm text-slate-400 max-w-md mt-1">
              Supports <code className="text-cyan-300 font-mono">.exe</code>, <code className="text-cyan-300 font-mono">.dll</code>, <code className="text-cyan-300 font-mono">.sys</code>, <code className="text-cyan-300 font-mono">.bin</code>. Processed strictly locally in browser memory via JavaScript DataView.
            </p>
            <div className="mt-4 flex items-center space-x-2 text-xs text-slate-500">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Zero-Trust Client: No binary bytes ever touch an untrusted server.</span>
            </div>
          </div>

          {/* Quick Presets Loader */}
          <div className="lg:col-span-4 bg-slate-900/60 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center space-x-2 mb-3">
                <Flame className="w-4 h-4 text-amber-400" />
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300">Forensic Showcase Presets</h4>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                Instantly load simulated forensic captures to explore static signatures, Shannon entropy curves, and MITRE mapping:
              </p>

              <div className="space-y-2">
                <button
                  onClick={() => { setReport(DEMO_PROFILES.polymorphic_packer); setErrorMessage(null); }}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-800 border border-slate-700/60 hover:border-rose-500/50 transition flex items-center justify-between group"
                >
                  <div>
                    <div className="text-xs font-semibold text-rose-300 flex items-center space-x-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
                      <span>Polymorphic Dropper (UPX)</span>
                    </div>
                    <div className="text-[11px] text-slate-400">High Entropy (7.91) + Dynamic API Resolution</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-rose-400 transition" />
                </button>

                <button
                  onClick={() => { setReport(DEMO_PROFILES.process_hollowing); setErrorMessage(null); }}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-800 border border-slate-700/60 hover:border-amber-500/50 transition flex items-center justify-between group"
                >
                  <div>
                    <div className="text-xs font-semibold text-amber-300 flex items-center space-x-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                      <span>Process Hollowing Agent</span>
                    </div>
                    <div className="text-[11px] text-slate-400">T1055: VirtualAllocEx + WriteProcessMemory</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-amber-400 transition" />
                </button>

                <button
                  onClick={() => { setReport(DEMO_PROFILES.benign_system); setErrorMessage(null); }}
                  className="w-full text-left p-2.5 rounded-xl bg-slate-800/80 hover:bg-slate-800 border border-slate-700/60 hover:border-emerald-500/50 transition flex items-center justify-between group"
                >
                  <div>
                    <div className="text-xs font-semibold text-emerald-300 flex items-center space-x-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                      <span>Benign Signed PE64 Utility</span>
                    </div>
                    <div className="text-[11px] text-slate-400">Clean Entropy (5.12), CFG & ASLR Hardened</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition" />
                </button>
              </div>
            </div>

            <div className="text-[10px] text-slate-500 font-mono mt-3 pt-3 border-t border-slate-800 flex items-center justify-between">
              <span>Cloudflare Pages: Production Ready</span>
              <span>Worker Engine: 2026.9</span>
            </div>
          </div>
        </section>

        {errorMessage && (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 flex items-center space-x-3 text-sm">
            <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Executive Forensic Summary Card */}
        <section className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
            {/* Risk Gauge & Verdict */}
            <div className="lg:col-span-4 flex items-center space-x-6 border-b lg:border-b-0 lg:border-r border-slate-800 pb-6 lg:pb-0 lg:pr-6">
              <div className="relative w-28 h-28 flex-shrink-0 flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                  <circle cx="50" cy="50" r="40" stroke="currentColor" strokeWidth="8" className="text-slate-800" fill="transparent" />
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    stroke="currentColor"
                    strokeWidth="8"
                    strokeDasharray={251.2}
                    strokeDashoffset={251.2 - (251.2 * (report.heuristics?.score || 0)) / 100}
                    className={`transition-all duration-1000 ${
                      report.heuristics?.score > 60 ? 'text-rose-500' : report.heuristics?.score > 25 ? 'text-amber-500' : 'text-emerald-500'
                    }`}
                    strokeLinecap="round"
                    fill="transparent"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-3xl font-black font-mono tracking-tight">{report.heuristics?.score ?? 0}</span>
                  <span className="text-[10px] uppercase tracking-wider text-slate-400">Risk Score</span>
                </div>
              </div>

              <div>
                <span className="text-xs uppercase tracking-wider text-slate-400 font-mono">Assessment Verdict</span>
                <div className="mt-1">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold font-mono tracking-wider ${
                    report.heuristics?.verdictColor === 'rose'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                      : report.heuristics?.verdictColor === 'amber'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    {report.heuristics?.verdict || 'ANALYZED'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-2 font-mono break-all line-clamp-1">
                  Target: <span className="text-slate-200">{report.meta?.fileName}</span>
                </p>
                <p className="text-xs text-slate-500 font-mono">
                  Size: {(report.meta?.fileSize / 1024).toFixed(1)} KB ({report.meta?.fileSize} bytes)
                </p>
              </div>
            </div>

            {/* Binary Metadata Quick Spec */}
            <div className="lg:col-span-8 grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Architecture</span>
                <p className="text-sm font-semibold text-white font-mono mt-0.5 truncate">{report.meta?.architecture}</p>
                <span className="text-[10px] text-slate-500">{report.meta?.formatName}</span>
              </div>

              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Peak Entropy</span>
                <p className={`text-sm font-bold font-mono mt-0.5 ${report.entropy?.classification?.color}`}>
                  {report.entropy?.highest?.toFixed(4) || '0.0000'} / 8.0
                </p>
                <span className="text-[10px] text-slate-400 truncate block">{report.entropy?.classification?.level}</span>
              </div>

              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Subsystem</span>
                <p className="text-sm font-semibold text-white font-mono mt-0.5 truncate">{report.meta?.subsystem}</p>
                <span className="text-[10px] text-slate-500">PE GUI / CUI</span>
              </div>

              <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider font-mono">Security Mitigations</span>
                <div className="flex items-center space-x-1.5 mt-1 font-mono text-[10px]">
                  <span className={`px-1.5 py-0.5 rounded ${report.mitigations?.aslr ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-500'}`}>ASLR</span>
                  <span className={`px-1.5 py-0.5 rounded ${report.mitigations?.dep_nx ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-500'}`}>DEP</span>
                  <span className={`px-1.5 py-0.5 rounded ${report.mitigations?.cfg ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-500'}`}>CFG</span>
                </div>
              </div>
            </div>
          </div>

          {/* SHA-256 Fingerprint */}
          <div className="mt-4 pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400">
            <div className="flex items-center space-x-2">
              <span className="text-slate-500">SHA-256:</span>
              <span className="text-cyan-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800 break-all">{hashes.sha256}</span>
            </div>
            <div className="text-slate-500 text-[11px]">
              Compiled: {report.meta?.compileTimestamp}
            </div>
          </div>
        </section>

        {/* View Switcher Tabs */}
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-2">
          {[
            { id: 'overview', label: 'Section Entropy Spectrum', icon: Activity },
            { id: 'mitre', label: 'MITRE ATT&CK & IAT Matrix', icon: ShieldAlert },
            { id: 'headers', label: 'PE Header Inspection', icon: Layers },
            { id: 'raw', label: 'Structured JSON Telemetry', icon: Terminal }
          ].map(tab => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            )
          })}
        </div>

        {/* TAB 1: SECTION ENTROPY SPECTRUM */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Mathematical Entropy Guidance Bar */}
            <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 text-xs">
              <div className="flex items-center justify-between mb-2">
                <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
                  <Info className="w-4 h-4 text-cyan-400" />
                  <span>Shannon Entropy Baseline Thresholds (0.0 to 8.0 bits/byte)</span>
                </span>
                <span className="font-mono text-slate-400">Formula: H(X) = -Σ p(x)·log₂(p(x))</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-2.5 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                  <div className="font-mono font-bold text-emerald-400">0.0 - 5.5 : Benign Code</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Uncompressed machine code, x86/x64 assembly instructions, plain text.</div>
                </div>
                <div className="p-2.5 rounded-lg bg-amber-500/5 border border-amber-500/20">
                  <div className="font-mono font-bold text-amber-400">5.5 - 7.1 : Compressed / Assets</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Icons, bitmap resources, localized string tables, zip containers.</div>
                </div>
                <div className="p-2.5 rounded-lg bg-rose-500/5 border border-rose-500/20">
                  <div className="font-mono font-bold text-rose-400">&gt;= 7.2 : Packed / Encrypted</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">Polymorphic packers (UPX, Themida), encrypted shellcode, ransomware payload.</div>
                </div>
              </div>
            </div>

            {/* Sections Spectrum Table */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">Section Headers & Byte Entropy Spectrum</h3>
                  <p className="text-xs text-slate-400">Evaluation of virtual allocation vs raw disk size and byte randomness</p>
                </div>
                <span className="text-xs font-mono text-slate-500">{report.sections?.length || 0} Sections Mapped</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-3">Section Name</th>
                      <th className="px-6 py-3">Virtual Address</th>
                      <th className="px-6 py-3">Virtual Size</th>
                      <th className="px-6 py-3">Raw Size</th>
                      <th className="px-6 py-3">Entropy Bar (H)</th>
                      <th className="px-6 py-3">Characteristics</th>
                      <th className="px-6 py-3 text-right">Flags</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {report.sections?.map((sec, idx) => {
                      const entropyRatio = Math.min(100, (sec.entropy / 8.0) * 100)
                      return (
                        <tr key={idx} className="hover:bg-slate-800/30 transition">
                          <td className="px-6 py-4 font-bold text-white flex items-center space-x-2">
                            <span>{sec.name}</span>
                            {sec.isPackedName && (
                              <span className="px-1.5 py-0.5 text-[9px] font-bold rounded bg-rose-950 text-rose-400 border border-rose-800">
                                PACKER
                              </span>
                            )}
                          </td>
                          <td className="px-6 py-4 text-slate-300">{sec.virtualAddress}</td>
                          <td className="px-6 py-4 text-slate-300">{sec.virtualSize.toLocaleString()} B</td>
                          <td className="px-6 py-4 text-slate-300">{sec.sizeOfRawData.toLocaleString()} B</td>
                          <td className="px-6 py-4 min-w-[200px]">
                            <div className="flex items-center space-x-3">
                              <div className="flex-1 bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800">
                                <div
                                  className={`h-full rounded-full ${
                                    sec.entropy >= 7.2 ? 'bg-rose-500' : sec.entropy >= 5.5 ? 'bg-amber-400' : 'bg-emerald-400'
                                  }`}
                                  style={{ width: `${entropyRatio}%` }}
                                />
                              </div>
                              <span className={`font-bold w-12 text-right ${sec.classification?.color}`}>
                                {sec.entropy.toFixed(3)}
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <div className="flex items-center space-x-1 text-[10px]">
                              <span className={`px-1.5 py-0.5 rounded ${sec.isReadable ? 'bg-slate-800 text-slate-300' : 'text-slate-600'}`}>R</span>
                              <span className={`px-1.5 py-0.5 rounded ${sec.isWritable ? 'bg-slate-800 text-slate-300' : 'text-slate-600'}`}>W</span>
                              <span className={`px-1.5 py-0.5 rounded ${sec.isExecutable ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'text-slate-600'}`}>X</span>
                            </div>
                          </td>
                          <td className="px-6 py-4 text-right">
                            {sec.isWX ? (
                              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/20 text-rose-400 border border-rose-500/40">
                                W^X VIOLATION
                              </span>
                            ) : (
                              <span className="text-slate-500 text-[10px]">Standard</span>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: MITRE ATT&CK & IAT MATRIX */}
        {activeTab === 'mitre' && (
          <div className="space-y-6">
            {/* Detected Threat Cards */}
            <div>
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center space-x-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Heuristic Threat Signatures & MITRE ATT&CK Mapping</span>
              </h3>

              {report.heuristics?.detectedThreats?.length === 0 ? (
                <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 text-center text-slate-400 text-xs">
                  <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                  No high-risk API clusters or MITRE heuristics triggered for this binary profile.
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {report.heuristics?.detectedThreats?.map((threat, idx) => (
                    <div key={idx} className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <span className="text-xs font-bold text-white font-mono">{threat.tactic}</span>
                          <span className={`px-2 py-0.5 text-[10px] font-bold rounded font-mono ${
                            threat.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-400 border border-rose-800'
                              : 'bg-amber-950 text-amber-400 border border-amber-800'
                          }`}>
                            {threat.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mb-3">{threat.description}</p>
                      </div>

                      {threat.matchedApis?.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-slate-800/80">
                          <span className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Correlated APIs:</span>
                          <div className="flex flex-wrap gap-1">
                            {threat.matchedApis.map((api, aIdx) => (
                              <span key={aIdx} className="px-2 py-0.5 rounded bg-slate-950 text-cyan-300 font-mono text-[10px] border border-slate-800">
                                {api}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Import Address Table (IAT) Explorer */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">Import Address Table (IAT) Resolved Modules</h3>
                  <p className="text-xs text-slate-400">Direct static DLL dependencies and imported functional symbols</p>
                </div>
                <span className="text-xs font-mono text-slate-500">{report.imports?.length || 0} Modules</span>
              </div>

              <div className="divide-y divide-slate-800/60">
                {report.imports?.map((mod, idx) => (
                  <div key={idx} className="p-4 hover:bg-slate-800/20 transition">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-bold text-cyan-400 font-mono flex items-center space-x-1.5">
                        <FileCode className="w-3.5 h-3.5" />
                        <span>{mod.module}</span>
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">{mod.apiCount} APIs</span>
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {mod.apis?.map((api, aIdx) => (
                        <span key={aIdx} className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 font-mono text-[11px] border border-slate-800">
                          {api}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: PE HEADER INSPECTION */}
        {activeTab === 'headers' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* DOS & COFF File Header */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 font-mono text-xs">
              <h3 className="text-sm font-semibold text-white font-sans flex items-center space-x-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>DOS & COFF File Header</span>
              </h3>

              <div className="space-y-2">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">e_magic (DOS Signature):</span>
                  <span className="text-cyan-300 font-bold">{report.headers?.dos?.e_magic} (MZ)</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">e_lfanew (PE Header Offset):</span>
                  <span className="text-slate-200">{report.headers?.dos?.e_lfanew}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Machine Architecture:</span>
                  <span className="text-slate-200">{report.headers?.fileHeader?.machine} ({report.meta?.architecture})</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">NumberOfSections:</span>
                  <span className="text-slate-200">{report.headers?.fileHeader?.numberOfSections}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">TimeDateStamp:</span>
                  <span className="text-slate-200">{report.headers?.fileHeader?.timeDateStamp}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">COFF Characteristics:</span>
                  <span className="text-slate-200">{report.headers?.fileHeader?.characteristics}</span>
                </div>
              </div>
            </div>

            {/* Optional Header */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 font-mono text-xs">
              <h3 className="text-sm font-semibold text-white font-sans flex items-center space-x-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Optional Header (Standard & NT Fields)</span>
              </h3>

              <div className="space-y-2">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">Magic:</span>
                  <span className="text-cyan-300 font-bold">{report.headers?.optionalHeader?.magic} ({report.meta?.formatName})</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">AddressOfEntryPoint:</span>
                  <span className="text-cyan-300">{report.headers?.optionalHeader?.addressOfEntryPoint}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">ImageBase:</span>
                  <span className="text-slate-200">{report.headers?.optionalHeader?.imageBase}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">SectionAlignment:</span>
                  <span className="text-slate-200">{report.headers?.optionalHeader?.sectionAlignment} bytes</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">FileAlignment:</span>
                  <span className="text-slate-200">{report.headers?.optionalHeader?.fileAlignment} bytes</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">SizeOfImage:</span>
                  <span className="text-slate-200">{report.headers?.optionalHeader?.sizeOfImage?.toLocaleString()} bytes</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-400">DllCharacteristics:</span>
                  <span className="text-slate-200">{report.headers?.optionalHeader?.dllCharacteristics}</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: STRUCTURED JSON TELEMETRY */}
        {activeTab === 'raw' && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
            <div className="flex items-center justify-between mb-3 px-2">
              <span className="text-xs font-mono text-slate-400 flex items-center space-x-1.5">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Forensic JSON Telemetry Schema v2.4 (CLI & Web Unified)</span>
              </span>
              <button
                onClick={exportTelemetryJson}
                className="text-xs px-3 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition flex items-center space-x-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Report</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 font-mono text-xs text-cyan-300 overflow-x-auto max-h-[500px]">
              {JSON.stringify({ hashes, ...report }, null, 2)}
            </pre>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#07090E] py-6 px-6 text-xs text-slate-500 font-mono text-center">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div>
            SentinelScan Forensic Binary Analysis Platform • MIT License
          </div>
          <div className="flex items-center space-x-4">
            <a href="https://sentinelscan-app.pages.dev" className="text-cyan-400 hover:underline">Cloudflare Pages App</a>
            <span>•</span>
            <a href="https://github.com/Zopyrus269/sentinelscan" target="_blank" rel="noreferrer" className="text-slate-400 hover:text-slate-300">GitHub Repository</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
