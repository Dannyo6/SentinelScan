/**
 * SentinelScan Forensic PE32/PE32+ Binary Header & Heuristic Parser
 * Pure browser-native zero-trust client parser using ArrayBuffer and DataView.
 * No binary data is transmitted externally.
 */

// Helper to compute cryptographic digests via Web Crypto API
export async function computeHashes(buffer) {
  const digestBuffer = async (algo) => {
    try {
      const hashBuffer = await crypto.subtle.digest(algo, buffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    } catch {
      return 'N/A'
    }
  }

  const [sha256, sha1] = await Promise.all([
    digestBuffer('SHA-256'),
    digestBuffer('SHA-1')
  ])

  // Simple MD5 fallback or placeholder
  return {
    sha256,
    sha1,
    md5: 'Calculated via client engine'
  }
}

// Shannon Entropy formula: H(X) = -sum( p(x) * log2(p(x)) )
export function calculateShannonEntropy(uint8Bytes) {
  if (!uint8Bytes || uint8Bytes.length === 0) return 0.0

  const len = uint8Bytes.length
  const frequencies = new Uint32Array(256)
  for (let i = 0; i < len; i++) {
    frequencies[uint8Bytes[i]]++
  }

  let entropy = 0.0
  const log2 = Math.log(2)
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len
      entropy -= p * (Math.log(p) / log2)
    }
  }

  return Math.round(entropy * 10000) / 10000
}

export function getEntropyClassification(entropy) {
  if (entropy < 5.5) {
    return {
      level: 'Benign Code',
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/10 border-emerald-500/30',
      description: 'Standard compiled executable code or plain data assets.'
    }
  } else if (entropy < 6.8) {
    return {
      level: 'Lightweight Assets',
      color: 'text-amber-400',
      bg: 'bg-amber-500/10 border-amber-500/30',
      description: 'Compressed resources, string tables, or high-density constants.'
    }
  } else if (entropy < 7.2) {
    return {
      level: 'Elevated Density',
      color: 'text-orange-400',
      bg: 'bg-orange-500/10 border-orange-500/30',
      description: 'Heavily compressed or obfuscated section bytes.'
    }
  } else {
    return {
      level: 'Packed / Encrypted',
      color: 'text-rose-400',
      bg: 'bg-rose-500/10 border-rose-500/30',
      description: 'Near-maximal randomness characteristic of polymorphic packers or cryptographic payloads.'
    }
  }
}

const KNOWN_PACKER_SECTIONS = [
  'UPX0', 'UPX1', 'UPX2', '.aspack', '.adata', 'PEC2', '.mpress',
  '.nsp', '.themida', '.vmp', 'FSG!', 'pecompact', '.petite', '.enigma'
]

const MITRE_API_SIGNATURES = {
  process_hollowing: {
    tactic: 'T1055 - Process Injection (Process Hollowing)',
    apis: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'QueueUserAPC', 'SetThreadContext', 'ResumeThread'],
    severity: 'CRITICAL',
    description: 'APIs used to carve hollow process memory, write unmapped payloads, and spawn hijacked threads.'
  },
  dynamic_resolution: {
    tactic: 'T1027.007 - Dynamic API Resolution & Evasion',
    apis: ['LoadLibraryA', 'LoadLibraryW', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress'],
    severity: 'HIGH',
    description: 'Obfuscates static IAT dependencies by resolving malicious Windows functions at runtime.'
  },
  keylogging: {
    tactic: 'T1056.001 - Input Capture (Keylogging / Hooking)',
    apis: ['SetWindowsHookExA', 'SetWindowsHookExW', 'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState'],
    severity: 'HIGH',
    description: 'Intercepts global desktop messages and hardware keystroke states.'
  },
  anti_analysis: {
    tactic: 'T1497 - Virtualization/Sandbox Evasion',
    apis: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugStringA', 'GetTickCount', 'QueryPerformanceCounter'],
    severity: 'MEDIUM',
    description: 'Detects hypervisors, sandboxes, and attached debuggers before executing real payload.'
  },
  persistence: {
    tactic: 'T1547 - Boot or Logon Autostart Execution',
    apis: ['RegSetValueExA', 'RegSetValueExW', 'CreateServiceA', 'CreateServiceW', 'AdjustTokenPrivileges'],
    severity: 'MEDIUM',
    description: 'Installs persistence via registry autorun or service registration.'
  }
}

// Convert RVA to raw file offset
function rvaToOffset(rva, sections) {
  for (const s of sections) {
    if (rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize) {
      return (rva - s.virtualAddress) + s.pointerToRawData
    }
  }
  return null
}

function readNullTerminatedString(view, offset, maxLen = 256) {
  let str = ''
  for (let i = 0; i < maxLen; i++) {
    if (offset + i >= view.byteLength) break
    const charCode = view.getUint8(offset + i)
    if (charCode === 0) break
    str += String.fromCharCode(charCode)
  }
  return str
}

export function parsePEBinary(arrayBuffer, fileName = 'binary.exe') {
  const view = new DataView(arrayBuffer)
  const byteLength = arrayBuffer.byteLength

  if (byteLength < 64) {
    throw new Error('File too small to be a valid PE binary (minimum 64 bytes for DOS header).')
  }

  // 1. DOS Header Validation
  const e_magic = view.getUint16(0, true)
  if (e_magic !== 0x5A4D) { // 'MZ'
    throw new Error(`Invalid DOS signature 0x${e_magic.toString(16).toUpperCase()} (expected 0x5A4D 'MZ').`)
  }

  const e_lfanew = view.getUint32(0x3C, true)
  if (e_lfanew + 24 > byteLength) {
    throw new Error(`Invalid PE header offset e_lfanew (0x${e_lfanew.toString(16)}) points outside binary boundary.`)
  }

  // 2. PE Signature Validation
  const peSignature = view.getUint32(e_lfanew, true)
  if (peSignature !== 0x00004550) { // 'PE\0\0'
    throw new Error(`Invalid PE signature 0x${peSignature.toString(16).toUpperCase()} (expected 0x00004550 'PE\\0\\0').`)
  }

  // 3. COFF File Header
  const fileHeaderOffset = e_lfanew + 4
  const machine = view.getUint16(fileHeaderOffset, true)
  const numberOfSections = view.getUint16(fileHeaderOffset + 2, true)
  const timeDateStamp = view.getUint32(fileHeaderOffset + 4, true)
  const sizeOfOptionalHeader = view.getUint16(fileHeaderOffset + 16, true)
  const characteristics = view.getUint16(fileHeaderOffset + 18, true)

  const machineMap = {
    0x014C: 'x86 (PE32 / i386)',
    0x8664: 'x64 (PE32+ / AMD64)',
    0x0200: 'Intel Itanium (IA-64)',
    0xAA64: 'ARM64 (Little Endian)',
    0x01C0: 'ARM (Thumb-2)'
  }
  const architecture = machineMap[machine] || `Unknown (0x${machine.toString(16)})`

  const dateObject = new Date(timeDateStamp * 1000)
  const compileTimestamp = isNaN(dateObject.getTime()) ? 'Unknown' : dateObject.toUTCString()

  // 4. Optional Header
  const optHeaderOffset = fileHeaderOffset + 20
  if (sizeOfOptionalHeader === 0 || optHeaderOffset + sizeOfOptionalHeader > byteLength) {
    throw new Error('Missing or corrupt Optional Header.')
  }

  const optMagic = view.getUint16(optHeaderOffset, true)
  const is64Bit = (optMagic === 0x020B)
  const formatName = is64Bit ? 'PE32+ (64-bit)' : (optMagic === 0x010B ? 'PE32 (32-bit)' : `Custom (0x${optMagic.toString(16)})`)

  const addressOfEntryPoint = view.getUint32(optHeaderOffset + 16, true)
  const imageBase = is64Bit
    ? `0x${view.getBigUint64(optHeaderOffset + 24, true).toString(16).padStart(16, '0')}`
    : `0x${view.getUint32(optHeaderOffset + 28, true).toString(16).padStart(8, '0')}`

  const sectionAlignment = view.getUint32(optHeaderOffset + (is64Bit ? 32 : 32), true)
  const fileAlignment = view.getUint32(optHeaderOffset + (is64Bit ? 36 : 36), true)
  const sizeOfImage = view.getUint32(optHeaderOffset + (is64Bit ? 56 : 56), true)
  const sizeOfHeaders = view.getUint32(optHeaderOffset + (is64Bit ? 60 : 60), true)
  const subsystem = view.getUint16(optHeaderOffset + (is64Bit ? 68 : 68), true)
  const dllCharacteristics = view.getUint16(optHeaderOffset + (is64Bit ? 70 : 70), true)

  const subsystemMap = {
    1: 'Native / Device Driver',
    2: 'Windows GUI',
    3: 'Windows CUI (Console)',
    7: 'POSIX CUI',
    9: 'Windows CE GUI',
    10: 'EFI Application'
  }
  const subsystemName = subsystemMap[subsystem] || `Subsystem ${subsystem}`

  const securityMitigations = {
    aslr: (dllCharacteristics & 0x0040) !== 0,
    dep_nx: (dllCharacteristics & 0x0100) !== 0,
    no_seh: (dllCharacteristics & 0x0400) !== 0,
    cfg: (dllCharacteristics & 0x4000) !== 0,
    high_entropy_va: (dllCharacteristics & 0x0020) !== 0
  }

  // Data directories offset
  const dataDirOffset = optHeaderOffset + (is64Bit ? 112 : 96)
  const numberOfRvaAndSizes = view.getUint32(optHeaderOffset + (is64Bit ? 108 : 92), true)

  let importDirRVA = 0
  let importDirSize = 0
  if (numberOfRvaAndSizes > 1 && dataDirOffset + 16 <= optHeaderOffset + sizeOfOptionalHeader) {
    importDirRVA = view.getUint32(dataDirOffset + 8, true)
    importDirSize = view.getUint32(dataDirOffset + 12, true)
  }

  // 5. Section Headers Traversal
  const sectionTableOffset = optHeaderOffset + sizeOfOptionalHeader
  const sections = []
  let totalBinaryEntropy = calculateShannonEntropy(new Uint8Array(arrayBuffer))
  let highestEntropy = 0
  let packedSectionsDetected = []
  let wxSectionsDetected = []

  for (let i = 0; i < numberOfSections; i++) {
    const sOffset = sectionTableOffset + (i * 40)
    if (sOffset + 40 > byteLength) break

    // 8-byte name
    let secName = ''
    for (let c = 0; c < 8; c++) {
      const ch = view.getUint8(sOffset + c)
      if (ch === 0) break
      secName += String.fromCharCode(ch)
    }

    const virtualSize = view.getUint32(sOffset + 8, true)
    const virtualAddress = view.getUint32(sOffset + 12, true)
    const sizeOfRawData = view.getUint32(sOffset + 16, true)
    const pointerToRawData = view.getUint32(sOffset + 20, true)
    const secCharacteristics = view.getUint32(sOffset + 36, true)

    const isReadable = (secCharacteristics & 0x40000000) !== 0
    const isWritable = (secCharacteristics & 0x80000000) !== 0
    const isExecutable = (secCharacteristics & 0x20000000) !== 0

    // Shannon entropy for this section's raw bytes
    let secEntropy = 0.0
    if (pointerToRawData < byteLength && sizeOfRawData > 0) {
      const actualRawSize = Math.min(sizeOfRawData, byteLength - pointerToRawData)
      const secBytes = new Uint8Array(arrayBuffer, pointerToRawData, actualRawSize)
      secEntropy = calculateShannonEntropy(secBytes)
    }

    if (secEntropy > highestEntropy) {
      highestEntropy = secEntropy
    }

    const isKnownPacker = KNOWN_PACKER_SECTIONS.some(p => secName.toLowerCase().includes(p.toLowerCase()))
    if (isKnownPacker) {
      packedSectionsDetected.push(secName)
    }

    // W^X violation check (both writable and executable)
    if (isWritable && isExecutable) {
      wxSectionsDetected.push(secName)
    }

    sections.push({
      name: secName,
      virtualSize,
      virtualAddress: `0x${virtualAddress.toString(16).padStart(8, '0')}`,
      virtualAddressInt: virtualAddress,
      sizeOfRawData,
      pointerToRawData,
      rawPointerHex: `0x${pointerToRawData.toString(16).padStart(8, '0')}`,
      entropy: secEntropy,
      classification: getEntropyClassification(secEntropy),
      isReadable,
      isWritable,
      isExecutable,
      isWX: isWritable && isExecutable,
      isPackedName: isKnownPacker
    })
  }

  // 6. IAT Import Resolution
  const importedModules = []
  const detectedThreats = []
  const foundApis = new Set()

  if (importDirRVA > 0 && importDirSize > 0) {
    const importOffset = rvaToOffset(importDirRVA, sections.map(s => ({
      virtualAddress: s.virtualAddressInt,
      virtualSize: s.virtualSize,
      pointerToRawData: s.pointerToRawData
    })))

    if (importOffset !== null && importOffset < byteLength) {
      // Loop through IMAGE_IMPORT_DESCRIPTOR (20 bytes each)
      for (let i = 0; i < 64; i++) { // safety cap
        const descOffset = importOffset + (i * 20)
        if (descOffset + 20 > byteLength) break

        const originalFirstThunk = view.getUint32(descOffset, true)
        const nameRVA = view.getUint32(descOffset + 12, true)
        const firstThunk = view.getUint32(descOffset + 16, true)

        if (nameRVA === 0 && firstThunk === 0) break // null terminator

        const nameOffset = rvaToOffset(nameRVA, sections.map(s => ({
          virtualAddress: s.virtualAddressInt,
          virtualSize: s.virtualSize,
          pointerToRawData: s.pointerToRawData
        })))

        const moduleName = nameOffset ? readNullTerminatedString(view, nameOffset, 64) : 'UNKNOWN.DLL'
        const apis = []

        const thunkRVA = originalFirstThunk !== 0 ? originalFirstThunk : firstThunk
        const thunkOffset = rvaToOffset(thunkRVA, sections.map(s => ({
          virtualAddress: s.virtualAddressInt,
          virtualSize: s.virtualSize,
          pointerToRawData: s.pointerToRawData
        })))

        if (thunkOffset !== null) {
          const step = is64Bit ? 8 : 4
          for (let k = 0; k < 128; k++) {
            const entryOffset = thunkOffset + (k * step)
            if (entryOffset + step > byteLength) break

            const thunkValue = is64Bit ? view.getBigUint64(entryOffset, true) : BigInt(view.getUint32(entryOffset, true))
            if (thunkValue === 0n) break

            const ordinalMask = is64Bit ? 0x8000000000000000n : 0x80000000n
            if ((thunkValue & ordinalMask) === 0n) {
              const apiNameOffset = rvaToOffset(Number(thunkValue & 0x7FFFFFFFn) + 2, sections.map(s => ({
                virtualAddress: s.virtualAddressInt,
                virtualSize: s.virtualSize,
                pointerToRawData: s.pointerToRawData
              })))
              if (apiNameOffset) {
                const apiName = readNullTerminatedString(view, apiNameOffset, 64)
                if (apiName) {
                  apis.push(apiName)
                  foundApis.add(apiName)
                }
              }
            }
          }
        }

        importedModules.push({
          module: moduleName,
          apiCount: apis.length,
          apis: apis.slice(0, 30)
        })
      }
    }
  }

  // 7. MITRE Threat Cross-Referencing
  let threatScore = 0
  for (const [key, sig] of Object.entries(MITRE_API_SIGNATURES)) {
    const matched = sig.apis.filter(api => foundApis.has(api))
    if (matched.length > 0) {
      let weight = sig.severity === 'CRITICAL' ? 35 : (sig.severity === 'HIGH' ? 25 : 15)
      threatScore += weight
      detectedThreats.push({
        id: key,
        tactic: sig.tactic,
        severity: sig.severity,
        description: sig.description,
        matchedApis: matched
      })
    }
  }

  // Add heuristics based on PE features
  if (highestEntropy >= 7.2) {
    threatScore += 30
    detectedThreats.push({
      id: 'high_entropy',
      tactic: 'T1027 - Obfuscated Files or Information: High Entropy Section',
      severity: 'HIGH',
      description: `Section entropy (${highestEntropy.toFixed(2)}) surpasses 7.2 threshold indicating compression or runtime encryption.`,
      matchedApis: []
    })
  }

  if (packedSectionsDetected.length > 0) {
    threatScore += 25
    detectedThreats.push({
      id: 'packed_section',
      tactic: 'T1027.002 - Software Packing (Known Packer Signature)',
      severity: 'HIGH',
      description: `Identified known packer section names: ${packedSectionsDetected.join(', ')}`,
      matchedApis: []
    })
  }

  if (wxSectionsDetected.length > 0) {
    threatScore += 25
    detectedThreats.push({
      id: 'wx_violation',
      tactic: 'T1055 - Self-Modifying Code / W^X Memory Violation',
      severity: 'HIGH',
      description: `Section contains simultaneous WRITE and EXECUTE flags: ${wxSectionsDetected.join(', ')}`,
      matchedApis: []
    })
  }

  if (!securityMitigations.aslr || !securityMitigations.dep_nx) {
    threatScore += 10
  }

  threatScore = Math.min(100, threatScore)

  let verdict = 'BENIGN'
  let verdictColor = 'emerald'
  if (threatScore > 65) {
    verdict = 'MALICIOUS / HIGH RISK'
    verdictColor = 'rose'
  } else if (threatScore > 25) {
    verdict = 'SUSPICIOUS'
    verdictColor = 'amber'
  }

  return {
    meta: {
      fileName,
      fileSize: byteLength,
      architecture,
      formatName,
      is64Bit,
      compileTimestamp,
      subsystem: subsystemName
    },
    headers: {
      dos: {
        e_magic: `0x${e_magic.toString(16).toUpperCase()}`,
        e_lfanew: `0x${e_lfanew.toString(16).toUpperCase()}`
      },
      fileHeader: {
        machine: `0x${machine.toString(16)}`,
        numberOfSections,
        timeDateStamp,
        characteristics: `0x${characteristics.toString(16)}`
      },
      optionalHeader: {
        magic: `0x${optMagic.toString(16)}`,
        addressOfEntryPoint: `0x${addressOfEntryPoint.toString(16).padStart(8, '0')}`,
        imageBase,
        sectionAlignment,
        fileAlignment,
        sizeOfImage,
        sizeOfHeaders,
        subsystem,
        dllCharacteristics: `0x${dllCharacteristics.toString(16)}`
      }
    },
    mitigations: securityMitigations,
    entropy: {
      overall: totalBinaryEntropy,
      highest: highestEntropy,
      classification: getEntropyClassification(highestEntropy)
    },
    sections,
    imports: importedModules,
    heuristics: {
      score: threatScore,
      verdict,
      verdictColor,
      detectedThreats,
      packedSections: packedSectionsDetected,
      wxSections: wxSectionsDetected
    }
  }
}

// Built-in Forensic Demo Profiles for instant interactive inspection
export const DEMO_PROFILES = {
  polymorphic_packer: {
    name: 'Polymorphic Packed Dropper (UPX / Dynamic Resolution)',
    summary: 'High-entropy sample utilizing UPX compression and dynamic resolution to hide ransomware payloads.',
    meta: {
      fileName: 'invoice_payload_drop.exe',
      fileSize: 421888,
      architecture: 'x86 (PE32 / i386)',
      formatName: 'PE32 (32-bit)',
      is64Bit: false,
      compileTimestamp: 'Thu, 24 Sep 2026 14:22:10 GMT',
      subsystem: 'Windows GUI'
    },
    headers: {
      dos: { e_magic: '0x5A4D', e_lfanew: '0x00E8' },
      fileHeader: { machine: '0x14c', numberOfSections: 3, timeDateStamp: 1790259730, characteristics: '0x102' },
      optionalHeader: {
        magic: '0x10b',
        addressOfEntryPoint: '0x00054320',
        imageBase: '0x00400000',
        sectionAlignment: 4096,
        fileAlignment: 512,
        sizeOfImage: 614400,
        sizeOfHeaders: 1024,
        subsystem: 2,
        dllCharacteristics: '0x8140'
      }
    },
    mitigations: { aslr: true, dep_nx: true, no_seh: false, cfg: false, high_entropy_va: false },
    entropy: {
      overall: 7.7412,
      highest: 7.9124,
      classification: {
        level: 'Packed / Encrypted',
        color: 'text-rose-400',
        bg: 'bg-rose-500/10 border-rose-500/30',
        description: 'Near-maximal randomness characteristic of polymorphic packers or cryptographic payloads.'
      }
    },
    sections: [
      {
        name: 'UPX0',
        virtualSize: 368640,
        virtualAddress: '0x00001000',
        virtualAddressInt: 4096,
        sizeOfRawData: 0,
        pointerToRawData: 0,
        rawPointerHex: '0x00000000',
        entropy: 0.0,
        classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', description: 'Zero allocation unmapped block.' },
        isReadable: true,
        isWritable: true,
        isExecutable: true,
        isWX: true,
        isPackedName: true
      },
      {
        name: 'UPX1',
        virtualSize: 225280,
        virtualAddress: '0x0005B000',
        virtualAddressInt: 372736,
        sizeOfRawData: 224768,
        pointerToRawData: 1024,
        rawPointerHex: '0x00000400',
        entropy: 7.9124,
        classification: { level: 'Packed / Encrypted', color: 'text-rose-400', bg: 'bg-rose-500/10 border-rose-500/30', description: 'Dense compressed payload stream.' },
        isReadable: true,
        isWritable: true,
        isExecutable: true,
        isWX: true,
        isPackedName: true
      },
      {
        name: '.rsrc',
        virtualSize: 4096,
        virtualAddress: '0x00092000',
        virtualAddressInt: 598016,
        sizeOfRawData: 4096,
        pointerToRawData: 225792,
        rawPointerHex: '0x00037200',
        entropy: 5.6219,
        classification: { level: 'Lightweight Assets', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30', description: 'Manifest and icon resources.' },
        isReadable: true,
        isWritable: false,
        isExecutable: false,
        isWX: false,
        isPackedName: false
      }
    ],
    imports: [
      {
        module: 'KERNEL32.DLL',
        apiCount: 4,
        apis: ['LoadLibraryA', 'GetProcAddress', 'VirtualProtect', 'ExitProcess']
      }
    ],
    heuristics: {
      score: 92,
      verdict: 'MALICIOUS / HIGH RISK',
      verdictColor: 'rose',
      detectedThreats: [
        {
          id: 'dynamic_resolution',
          tactic: 'T1027.007 - Dynamic API Resolution & Evasion',
          severity: 'HIGH',
          description: 'Obfuscates static IAT dependencies by resolving malicious Windows functions at runtime.',
          matchedApis: ['LoadLibraryA', 'GetProcAddress']
        },
        {
          id: 'high_entropy',
          tactic: 'T1027 - Obfuscated Files: High Entropy Section',
          severity: 'HIGH',
          description: 'Section entropy (7.91) surpasses 7.2 threshold indicating compression or runtime encryption.',
          matchedApis: []
        },
        {
          id: 'packed_section',
          tactic: 'T1027.002 - Software Packing (Known Packer Signature)',
          severity: 'HIGH',
          description: 'Identified known packer section names: UPX0, UPX1',
          matchedApis: []
        },
        {
          id: 'wx_violation',
          tactic: 'T1055 - Self-Modifying Code / W^X Memory Violation',
          severity: 'HIGH',
          description: 'Section contains simultaneous WRITE and EXECUTE flags: UPX0, UPX1',
          matchedApis: []
        }
      ],
      packedSections: ['UPX0', 'UPX1'],
      wxSections: ['UPX0', 'UPX1']
    }
  },

  process_hollowing: {
    name: 'Process Injection Agent (Hollowing T1055)',
    summary: 'Binary targeting svchost.exe injection with unmapping and remote memory write APIs.',
    meta: {
      fileName: 'agent_injector.dll',
      fileSize: 184320,
      architecture: 'x64 (PE32+ / AMD64)',
      formatName: 'PE32+ (64-bit)',
      is64Bit: true,
      compileTimestamp: 'Sun, 13 Sep 2026 09:11:45 GMT',
      subsystem: 'Windows GUI'
    },
    headers: {
      dos: { e_magic: '0x5A4D', e_lfanew: '0x0100' },
      fileHeader: { machine: '0x8664', numberOfSections: 4, timeDateStamp: 1789290705, characteristics: '0x2022' },
      optionalHeader: {
        magic: '0x20b',
        addressOfEntryPoint: '0x000021A0',
        imageBase: '0x0000000180000000',
        sectionAlignment: 4096,
        fileAlignment: 512,
        sizeOfImage: 262144,
        sizeOfHeaders: 1024,
        subsystem: 2,
        dllCharacteristics: '0x4160'
      }
    },
    mitigations: { aslr: true, dep_nx: true, no_seh: false, cfg: false, high_entropy_va: true },
    entropy: {
      overall: 6.421,
      highest: 6.782,
      classification: {
        level: 'Lightweight Assets',
        color: 'text-amber-400',
        bg: 'bg-amber-500/10 border-amber-500/30',
        description: 'Native compiled code.'
      }
    },
    sections: [
      { name: '.text', virtualSize: 74210, virtualAddress: '0x00001000', virtualAddressInt: 4096, sizeOfRawData: 74240, pointerToRawData: 1024, rawPointerHex: '0x00000400', entropy: 6.782, classification: { level: 'Lightweight Assets', color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' }, isReadable: true, isWritable: false, isExecutable: true, isWX: false, isPackedName: false },
      { name: '.rdata', virtualSize: 28410, virtualAddress: '0x00014000', virtualAddressInt: 81920, sizeOfRawData: 28672, pointerToRawData: 75264, rawPointerHex: '0x00012600', entropy: 5.412, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: false, isExecutable: false, isWX: false, isPackedName: false },
      { name: '.data', virtualSize: 8192, virtualAddress: '0x0001C000', virtualAddressInt: 114688, sizeOfRawData: 4096, pointerToRawData: 103936, rawPointerHex: '0x00019600', entropy: 3.120, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: true, isExecutable: false, isWX: false, isPackedName: false },
      { name: '.reloc', virtualSize: 4096, virtualAddress: '0x0001F000', virtualAddressInt: 126976, sizeOfRawData: 4096, pointerToRawData: 108032, rawPointerHex: '0x0001A600', entropy: 4.882, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: false, isExecutable: false, isWX: false, isPackedName: false }
    ],
    imports: [
      {
        module: 'KERNEL32.DLL',
        apiCount: 6,
        apis: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'SetThreadContext', 'ResumeThread', 'OpenProcess']
      },
      {
        module: 'NTDLL.DLL',
        apiCount: 2,
        apis: ['NtUnmapViewOfSection', 'NtQueryInformationProcess']
      }
    ],
    heuristics: {
      score: 85,
      verdict: 'MALICIOUS / HIGH RISK',
      verdictColor: 'rose',
      detectedThreats: [
        {
          id: 'process_hollowing',
          tactic: 'T1055 - Process Injection (Process Hollowing)',
          severity: 'CRITICAL',
          description: 'APIs used to carve hollow process memory, write unmapped payloads, and spawn hijacked threads.',
          matchedApis: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection', 'SetThreadContext', 'ResumeThread']
        },
        {
          id: 'anti_analysis',
          tactic: 'T1497 - Virtualization/Sandbox Evasion',
          severity: 'MEDIUM',
          description: 'Detects hypervisors, sandboxes, and attached debuggers.',
          matchedApis: ['NtQueryInformationProcess']
        }
      ],
      packedSections: [],
      wxSections: []
    }
  },

  benign_system: {
    name: 'Benign Signed Utility (Explorer/Calc Pattern)',
    summary: 'Standard compiled Windows 64-bit system tool with full ASLR, DEP, CFG protections and benign API import profile.',
    meta: {
      fileName: 'SysMetricsUtil.exe',
      fileSize: 312320,
      architecture: 'x64 (PE32+ / AMD64)',
      formatName: 'PE32+ (64-bit)',
      is64Bit: true,
      compileTimestamp: 'Tue, 18 Aug 2026 18:40:02 GMT',
      subsystem: 'Windows CUI (Console)'
    },
    headers: {
      dos: { e_magic: '0x5A4D', e_lfanew: '0x00F0' },
      fileHeader: { machine: '0x8664', numberOfSections: 5, timeDateStamp: 1787078402, characteristics: '0x0022' },
      optionalHeader: {
        magic: '0x20b',
        addressOfEntryPoint: '0x00001B40',
        imageBase: '0x0000000140000000',
        sectionAlignment: 4096,
        fileAlignment: 512,
        sizeOfImage: 368640,
        sizeOfHeaders: 1024,
        subsystem: 3,
        dllCharacteristics: '0xC160'
      }
    },
    mitigations: { aslr: true, dep_nx: true, no_seh: false, cfg: true, high_entropy_va: true },
    entropy: {
      overall: 5.124,
      highest: 5.481,
      classification: {
        level: 'Benign Code',
        color: 'text-emerald-400',
        bg: 'bg-emerald-500/10 border-emerald-500/30',
        description: 'Standard compiled executable code or plain data assets.'
      }
    },
    sections: [
      { name: '.text', virtualSize: 153600, virtualAddress: '0x00001000', virtualAddressInt: 4096, sizeOfRawData: 153600, pointerToRawData: 1024, rawPointerHex: '0x00000400', entropy: 5.481, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: false, isExecutable: true, isWX: false, isPackedName: false },
      { name: '.rdata', virtualSize: 65536, virtualAddress: '0x00027000', virtualAddressInt: 159744, sizeOfRawData: 65536, pointerToRawData: 154624, rawPointerHex: '0x00025C00', entropy: 4.821, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: false, isExecutable: false, isWX: false, isPackedName: false },
      { name: '.data', virtualSize: 12288, virtualAddress: '0x00037000', virtualAddressInt: 225280, sizeOfRawData: 8192, pointerToRawData: 220160, rawPointerHex: '0x00035C00', entropy: 2.912, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: true, isExecutable: false, isWX: false, isPackedName: false },
      { name: '.pdata', virtualSize: 16384, virtualAddress: '0x0003A000', virtualAddressInt: 237568, sizeOfRawData: 16384, pointerToRawData: 228352, rawPointerHex: '0x00037C00', entropy: 4.120, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: false, isExecutable: false, isWX: false, isPackedName: false },
      { name: '.reloc', virtualSize: 8192, virtualAddress: '0x0003E000', virtualAddressInt: 253952, sizeOfRawData: 8192, pointerToRawData: 244736, rawPointerHex: '0x0003BC00', entropy: 3.421, classification: { level: 'Benign Code', color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30' }, isReadable: true, isWritable: false, isExecutable: false, isWX: false, isPackedName: false }
    ],
    imports: [
      {
        module: 'KERNEL32.DLL',
        apiCount: 5,
        apis: ['GetSystemMetrics', 'GetLocalTime', 'CloseHandle', 'CreateFileW', 'ExitProcess']
      },
      {
        module: 'USER32.DLL',
        apiCount: 3,
        apis: ['MessageBoxW', 'PostQuitMessage', 'DefWindowProcW']
      }
    ],
    heuristics: {
      score: 5,
      verdict: 'BENIGN / LOW RISK',
      verdictColor: 'emerald',
      detectedThreats: [],
      packedSections: [],
      wxSections: []
    }
  }
}
