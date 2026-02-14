import React, { useState, useEffect, useCallback } from 'react';
import {
  SafeAreaView,
  StyleSheet,
  Text,
  View,
  FlatList,
  TouchableOpacity,
  Platform,
  Alert,
  ActivityIndicator,
  Share,
  StatusBar,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

// ═══════════════════════════════════════════════════════════════════════════════
//  TYPES
// ═══════════════════════════════════════════════════════════════════════════════

interface Device {
  ip: string;
  mac: string;
  status: string;
  scan_mode?: string;
  vendor?: string;
  deviceType?: string;
}

interface HoneypotLog {
  ip: string;
  time: string;
  port?: number;
}

interface ScanResponse {
  status: string;
  scan_mode: string;
  subnet: string;
  count: number;
  is_root: boolean;
  timestamp: string;
  devices: Device[];
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DEVICE ICON RESOLVER
// ═══════════════════════════════════════════════════════════════════════════════

function getDeviceIcon(deviceType?: string): string {
  switch (deviceType) {
    case 'mobile': return '📱';
    case 'desktop': return '🖥️';
    case 'iot': return '📡';
    case 'network': return '🌐';
    default: return '❓';
  }
}

function getDeviceLabel(deviceType?: string): string {
  switch (deviceType) {
    case 'mobile': return 'MOBILE';
    case 'desktop': return 'DESKTOP';
    case 'iot': return 'IoT DEVICE';
    case 'network': return 'NETWORK';
    default: return 'UNKNOWN';
  }
}

function getRiskColor(risk?: string): string {
  switch (risk) {
    case 'CRITICAL': return '#FF2D55';
    case 'HIGH': return '#FF453A';
    case 'MEDIUM': return '#FF9F0A';
    case 'LOW': return '#30D158';
    default: return '#8E8E93';
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STORAGE KEYS
// ═══════════════════════════════════════════════════════════════════════════════

const STORAGE_KEYS = {
  TRUSTED_MACS: '@sentinel_trusted_macs',
  LAST_SCAN: '@sentinel_last_scan_time',
};

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN APP
// ═══════════════════════════════════════════════════════════════════════════════

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [trustedMacs, setTrustedMacs] = useState<string[]>([]);
  const [honeypotLogs, setHoneypotLogs] = useState<HoneypotLog[]>([]);
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);
  const [scanMode, setScanMode] = useState<string>('—');
  const [subnet, setSubnet] = useState<string>('—');

  // ── Connection ──────────────────────────────────────────────────────────────
  const BASE_URL = Platform.OS === 'android'
    ? 'http://10.0.2.2:3000'
    : 'http://localhost:3000';

  // ── Load persisted data on startup ──────────────────────────────────────────
  useEffect(() => {
    const loadPersistedData = async () => {
      try {
        const [storedMacs, storedTime] = await Promise.all([
          AsyncStorage.getItem(STORAGE_KEYS.TRUSTED_MACS),
          AsyncStorage.getItem(STORAGE_KEYS.LAST_SCAN),
        ]);
        if (storedMacs) setTrustedMacs(JSON.parse(storedMacs));
        if (storedTime) setLastScanTime(storedTime);
      } catch (e) {
        console.error('Failed to load persisted data:', e);
      }
    };
    loadPersistedData();
  }, []);

  // ── Network Scan ────────────────────────────────────────────────────────────
  const fetchScan = useCallback(async () => {
    setLoading(true);
    try {
      const [scanRes, hpRes] = await Promise.all([
        fetch(`${BASE_URL}/api/scan`),
        fetch(`${BASE_URL}/api/honeypot`),
      ]);

      const scanData: ScanResponse = await scanRes.json();
      const hpData: HoneypotLog[] = await hpRes.json();

      setDevices(scanData.devices || []);
      setHoneypotLogs(hpData || []);
      setScanMode(scanData.scan_mode || 'unknown');
      setSubnet(scanData.subnet || 'unknown');

      // Persist last scan time
      const timeStr = new Date().toLocaleString();
      setLastScanTime(timeStr);
      await AsyncStorage.setItem(STORAGE_KEYS.LAST_SCAN, timeStr);

    } catch (error) {
      Alert.alert(
        '🔴 Connection Error',
        'Could not connect to Sentinel Backend.\n\nMake sure the server is running:\n  node server.js'
      );
    } finally {
      setLoading(false);
    }
  }, [BASE_URL]);

  // ── Deep Scan ───────────────────────────────────────────────────────────────
  const inspectDevice = useCallback(async (ip: string) => {
    Alert.alert('🕵️ Deep Scan', `Scanning ${ip} for open ports...`);
    try {
      const response = await fetch(`${BASE_URL}/api/inspect?ip=${ip}`);
      const data = await response.json();

      const ports = data.open_ports || [];
      const portList = ports.length > 0
        ? ports.map((p: any) => `${p.port}${p.banner ? ` (${p.banner.substring(0, 30)})` : ''}`).join('\n')
        : 'None found';

      Alert.alert(
        `🔎 ${data.hostname || ip}`,
        `Risk: ${data.risk_level || 'N/A'}\n` +
        `Ports scanned: 20\n` +
        `Open: ${data.port_count || 0}\n\n` +
        `${portList}`
      );
    } catch (e) {
      Alert.alert('Error', 'Deep scan failed.');
    }
  }, [BASE_URL]);

  // ── Credential Audit ────────────────────────────────────────────────────────
  const auditDevice = useCallback(async (ip: string) => {
    try {
      const response = await fetch(`${BASE_URL}/api/audit?ip=${ip}`);
      const data = await response.json();

      if (data.status === 'VULNERABLE') {
        const vulnCreds = data.details
          ?.filter((d: any) => d.status === 'VULNERABLE')
          .map((d: any) => `  • ${d.credential}`)
          .join('\n') || '';

        Alert.alert(
          '🚨 CRITICAL — DEFAULT CREDENTIALS',
          `${data.message}\n\nAccepted credentials:\n${vulnCreds}\n\nChange these immediately!`
        );
      } else {
        Alert.alert('✅ Secure', data.message || 'No default credentials found.');
      }
    } catch (e) {
      Alert.alert('Error', 'Credential audit failed.');
    }
  }, [BASE_URL]);

  // ── Trust Toggle ────────────────────────────────────────────────────────────
  const toggleTrust = useCallback(async (mac: string) => {
    const newTrusted = trustedMacs.includes(mac)
      ? trustedMacs.filter(m => m !== mac)
      : [...trustedMacs, mac];

    setTrustedMacs(newTrusted);
    try {
      await AsyncStorage.setItem(STORAGE_KEYS.TRUSTED_MACS, JSON.stringify(newTrusted));
    } catch (e) {
      console.error('Failed to persist trusted MACs:', e);
    }
  }, [trustedMacs]);

  // ── Report Generation ──────────────────────────────────────────────────────
  const generateReport = useCallback(async () => {
    const date = new Date().toLocaleString();
    let report = `🛡️ SENTINEL SECURITY REPORT\n`;
    report += `Generated: ${date}\n`;
    report += `Subnet: ${subnet} | Mode: ${scanMode}\n\n`;

    report += `═══ DEVICE LIST (${devices.length}) ═══\n`;
    devices.forEach(d => {
      const icon = getDeviceIcon(d.deviceType);
      const vendor = d.vendor || 'Unknown';
      const trusted = trustedMacs.includes(d.mac);
      report += `${icon} [${trusted ? 'TRUSTED' : 'UNKNOWN'}] ${d.ip}\n`;
      report += `   Vendor: ${vendor} | MAC: ${d.mac}\n\n`;
    });

    if (honeypotLogs.length > 0) {
      report += `\n🚨 INTRUSION ATTEMPTS (${honeypotLogs.length}) ═══\n`;
      honeypotLogs.forEach(log => {
        report += `[BLOCKED] ${log.ip} at ${log.time}\n`;
      });
    } else {
      report += `\n✅ No intrusion attempts detected.\n`;
    }

    try {
      await Share.share({ message: report });
    } catch {
      Alert.alert('Error', 'Could not export report.');
    }
  }, [devices, honeypotLogs, trustedMacs, scanMode, subnet]);

  // ── Computed values ─────────────────────────────────────────────────────────
  const untrustedCount = devices.filter(d => !trustedMacs.includes(d.mac)).length;

  // ═══════════════════════════════════════════════════════════════════════════════
  //  RENDER
  // ═══════════════════════════════════════════════════════════════════════════════

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#000" />

      {/* ── Header ──────────────────────────────────────────────────────── */}
      <View style={styles.header}>
        <Text style={styles.title}>🛡️ Sentinel Pro</Text>
        <Text style={styles.subtitle}>
          {devices.length} Devices • {untrustedCount} Unknown • {honeypotLogs.length} Intrusions
        </Text>
        {lastScanTime && (
          <Text style={styles.scanTime}>Last scan: {lastScanTime} • {scanMode.toUpperCase()}</Text>
        )}
      </View>

      {/* ── Honeypot Banner ─────────────────────────────────────────────── */}
      {honeypotLogs.length > 0 && (
        <View style={styles.banner}>
          <Text style={styles.bannerText}>
            🚨 HONEYPOT TRIGGERED! ({honeypotLogs.length} intrusion{honeypotLogs.length > 1 ? 's' : ''})
          </Text>
        </View>
      )}

      {/* ── Content ─────────────────────────────────────────────────────── */}
      <View style={styles.content}>

        {/* Action Buttons */}
        <View style={styles.buttonRow}>
          <TouchableOpacity
            style={[styles.scanButton, { flex: 2, marginRight: 10, opacity: loading ? 0.7 : 1 }]}
            onPress={fetchScan}
            disabled={loading}
          >
            {loading ? (
              <View style={styles.buttonInner}>
                <ActivityIndicator color="#FFF" />
                <Text style={[styles.buttonText, { marginLeft: 10 }]}>SCANNING...</Text>
              </View>
            ) : (
              <Text style={styles.buttonText}>🚀 SCAN NETWORK</Text>
            )}
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.scanButton, { flex: 1, backgroundColor: '#34C759' }]}
            onPress={generateReport}
          >
            <Text style={styles.buttonText}>📄 REPORT</Text>
          </TouchableOpacity>
        </View>

        {/* ── Empty State ──────────────────────────────────────────────── */}
        {devices.length === 0 && !loading && (
          <View style={styles.emptyState}>
            <Text style={styles.emptyIcon}>📡</Text>
            <Text style={styles.emptyTitle}>No Devices Found</Text>
            <Text style={styles.emptySubtitle}>
              Tap "SCAN NETWORK" to discover devices on your network.
            </Text>
          </View>
        )}

        {/* ── Device List ──────────────────────────────────────────────── */}
        <FlatList
          data={devices}
          keyExtractor={(item) => item.mac}
          extraData={trustedMacs}
          showsVerticalScrollIndicator={false}
          renderItem={({ item }) => {
            const vendor = item.vendor || 'Unknown Device';
            const isTrusted = trustedMacs.includes(item.mac);
            const isUnknown = !isTrusted;
            const deviceIcon = getDeviceIcon(item.deviceType);
            const deviceLabel = getDeviceLabel(item.deviceType);

            return (
              <TouchableOpacity
                activeOpacity={0.6}
                onPress={() => toggleTrust(item.mac)}
                onLongPress={() => inspectDevice(item.ip)}
                delayLongPress={500}
              >
                <View style={[styles.card, isUnknown ? styles.intruderCard : styles.safeCard]}>

                  {/* Device Type Icon */}
                  <View style={styles.iconContainer}>
                    <Text style={styles.deviceIcon}>{deviceIcon}</Text>
                    <Text style={styles.typeLabel}>{deviceLabel}</Text>
                  </View>

                  {/* Device Info */}
                  <View style={styles.cardBody}>
                    <View style={styles.cardHeader}>
                      <View style={styles.statusRow}>
                        <View style={[styles.statusDot, { backgroundColor: isTrusted ? '#30D158' : '#FF453A' }]} />
                        <Text style={[styles.statusLabel, { color: isTrusted ? '#30D158' : '#FF453A' }]}>
                          {isTrusted ? 'TRUSTED' : 'UNKNOWN'}
                        </Text>
                      </View>

                      {isUnknown && (
                        <View style={styles.actionRow}>
                          <View style={styles.riskBadge}>
                            <Text style={styles.riskText}>REVIEW</Text>
                          </View>
                          <TouchableOpacity
                            style={styles.keyButton}
                            onPress={() => auditDevice(item.ip)}
                          >
                            <Text style={{ fontSize: 14 }}>🔐</Text>
                          </TouchableOpacity>
                        </View>
                      )}
                    </View>

                    <Text style={styles.deviceName} numberOfLines={1}>{vendor}</Text>
                    <Text style={styles.deviceIp}>{item.ip}</Text>
                    <Text style={styles.macText}>{item.mac}</Text>

                    {isUnknown && (
                      <Text style={styles.hintText}>Tap to trust • Long press to inspect • 🔐 to audit</Text>
                    )}
                    {isTrusted && (
                      <Text style={[styles.hintText, { color: '#30D158' }]}>Tap to untrust • Long press to inspect</Text>
                    )}
                  </View>
                </View>
              </TouchableOpacity>
            );
          }}
        />
      </View>
    </SafeAreaView>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STYLES
// ═══════════════════════════════════════════════════════════════════════════════

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000000',
  },

  // Header
  header: {
    padding: 20,
    paddingTop: Platform.OS === 'android' ? 50 : 60,
    backgroundColor: '#0D0D0D',
    borderBottomWidth: 1,
    borderBottomColor: '#1C1C1E',
  },
  title: {
    fontSize: 32,
    fontWeight: '900',
    color: '#FFFFFF',
    letterSpacing: 0.5,
  },
  subtitle: {
    color: '#8E8E93',
    marginTop: 4,
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  scanTime: {
    color: '#48484A',
    marginTop: 3,
    fontSize: 10,
    fontWeight: '500',
  },

  // Banner
  banner: {
    backgroundColor: '#FF453A',
    padding: 10,
    alignItems: 'center',
  },
  bannerText: {
    color: '#FFF',
    fontWeight: 'bold',
    fontSize: 13,
  },

  // Content
  content: {
    padding: 16,
    flex: 1,
  },

  // Buttons
  buttonRow: {
    flexDirection: 'row',
    marginBottom: 20,
  },
  scanButton: {
    backgroundColor: '#0A84FF',
    padding: 16,
    borderRadius: 14,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#0A84FF',
    shadowOpacity: 0.4,
    shadowRadius: 10,
    shadowOffset: { width: 0, height: 4 },
    elevation: 8,
  },
  buttonInner: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  buttonText: {
    fontWeight: '800',
    fontSize: 15,
    color: '#FFF',
  },

  // Empty State
  emptyState: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    paddingBottom: 100,
  },
  emptyIcon: {
    fontSize: 64,
    marginBottom: 16,
  },
  emptyTitle: {
    color: '#FFF',
    fontSize: 20,
    fontWeight: '800',
    marginBottom: 8,
  },
  emptySubtitle: {
    color: '#636366',
    fontSize: 14,
    textAlign: 'center',
    paddingHorizontal: 40,
  },

  // Cards
  card: {
    padding: 14,
    borderRadius: 16,
    marginBottom: 12,
    flexDirection: 'row',
    borderWidth: 1,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 4,
  },
  intruderCard: {
    backgroundColor: 'rgba(40, 8, 8, 0.9)',
    borderColor: 'rgba(255, 69, 58, 0.25)',
  },
  safeCard: {
    backgroundColor: 'rgba(8, 40, 8, 0.9)',
    borderColor: 'rgba(48, 209, 88, 0.25)',
  },

  // Icon column
  iconContainer: {
    marginRight: 12,
    alignItems: 'center',
    justifyContent: 'center',
    width: 44,
  },
  deviceIcon: {
    fontSize: 26,
  },
  typeLabel: {
    color: '#636366',
    fontSize: 7,
    fontWeight: '800',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginTop: 4,
    textAlign: 'center',
  },

  // Card body
  cardBody: {
    flex: 1,
  },
  cardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statusDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    marginRight: 5,
  },
  statusLabel: {
    fontSize: 9,
    fontWeight: '900',
    letterSpacing: 1.2,
  },
  actionRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  riskBadge: {
    backgroundColor: '#FF453A',
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  riskText: {
    color: '#FFF',
    fontSize: 8,
    fontWeight: '900',
    letterSpacing: 0.5,
  },
  keyButton: {
    backgroundColor: 'rgba(255,255,255,0.08)',
    borderRadius: 10,
    padding: 4,
    marginLeft: 6,
  },

  // Text
  deviceName: {
    color: '#FFF',
    fontSize: 15,
    fontWeight: '700',
  },
  deviceIp: {
    color: '#AEAEB2',
    fontSize: 13,
    marginTop: 2,
  },
  macText: {
    color: '#48484A',
    fontSize: 10,
    marginTop: 3,
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  hintText: {
    color: '#FF453A',
    fontSize: 9,
    marginTop: 5,
    fontStyle: 'italic',
    opacity: 0.7,
  },
});