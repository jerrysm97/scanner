/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Mobile v3.0 — Production-Ready React Native App
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Features:
 *  ► Physical device support (connects via LAN IP)
 *  ► AsyncStorage persistence for trusted devices
 *  ► Network scanning with device classification
 *  ► Deep scan (long-press any device)
 *  ► Credential audit (tap 🔐 on intruder cards)
 *  ► Honeypot intrusion detection (polls every 10s)
 *  ► Security report sharing (via Share API)
 *  ► Dark theme with animated UI
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
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
  Animated,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

// ═══════════════════════════════════════════════════════════════════════════════
//  TYPES
// ═══════════════════════════════════════════════════════════════════════════════

interface Device {
  ip: string;
  mac: string;
  vendor?: string;
  type?: string;
  status?: string;
  risk?: string;
  scan_mode?: string;
}

interface HoneypotLog {
  ip: string;
  timestamp: string;
  port: number;
  message: string;
}

interface DeepScanResult {
  ip: string;
  hostname: string;
  open_ports: { port: number; banner: string }[];
  port_count: number;
  risk_level: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const STORAGE_KEYS = {
  TRUSTED_MACS: '@sentinel_trusted_macs',
  LAST_SCAN: '@sentinel_last_scan',
  DEVICES: '@sentinel_devices',
};

const HONEYPOT_POLL_INTERVAL = 10000; // 10 seconds

// ═══════════════════════════════════════════════════════════════════════════════
//  APP COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [trustedMacs, setTrustedMacs] = useState<string[]>([]);
  const [honeypotLogs, setHoneypotLogs] = useState<HoneypotLog[]>([]);
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);
  const [scanMode, setScanMode] = useState<string>('—');
  const [subnet, setSubnet] = useState<string>('—');

  // Banner animation
  const bannerAnim = useRef(new Animated.Value(0)).current;

  // ── Connection ──────────────────────────────────────────────────────────────
  // Use your computer's LAN IP so physical phones can reach the backend.
  // Emulator uses 10.0.2.2 to reach the host machine.
  const BASE_URL = Platform.OS === 'android'
    ? __DEV__
      ? 'http://192.168.1.103:3000'   // Physical phone or emulator on same LAN
      : 'http://192.168.1.103:3000'
    : 'http://localhost:3000';

  // ── Load persisted data on startup ──────────────────────────────────────────
  useEffect(() => {
    const loadPersistedData = async () => {
      try {
        const [storedMacs, storedTime, storedDevices] = await Promise.all([
          AsyncStorage.getItem(STORAGE_KEYS.TRUSTED_MACS),
          AsyncStorage.getItem(STORAGE_KEYS.LAST_SCAN),
          AsyncStorage.getItem(STORAGE_KEYS.DEVICES),
        ]);
        if (storedMacs) setTrustedMacs(JSON.parse(storedMacs));
        if (storedTime) setLastScanTime(storedTime);
        if (storedDevices) setDevices(JSON.parse(storedDevices));
      } catch (e) {
        console.error('Failed to load persisted data:', e);
      }
    };
    loadPersistedData();
  }, []);

  // ── Honeypot Polling — every 10 seconds ─────────────────────────────────────
  useEffect(() => {
    const pollHoneypot = async () => {
      try {
        const resp = await fetch(`${BASE_URL}/api/honeypot`);
        const logs: HoneypotLog[] = await resp.json();
        setHoneypotLogs(logs);

        // Animate banner in/out
        Animated.timing(bannerAnim, {
          toValue: logs.length > 0 ? 1 : 0,
          duration: 300,
          useNativeDriver: false,
        }).start();
      } catch {
        // Server not reachable — ignore
      }
    };

    pollHoneypot(); // Immediate first poll
    const interval = setInterval(pollHoneypot, HONEYPOT_POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [BASE_URL]);

  // ── Network Scan ────────────────────────────────────────────────────────────
  const fetchScan = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${BASE_URL}/api/scan`);
      const data = await response.json();

      if (data.devices && data.devices.length > 0) {
        setDevices(data.devices);
        setScanMode(data.scan_mode || 'passive');
        setSubnet(data.subnet || '—');

        const now = new Date().toLocaleTimeString();
        setLastScanTime(now);

        // Persist scan results
        await Promise.all([
          AsyncStorage.setItem(STORAGE_KEYS.LAST_SCAN, now),
          AsyncStorage.setItem(STORAGE_KEYS.DEVICES, JSON.stringify(data.devices)),
        ]);
      } else {
        Alert.alert('Scan Complete', data.message || 'No devices found.');
      }
    } catch (error: any) {
      Alert.alert(
        '⚠️ Connection Error',
        `Cannot reach the Sentinel server at:\n${BASE_URL}\n\nMake sure:\n1. Backend is running (node server.js)\n2. Phone and computer are on the same WiFi\n3. IP address is correct`
      );
    } finally {
      setLoading(false);
    }
  }, [BASE_URL]);

  // ── Deep Scan (long-press) ──────────────────────────────────────────────────
  const deepScan = useCallback(async (ip: string) => {
    Alert.alert('🔍 Deep Scan', `Scanning ${ip}...\nThis may take a few seconds.`);

    try {
      const response = await fetch(`${BASE_URL}/api/inspect?ip=${ip}`);
      const data: DeepScanResult = await response.json();

      if (data.error) {
        Alert.alert('Scan Error', data.error);
        return;
      }

      const portList = data.open_ports?.length > 0
        ? data.open_ports.map(p => `  • Port ${p.port}${p.banner ? ` — ${p.banner}` : ''}`).join('\n')
        : '  None found';

      Alert.alert(
        `🔍 Deep Scan: ${ip}`,
        `Hostname: ${data.hostname}\n` +
        `Open Ports (${data.port_count}):\n${portList}\n\n` +
        `Risk Level: ${riskEmoji(data.risk_level)} ${data.risk_level}`
      );
    } catch {
      Alert.alert('Error', 'Deep scan failed. Is the server running?');
    }
  }, [BASE_URL]);

  // ── Credential Audit (tap 🔐) ──────────────────────────────────────────────
  const auditCredentials = useCallback(async (ip: string) => {
    Alert.alert('🔐 Auditing', `Checking default credentials on ${ip}...`);

    try {
      const response = await fetch(`${BASE_URL}/api/audit?ip=${ip}`);
      const data = await response.json();

      if (data.status === 'VULNERABLE') {
        const creds = data.details
          .filter((d: any) => d.status === 'VULNERABLE')
          .map((d: any) => `  ⚠️ ${d.credential}`)
          .join('\n');

        Alert.alert(
          '🚨 VULNERABLE!',
          `Device ${ip} accepts default credentials!\n\n${creds}\n\nChange these passwords immediately!`
        );
      } else {
        Alert.alert(
          '✅ Secure',
          data.message || `Device ${ip} rejected all default credentials.`
        );
      }
    } catch {
      Alert.alert('Error', 'Credential audit failed. Is the server running?');
    }
  }, [BASE_URL]);

  // ── Trust Toggle ────────────────────────────────────────────────────────────
  const toggleTrust = useCallback(async (mac: string) => {
    const updated = trustedMacs.includes(mac)
      ? trustedMacs.filter(m => m !== mac)
      : [...trustedMacs, mac];

    setTrustedMacs(updated);

    try {
      await AsyncStorage.setItem(STORAGE_KEYS.TRUSTED_MACS, JSON.stringify(updated));
    } catch (e) {
      console.error('Failed to save trusted devices:', e);
    }
  }, [trustedMacs]);

  // ── Generate Security Report ────────────────────────────────────────────────
  const generateReport = useCallback(async () => {
    const trusted = devices.filter(d => trustedMacs.includes(d.mac));
    const intruders = devices.filter(d => !trustedMacs.includes(d.mac));

    const report = [
      `══════════════════════════════════════`,
      `   🛡️ SENTINEL SECURITY REPORT`,
      `══════════════════════════════════════`,
      `📅 Generated: ${new Date().toLocaleString()}`,
      `📡 Subnet: ${subnet}`,
      `🔍 Scan Mode: ${scanMode}`,
      `📊 Total Devices: ${devices.length}`,
      `✅ Trusted: ${trusted.length}`,
      `⚠️ Untrusted: ${intruders.length}`,
      `🪤 Honeypot Triggers: ${honeypotLogs.length}`,
      ``,
      `── Trusted Devices ─────────────────`,
      ...trusted.map(d => `  ✅ ${d.ip} | ${d.mac} | ${d.vendor || 'Unknown'}`),
      ``,
      `── Untrusted Devices ───────────────`,
      ...intruders.map(d => `  ⚠️ ${d.ip} | ${d.mac} | ${d.vendor || 'Unknown'}`),
    ];

    if (honeypotLogs.length > 0) {
      report.push(``, `── Honeypot Intrusions ─────────────`);
      honeypotLogs.forEach(log => {
        report.push(`  🪤 ${log.ip} at ${log.timestamp}`);
      });
    }

    report.push(``, `══════════════════════════════════════`);

    try {
      await Share.share({
        message: report.join('\n'),
        title: 'Sentinel Security Report',
      });
    } catch {
      Alert.alert('Error', 'Failed to share report.');
    }
  }, [devices, trustedMacs, honeypotLogs, subnet, scanMode]);

  // ── Helpers ─────────────────────────────────────────────────────────────────
  const riskEmoji = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return '🔴';
      case 'HIGH': return '🟠';
      case 'MEDIUM': return '🟡';
      default: return '🟢';
    }
  };

  const typeEmoji = (type: string) => {
    if (!type) return '📱';
    const t = type.toLowerCase();
    if (t.includes('router')) return '🌐';
    if (t.includes('apple')) return '🍎';
    if (t.includes('android')) return '📱';
    if (t.includes('camera')) return '📷';
    if (t.includes('printer')) return '🖨️';
    if (t.includes('smart home')) return '🏠';
    if (t.includes('google')) return '🔵';
    if (t.includes('raspberry')) return '🍓';
    if (t.includes('media')) return '📺';
    if (t.includes('iot')) return '⚡';
    if (t.includes('pc')) return '💻';
    return '📱';
  };

  // ── Render Device Card ──────────────────────────────────────────────────────
  const renderDevice = ({ item }: { item: Device }) => {
    const isTrusted = trustedMacs.includes(item.mac);
    const isIntruder = !isTrusted && devices.length > 0;

    return (
      <TouchableOpacity
        style={[
          styles.card,
          isTrusted ? styles.trustedCard : styles.intruderCard,
        ]}
        onLongPress={() => deepScan(item.ip)}
        activeOpacity={0.7}
      >
        {/* Header */}
        <View style={styles.cardHeader}>
          <Text style={styles.cardEmoji}>{typeEmoji(item.type || '')}</Text>
          <View style={styles.cardInfo}>
            <Text style={styles.cardIP}>{item.ip}</Text>
            <Text style={styles.cardType}>{item.type || 'Unknown Device'}</Text>
          </View>
          <View style={styles.cardActions}>
            {/* Credential Audit Button (only for non-trusted) */}
            {isIntruder && (
              <TouchableOpacity
                style={styles.auditBtn}
                onPress={() => auditCredentials(item.ip)}
              >
                <Text style={styles.auditBtnText}>🔐</Text>
              </TouchableOpacity>
            )}
            {/* Trust Toggle */}
            <TouchableOpacity
              style={[styles.trustBtn, isTrusted ? styles.trustedBtn : styles.untrustedBtn]}
              onPress={() => toggleTrust(item.mac)}
            >
              <Text style={styles.trustBtnText}>
                {isTrusted ? '✅' : '❌'}
              </Text>
            </TouchableOpacity>
          </View>
        </View>

        {/* Details */}
        <View style={styles.cardDetails}>
          <Text style={styles.cardMAC}>MAC: {item.mac}</Text>
          <Text style={styles.cardVendor}>{item.vendor || 'Unknown vendor'}</Text>
        </View>

        {/* Status Bar */}
        <View style={styles.cardStatus}>
          <Text style={[styles.statusBadge, isTrusted ? styles.trustedBadge : styles.intruderBadge]}>
            {isTrusted ? '✅ TRUSTED' : '⚠️ INTRUDER'}
          </Text>
          <Text style={styles.cardHint}>Long press → Deep Scan</Text>
        </View>
      </TouchableOpacity>
    );
  };

  // ── Main Render ─────────────────────────────────────────────────────────────
  const bannerHeight = bannerAnim.interpolate({
    inputRange: [0, 1],
    outputRange: [0, 60],
  });

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#0a0a0a" />

      {/* ── Honeypot Intrusion Banner ── */}
      <Animated.View style={[styles.intrusionBanner, { height: bannerHeight, opacity: bannerAnim }]}>
        <Text style={styles.intrusionText}>
          🚨 INTRUSION DETECTED — {honeypotLogs.length} connection(s) on honeypot!
        </Text>
      </Animated.View>

      {/* ── Header ── */}
      <View style={styles.header}>
        <Text style={styles.title}>🛡️ SENTINEL</Text>
        <Text style={styles.subtitle}>Network Security Monitor v3.0</Text>
        <View style={styles.statsRow}>
          <Text style={styles.stat}>📡 {subnet}</Text>
          <Text style={styles.stat}>🔍 {scanMode}</Text>
          <Text style={styles.stat}>🕐 {lastScanTime || '—'}</Text>
        </View>
        <View style={styles.statsRow}>
          <Text style={styles.stat}>📊 {devices.length} devices</Text>
          <Text style={styles.stat}>
            ✅ {devices.filter(d => trustedMacs.includes(d.mac)).length} trusted
          </Text>
          <Text style={styles.stat}>
            ⚠️ {devices.filter(d => !trustedMacs.includes(d.mac)).length} intruders
          </Text>
        </View>
      </View>

      {/* ── Device List ── */}
      <FlatList
        data={devices}
        keyExtractor={(item) => item.mac}
        renderItem={renderDevice}
        extraData={trustedMacs}
        contentContainerStyle={styles.list}
        ListEmptyComponent={
          <View style={styles.emptyState}>
            <Text style={styles.emptyEmoji}>📡</Text>
            <Text style={styles.emptyText}>No devices scanned yet.</Text>
            <Text style={styles.emptyHint}>Tap "SCAN NETWORK" to begin.</Text>
          </View>
        }
      />

      {/* ── Action Buttons ── */}
      <View style={styles.buttonRow}>
        <TouchableOpacity
          style={[styles.scanBtn, loading && styles.scanBtnDisabled]}
          onPress={fetchScan}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" size="small" />
          ) : (
            <Text style={styles.scanBtnText}>📡 SCAN NETWORK</Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.reportBtn}
          onPress={generateReport}
          disabled={devices.length === 0}
        >
          <Text style={styles.reportBtnText}>📋 REPORT</Text>
        </TouchableOpacity>
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
    backgroundColor: '#0a0a0a',
  },

  // ── Intrusion Banner ──
  intrusionBanner: {
    backgroundColor: '#dc2626',
    justifyContent: 'center',
    alignItems: 'center',
    overflow: 'hidden',
  },
  intrusionText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '800',
    letterSpacing: 0.5,
  },

  // ── Header ──
  header: {
    padding: 20,
    paddingBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#1a1a1a',
  },
  title: {
    fontSize: 28,
    fontWeight: '900',
    color: '#00ff88',
    letterSpacing: 2,
  },
  subtitle: {
    fontSize: 13,
    color: '#666',
    marginTop: 2,
    letterSpacing: 0.5,
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 8,
  },
  stat: {
    fontSize: 12,
    color: '#888',
  },

  // ── Device List ──
  list: {
    padding: 12,
    paddingBottom: 100,
  },

  // ── Device Card ──
  card: {
    borderRadius: 12,
    padding: 14,
    marginBottom: 10,
    borderWidth: 1,
  },
  trustedCard: {
    backgroundColor: '#0d1f12',
    borderColor: '#1a3d20',
  },
  intruderCard: {
    backgroundColor: '#1f0d0d',
    borderColor: '#3d1a1a',
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  cardEmoji: {
    fontSize: 28,
    marginRight: 12,
  },
  cardInfo: {
    flex: 1,
  },
  cardIP: {
    fontSize: 16,
    fontWeight: '700',
    color: '#fff',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  cardType: {
    fontSize: 12,
    color: '#aaa',
    marginTop: 2,
  },
  cardActions: {
    flexDirection: 'row',
    gap: 8,
  },
  auditBtn: {
    padding: 8,
    borderRadius: 8,
    backgroundColor: '#2a1a00',
    borderWidth: 1,
    borderColor: '#4a3000',
  },
  auditBtnText: {
    fontSize: 18,
  },
  trustBtn: {
    padding: 8,
    borderRadius: 8,
    borderWidth: 1,
  },
  trustedBtn: {
    backgroundColor: '#0d2818',
    borderColor: '#1a5030',
  },
  untrustedBtn: {
    backgroundColor: '#280d0d',
    borderColor: '#501a1a',
  },
  trustBtnText: {
    fontSize: 18,
  },
  cardDetails: {
    marginTop: 8,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: '#1a1a1a',
  },
  cardMAC: {
    fontSize: 11,
    color: '#666',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  cardVendor: {
    fontSize: 11,
    color: '#888',
    marginTop: 2,
  },
  cardStatus: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 8,
  },
  statusBadge: {
    fontSize: 11,
    fontWeight: '700',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    overflow: 'hidden',
  },
  trustedBadge: {
    color: '#00ff88',
    backgroundColor: '#0a2a14',
  },
  intruderBadge: {
    color: '#ff4444',
    backgroundColor: '#2a0a0a',
  },
  cardHint: {
    fontSize: 10,
    color: '#444',
    fontStyle: 'italic',
  },

  // ── Empty State ──
  emptyState: {
    alignItems: 'center',
    paddingTop: 80,
  },
  emptyEmoji: {
    fontSize: 48,
    marginBottom: 12,
  },
  emptyText: {
    color: '#666',
    fontSize: 16,
  },
  emptyHint: {
    color: '#444',
    fontSize: 13,
    marginTop: 4,
  },

  // ── Buttons ──
  buttonRow: {
    flexDirection: 'row',
    padding: 16,
    paddingBottom: Platform.OS === 'ios' ? 30 : 16,
    gap: 10,
    backgroundColor: '#0a0a0a',
    borderTopWidth: 1,
    borderTopColor: '#1a1a1a',
  },
  scanBtn: {
    flex: 2,
    backgroundColor: '#00cc66',
    paddingVertical: 14,
    borderRadius: 10,
    alignItems: 'center',
  },
  scanBtnDisabled: {
    backgroundColor: '#004422',
  },
  scanBtnText: {
    color: '#000',
    fontSize: 16,
    fontWeight: '800',
    letterSpacing: 1,
  },
  reportBtn: {
    flex: 1,
    backgroundColor: '#1a1a2e',
    paddingVertical: 14,
    borderRadius: 10,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#2a2a4e',
  },
  reportBtnText: {
    color: '#aaa',
    fontSize: 14,
    fontWeight: '700',
  },
});