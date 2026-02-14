/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Mobile v4.0 — Enterprise-Grade React Native App
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Features:
 *  ► Physical device support via LAN IP
 *  ► Database status indicator (total devices logged in Supabase)
 *  ► AsyncStorage persistence for trusted devices
 *  ► Long-press device card → Credential Audit
 *  ► Honeypot intrusion detection (polls every 10s)
 *  ► Deep scan via swipe/tap
 *  ► Security report sharing
 *  ► Professional dark mode theme
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
  last_seen?: string;
}

interface HoneypotLog {
  ip: string;
  timestamp: string;
  port: number;
  message: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const STORAGE_KEYS = {
  TRUSTED_MACS: '@sentinel_trusted_macs',
  LAST_SCAN: '@sentinel_last_scan',
  DEVICES: '@sentinel_devices',
};

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
  const [dbTotal, setDbTotal] = useState<number>(0);
  const [dbConnected, setDbConnected] = useState<boolean>(false);

  const bannerAnim = useRef(new Animated.Value(0)).current;

  // ── Connection ──────────────────────────────────────────────────────────────
  // IMPORTANT: Replace with YOUR computer's local IP address.
  // Find it: macOS → System Settings → Wi-Fi → Details → IP Address
  //          Windows → ipconfig → IPv4 Address
  const BASE_URL = 'http://192.168.1.103:3000';

  // ── Load Persisted Data ─────────────────────────────────────────────────────
  useEffect(() => {
    const load = async () => {
      try {
        const [macs, time, devs] = await Promise.all([
          AsyncStorage.getItem(STORAGE_KEYS.TRUSTED_MACS),
          AsyncStorage.getItem(STORAGE_KEYS.LAST_SCAN),
          AsyncStorage.getItem(STORAGE_KEYS.DEVICES),
        ]);
        if (macs) setTrustedMacs(JSON.parse(macs));
        if (time) setLastScanTime(time);
        if (devs) setDevices(JSON.parse(devs));
      } catch (e) {
        console.error('Load error:', e);
      }
    };
    load();
  }, []);

  // ── Honeypot Polling (every 10s) ────────────────────────────────────────────
  useEffect(() => {
    const poll = async () => {
      try {
        const resp = await fetch(`${BASE_URL}/api/honeypot`);
        const logs: HoneypotLog[] = await resp.json();
        setHoneypotLogs(logs);
        Animated.timing(bannerAnim, {
          toValue: logs.length > 0 ? 1 : 0,
          duration: 300,
          useNativeDriver: false,
        }).start();
      } catch { /* server unreachable */ }
    };

    poll();
    const interval = setInterval(poll, 10000);
    return () => clearInterval(interval);
  }, [BASE_URL]);

  // ── Check Database Status on Mount ──────────────────────────────────────────
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const resp = await fetch(`${BASE_URL}/api/status`);
        const data = await resp.json();
        setDbConnected(data.supabase_connected || false);
        setDbTotal(data.total_devices_logged || 0);
      } catch { /* ignore */ }
    };
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
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

        // Database info
        if (data.database) {
          setDbTotal(data.database.total_logged || 0);
        }

        const now = new Date().toLocaleTimeString();
        setLastScanTime(now);

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
        `Cannot reach server at:\n${BASE_URL}\n\n` +
        `Make sure:\n` +
        `1. Backend is running (node server.js)\n` +
        `2. Phone & computer on same WiFi\n` +
        `3. IP address is correct`
      );
    } finally {
      setLoading(false);
    }
  }, [BASE_URL]);

  // ── Deep Scan ───────────────────────────────────────────────────────────────
  const deepScan = useCallback(async (ip: string) => {
    try {
      const response = await fetch(`${BASE_URL}/api/inspect?ip=${ip}`);
      const data = await response.json();

      if (data.error) {
        Alert.alert('Error', data.error);
        return;
      }

      const portList = data.open_ports?.length > 0
        ? data.open_ports.map((p: any) => `  • Port ${p.port}${p.banner ? ` — ${p.banner}` : ''}`).join('\n')
        : '  None found';

      Alert.alert(
        `🔍 Deep Scan: ${ip}`,
        `Hostname: ${data.hostname}\n` +
        `Open Ports (${data.port_count}):\n${portList}\n\n` +
        `Risk Level: ${data.risk_level}`
      );
    } catch {
      Alert.alert('Error', 'Deep scan failed.');
    }
  }, [BASE_URL]);

  // ── Credential Audit (LONG PRESS) ──────────────────────────────────────────
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
      Alert.alert('Error', 'Credential audit failed.');
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
      console.error('Save error:', e);
    }
  }, [trustedMacs]);

  // ── Report ──────────────────────────────────────────────────────────────────
  const generateReport = useCallback(async () => {
    const trusted = devices.filter(d => trustedMacs.includes(d.mac));
    const intruders = devices.filter(d => !trustedMacs.includes(d.mac));

    const report = [
      `═══════════════════════════════════`,
      `  🛡️ SENTINEL SECURITY REPORT`,
      `═══════════════════════════════════`,
      `📅 ${new Date().toLocaleString()}`,
      `📡 Subnet: ${subnet}  |  Mode: ${scanMode}`,
      `📊 Total: ${devices.length}  |  DB Logged: ${dbTotal}`,
      `✅ Trusted: ${trusted.length}  |  ⚠️ Untrusted: ${intruders.length}`,
      `🪤 Honeypot Triggers: ${honeypotLogs.length}`,
      ``,
      `── Trusted ─────────────────────`,
      ...trusted.map(d => `  ✅ ${d.ip} | ${d.mac} | ${d.vendor || '?'}`),
      ``,
      `── Untrusted ───────────────────`,
      ...intruders.map(d => `  ⚠️ ${d.ip} | ${d.mac} | ${d.vendor || '?'}`),
    ];

    if (honeypotLogs.length > 0) {
      report.push(``, `── Honeypot ────────────────────`);
      honeypotLogs.forEach(l => report.push(`  🪤 ${l.ip} at ${l.timestamp}`));
    }

    try {
      await Share.share({ message: report.join('\n'), title: 'Sentinel Report' });
    } catch { /* ignore */ }
  }, [devices, trustedMacs, honeypotLogs, subnet, scanMode, dbTotal]);

  // ── Emoji Helpers ───────────────────────────────────────────────────────────
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

    return (
      <TouchableOpacity
        style={[styles.card, isTrusted ? styles.trustedCard : styles.intruderCard]}
        onPress={() => deepScan(item.ip)}
        onLongPress={() => auditCredentials(item.ip)}
        delayLongPress={600}
        activeOpacity={0.7}
      >
        {/* Header Row */}
        <View style={styles.cardHeader}>
          <Text style={styles.cardEmoji}>{typeEmoji(item.type || '')}</Text>
          <View style={styles.cardInfo}>
            <Text style={styles.cardIP}>{item.ip}</Text>
            <Text style={styles.cardType}>{item.type || 'Unknown Device'}</Text>
          </View>
          <TouchableOpacity
            style={[styles.trustBtn, isTrusted ? styles.trustedBtn : styles.untrustedBtn]}
            onPress={() => toggleTrust(item.mac)}
          >
            <Text style={styles.trustBtnText}>{isTrusted ? '✅' : '❌'}</Text>
          </TouchableOpacity>
        </View>

        {/* Details */}
        <View style={styles.cardDetails}>
          <Text style={styles.cardMAC}>{item.mac}</Text>
          <Text style={styles.cardVendor}>{item.vendor || 'Unknown vendor'}</Text>
        </View>

        {/* Footer */}
        <View style={styles.cardFooter}>
          <Text style={[styles.badge, isTrusted ? styles.trustedBadge : styles.intruderBadge]}>
            {isTrusted ? '✅ TRUSTED' : '⚠️ INTRUDER'}
          </Text>
          <Text style={styles.hintText}>Tap → Scan  |  Hold → Audit 🔐</Text>
        </View>
      </TouchableOpacity>
    );
  };

  // ── Main Render ─────────────────────────────────────────────────────────────
  const bannerHeight = bannerAnim.interpolate({
    inputRange: [0, 1],
    outputRange: [0, 56],
  });

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#050505" />

      {/* ── Honeypot Alert Banner ── */}
      <Animated.View style={[styles.intrusionBanner, { height: bannerHeight, opacity: bannerAnim }]}>
        <Text style={styles.intrusionText}>
          🚨 INTRUSION DETECTED — {honeypotLogs.length} connection(s) on honeypot
        </Text>
      </Animated.View>

      {/* ── Header ── */}
      <View style={styles.header}>
        <View style={styles.titleRow}>
          <View>
            <Text style={styles.title}>🛡️ SENTINEL</Text>
            <Text style={styles.subtitle}>Enterprise Security Monitor v4.0</Text>
          </View>
          {/* Database Status Indicator */}
          <View style={styles.dbStatus}>
            <View style={[styles.dbDot, dbConnected ? styles.dbDotOn : styles.dbDotOff]} />
            <Text style={styles.dbText}>DB: {dbTotal}</Text>
          </View>
        </View>

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
            <Text style={styles.emptyTitle}>No Devices Scanned</Text>
            <Text style={styles.emptyHint}>Tap "SCAN NETWORK" to discover devices</Text>
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
            <ActivityIndicator color="#000" size="small" />
          ) : (
            <Text style={styles.scanBtnText}>📡 SCAN NETWORK</Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.reportBtn}
          onPress={generateReport}
          disabled={devices.length === 0}
        >
          <Text style={styles.reportBtnText}>📋</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STYLES — Professional Dark Mode
// ═══════════════════════════════════════════════════════════════════════════════

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#050505',
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
    fontSize: 13,
    fontWeight: '800',
    letterSpacing: 0.5,
  },

  // ── Header ──
  header: {
    paddingHorizontal: 20,
    paddingTop: 16,
    paddingBottom: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#151515',
  },
  titleRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  title: {
    fontSize: 26,
    fontWeight: '900',
    color: '#00ff88',
    letterSpacing: 2,
  },
  subtitle: {
    fontSize: 11,
    color: '#555',
    marginTop: 2,
    letterSpacing: 0.5,
  },
  dbStatus: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#111',
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#222',
  },
  dbDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: 6,
  },
  dbDotOn: {
    backgroundColor: '#00ff88',
  },
  dbDotOff: {
    backgroundColor: '#ff4444',
  },
  dbText: {
    color: '#888',
    fontSize: 12,
    fontWeight: '600',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  statsRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginTop: 8,
  },
  stat: {
    fontSize: 11,
    color: '#666',
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
    backgroundColor: '#0a1a0f',
    borderColor: '#153d20',
  },
  intruderCard: {
    backgroundColor: '#1a0a0a',
    borderColor: '#3d1515',
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  cardEmoji: {
    fontSize: 26,
    marginRight: 12,
  },
  cardInfo: {
    flex: 1,
  },
  cardIP: {
    fontSize: 16,
    fontWeight: '700',
    color: '#eee',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  cardType: {
    fontSize: 11,
    color: '#888',
    marginTop: 2,
  },
  trustBtn: {
    padding: 8,
    borderRadius: 8,
    borderWidth: 1,
  },
  trustedBtn: {
    backgroundColor: '#0a2818',
    borderColor: '#1a5030',
  },
  untrustedBtn: {
    backgroundColor: '#280a0a',
    borderColor: '#501515',
  },
  trustBtnText: {
    fontSize: 18,
  },
  cardDetails: {
    marginTop: 8,
    paddingTop: 8,
    borderTopWidth: 1,
    borderTopColor: '#151515',
  },
  cardMAC: {
    fontSize: 10,
    color: '#555',
    fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
  },
  cardVendor: {
    fontSize: 10,
    color: '#777',
    marginTop: 2,
  },
  cardFooter: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 8,
  },
  badge: {
    fontSize: 10,
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
  hintText: {
    fontSize: 9,
    color: '#333',
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
  emptyTitle: {
    color: '#555',
    fontSize: 16,
    fontWeight: '600',
  },
  emptyHint: {
    color: '#333',
    fontSize: 12,
    marginTop: 4,
  },

  // ── Buttons ──
  buttonRow: {
    flexDirection: 'row',
    padding: 16,
    paddingBottom: Platform.OS === 'ios' ? 30 : 16,
    gap: 10,
    backgroundColor: '#050505',
    borderTopWidth: 1,
    borderTopColor: '#151515',
  },
  scanBtn: {
    flex: 1,
    backgroundColor: '#00cc66',
    paddingVertical: 14,
    borderRadius: 10,
    alignItems: 'center',
  },
  scanBtnDisabled: {
    backgroundColor: '#003d1f',
  },
  scanBtnText: {
    color: '#000',
    fontSize: 15,
    fontWeight: '800',
    letterSpacing: 1,
  },
  reportBtn: {
    width: 52,
    backgroundColor: '#111',
    paddingVertical: 14,
    borderRadius: 10,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#222',
  },
  reportBtnText: {
    fontSize: 20,
  },
});