/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Mobile v5.0 — Production-Ready Enterprise App
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Enterprise Features:
 *  ► Settings Screen        — Change server IP dynamically (persisted)
 *  ► Skeleton Loader        — Animated placeholder during scans
 *  ► Toast Notifications    — Non-intrusive status messages (no Alert spam)
 *  ► Offline Handling       — Clean "Cannot Connect" screen with Retry
 *  ► Database Status        — Shows total devices logged in Supabase
 *  ► Long-Press Audit       — Credential audit via long press
 *  ► Honeypot Alerts        — Polls every 10s for intrusion events
 *  ► Report Sharing         — Export security report via Share API
 *  ► AsyncStorage           — Persists trusted devices & settings
 *
 *  Edge Cases Handled:
 *  - Server unreachable     → Offline screen with retry button
 *  - Empty scan results     → "No devices found" message
 *  - AsyncStorage failure   → Falls back to in-memory state
 *  - Invalid server URL     → Validation before saving
 *  - FlatList key collisions→ MAC used as unique key
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
  Modal,
  TextInput,
  Dimensions,
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
  last_seen?: string;
}

interface HoneypotLog {
  ip: string;
  timestamp: string;
  port: number;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const STORAGE_KEYS = {
  SERVER_URL: '@sentinel_server_url',
  TRUSTED_MACS: '@sentinel_trusted_macs',
  LAST_SCAN: '@sentinel_last_scan',
  DEVICES: '@sentinel_devices',
};

const DEFAULT_SERVER = 'http://192.168.1.103:3000';
const SCREEN_WIDTH = Dimensions.get('window').width;

// ═══════════════════════════════════════════════════════════════════════════════
//  TOAST COMPONENT — Non-intrusive notification bar
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Replaces Alert.alert with a slide-down toast that auto-dismisses.
 * Edge case: multiple toasts → latest one replaces the previous.
 */
function Toast({ message, type, visible }: { message: string; type: 'success' | 'error' | 'info'; visible: boolean }) {
  const translateY = useRef(new Animated.Value(-80)).current;

  useEffect(() => {
    if (visible) {
      Animated.sequence([
        Animated.timing(translateY, { toValue: 0, duration: 250, useNativeDriver: true }),
        Animated.delay(2500),
        Animated.timing(translateY, { toValue: -80, duration: 250, useNativeDriver: true }),
      ]).start();
    }
  }, [visible, message]);

  const bgColor = type === 'success' ? '#059669' : type === 'error' ? '#dc2626' : '#2563eb';

  return (
    <Animated.View style={[styles.toast, { backgroundColor: bgColor, transform: [{ translateY }] }]}>
      <Text style={styles.toastText}>{message}</Text>
    </Animated.View>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SKELETON LOADER — Animated placeholder during scans
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Renders 4 pulsing placeholder cards while scanning is in progress.
 * Provides visual feedback that the app is working (better than a spinner).
 */
function SkeletonLoader() {
  const pulseAnim = useRef(new Animated.Value(0.3)).current;

  useEffect(() => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, { toValue: 0.7, duration: 800, useNativeDriver: true }),
        Animated.timing(pulseAnim, { toValue: 0.3, duration: 800, useNativeDriver: true }),
      ])
    ).start();
  }, []);

  return (
    <View style={styles.skeletonContainer}>
      <Text style={styles.scanningTitle}>📡 Scanning Network...</Text>
      <Text style={styles.scanningHint}>Looking for devices on your WiFi</Text>
      {[1, 2, 3, 4].map(i => (
        <Animated.View key={i} style={[styles.skeletonCard, { opacity: pulseAnim }]}>
          <View style={styles.skeletonRow}>
            <View style={styles.skeletonCircle} />
            <View style={styles.skeletonLines}>
              <View style={[styles.skeletonLine, { width: '60%' }]} />
              <View style={[styles.skeletonLine, { width: '40%', marginTop: 6 }]} />
            </View>
          </View>
        </Animated.View>
      ))}
    </View>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OFFLINE SCREEN — Clean "Cannot Connect" with Retry
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Shown when the server is unreachable. Provides clear instructions and a Retry button.
 * Edge case: user taps retry rapidly → debounced by the loading state in parent.
 */
function OfflineScreen({ serverUrl, onRetry, onOpenSettings }: {
  serverUrl: string;
  onRetry: () => void;
  onOpenSettings: () => void;
}) {
  return (
    <View style={styles.offlineContainer}>
      <Text style={styles.offlineEmoji}>📡</Text>
      <Text style={styles.offlineTitle}>Cannot Connect to Server</Text>
      <Text style={styles.offlineMessage}>
        The Sentinel server at{'\n'}
        <Text style={styles.offlineUrl}>{serverUrl}</Text>
        {'\n'}is not reachable.
      </Text>
      <View style={styles.offlineChecklist}>
        <Text style={styles.offlineItem}>1. Is the backend running? (node server.js)</Text>
        <Text style={styles.offlineItem}>2. Are you on the same WiFi network?</Text>
        <Text style={styles.offlineItem}>3. Is the server IP address correct?</Text>
      </View>
      <TouchableOpacity style={styles.retryBtn} onPress={onRetry}>
        <Text style={styles.retryBtnText}>🔄 RETRY CONNECTION</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.settingsLink} onPress={onOpenSettings}>
        <Text style={styles.settingsLinkText}>⚙️ Change Server IP</Text>
      </TouchableOpacity>
    </View>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  APP COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

export default function App() {
  // ── State ───────────────────────────────────────────────────────────────────
  const [serverUrl, setServerUrl] = useState<string>(DEFAULT_SERVER);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [trustedMacs, setTrustedMacs] = useState<string[]>([]);
  const [honeypotLogs, setHoneypotLogs] = useState<HoneypotLog[]>([]);
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);
  const [scanMode, setScanMode] = useState<string>('—');
  const [subnet, setSubnet] = useState<string>('—');
  const [dbTotal, setDbTotal] = useState<number>(0);
  const [dbConnected, setDbConnected] = useState<boolean>(false);
  const [isOffline, setIsOffline] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsInput, setSettingsInput] = useState('');

  // Toast state
  const [toastMsg, setToastMsg] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error' | 'info'>('info');
  const [toastKey, setToastKey] = useState(0);

  const bannerAnim = useRef(new Animated.Value(0)).current;

  // ── Show Toast ──────────────────────────────────────────────────────────────
  const showToast = useCallback((message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setToastMsg(message);
    setToastType(type);
    setToastKey(prev => prev + 1);
  }, []);

  // ── Load Persisted Data on Startup ──────────────────────────────────────────
  useEffect(() => {
    const loadPersistedData = async () => {
      try {
        const [url, macs, time, devs] = await Promise.all([
          AsyncStorage.getItem(STORAGE_KEYS.SERVER_URL),
          AsyncStorage.getItem(STORAGE_KEYS.TRUSTED_MACS),
          AsyncStorage.getItem(STORAGE_KEYS.LAST_SCAN),
          AsyncStorage.getItem(STORAGE_KEYS.DEVICES),
        ]);
        if (url) setServerUrl(url);
        if (macs) setTrustedMacs(JSON.parse(macs));
        if (time) setLastScanTime(time);
        if (devs) setDevices(JSON.parse(devs));
      } catch (e) {
        console.error('Persisted data load error:', e);
      }
    };
    loadPersistedData();
  }, []);

  // ── Honeypot Polling ────────────────────────────────────────────────────────
  useEffect(() => {
    const pollHoneypot = async () => {
      try {
        const resp = await fetch(`${serverUrl}/api/honeypot`);
        const logs: HoneypotLog[] = await resp.json();
        setHoneypotLogs(logs);
        Animated.timing(bannerAnim, {
          toValue: logs.length > 0 ? 1 : 0,
          duration: 300,
          useNativeDriver: false,
        }).start();
      } catch { /* server unreachable — handled elsewhere */ }
    };

    pollHoneypot();
    const interval = setInterval(pollHoneypot, 10000);
    return () => clearInterval(interval);
  }, [serverUrl]);

  // ── Server Status Check ─────────────────────────────────────────────────────
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const resp = await fetch(`${serverUrl}/api/status`);
        const data = await resp.json();
        setDbConnected(data.supabase_connected || false);
        setDbTotal(data.total_devices_logged || 0);
        setIsOffline(false);
      } catch {
        setIsOffline(true);
      }
    };
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, [serverUrl]);

  // ── Network Scan ────────────────────────────────────────────────────────────
  const fetchScan = useCallback(async () => {
    setLoading(true);
    setIsOffline(false);

    try {
      const response = await fetch(`${serverUrl}/api/scan`);
      const scanData = await response.json();

      if (scanData.devices && scanData.devices.length > 0) {
        setDevices(scanData.devices);
        setScanMode(scanData.scan_mode || 'passive');
        setSubnet(scanData.subnet || '—');

        if (scanData.database) {
          setDbTotal(scanData.database.total_logged || 0);
        }

        const now = new Date().toLocaleTimeString();
        setLastScanTime(now);

        // Persist results
        await Promise.all([
          AsyncStorage.setItem(STORAGE_KEYS.LAST_SCAN, now),
          AsyncStorage.setItem(STORAGE_KEYS.DEVICES, JSON.stringify(scanData.devices)),
        ]);

        showToast(`✅ Found ${scanData.devices.length} device(s)`, 'success');
      } else {
        showToast('No devices found on this network.', 'info');
      }
    } catch {
      setIsOffline(true);
    } finally {
      setLoading(false);
    }
  }, [serverUrl, showToast]);

  // ── Deep Scan (tap) ─────────────────────────────────────────────────────────
  const deepScan = useCallback(async (ip: string) => {
    showToast(`🔍 Scanning ${ip}...`, 'info');

    try {
      const response = await fetch(`${serverUrl}/api/inspect?ip=${ip}`);
      const data = await response.json();

      if (data.error) {
        showToast(`Error: ${data.error}`, 'error');
        return;
      }

      const portList = data.open_ports?.length > 0
        ? data.open_ports.map((p: any) => `  • Port ${p.port}${p.banner ? ` (${p.banner})` : ''}`).join('\n')
        : '  None found';

      Alert.alert(
        `🔍 ${ip}`,
        `Host: ${data.hostname}\nPorts (${data.port_count}):\n${portList}\n\nRisk: ${data.risk_level}`
      );
    } catch {
      showToast('Deep scan failed — server unreachable', 'error');
    }
  }, [serverUrl, showToast]);

  // ── Credential Audit (long press) ──────────────────────────────────────────
  const auditCredentials = useCallback(async (ip: string) => {
    showToast(`🔐 Auditing ${ip}...`, 'info');

    try {
      const response = await fetch(`${serverUrl}/api/audit?ip=${ip}`);
      const data = await response.json();

      if (data.status === 'VULNERABLE') {
        const creds = data.details
          .filter((d: any) => d.status === 'VULNERABLE')
          .map((d: any) => `  ⚠️ ${d.credential}`)
          .join('\n');

        Alert.alert(
          '🚨 VULNERABLE!',
          `${ip} accepts default credentials!\n\n${creds}\n\nChange these immediately!`
        );
      } else {
        showToast(`✅ ${ip}: ${data.message}`, 'success');
      }
    } catch {
      showToast('Audit failed — server unreachable', 'error');
    }
  }, [serverUrl, showToast]);

  // ── Trust Toggle ────────────────────────────────────────────────────────────
  const toggleTrust = useCallback(async (mac: string) => {
    const isTrusted = trustedMacs.includes(mac);
    const updated = isTrusted
      ? trustedMacs.filter(m => m !== mac)
      : [...trustedMacs, mac];

    setTrustedMacs(updated);
    showToast(isTrusted ? '❌ Removed from trusted' : '✅ Marked as trusted', 'info');

    try {
      await AsyncStorage.setItem(STORAGE_KEYS.TRUSTED_MACS, JSON.stringify(updated));
    } catch (e) {
      console.error('Trust save error:', e);
    }
  }, [trustedMacs, showToast]);

  // ── Save Server URL ────────────────────────────────────────────────────────
  const saveServerUrl = useCallback(async () => {
    const url = settingsInput.trim();

    // Basic URL validation
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      showToast('URL must start with http:// or https://', 'error');
      return;
    }

    setServerUrl(url);
    setSettingsOpen(false);
    setIsOffline(false);

    try {
      await AsyncStorage.setItem(STORAGE_KEYS.SERVER_URL, url);
      showToast(`✅ Server set to ${url}`, 'success');
    } catch {
      showToast('Failed to save settings', 'error');
    }
  }, [settingsInput, showToast]);

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
      `📊 Devices: ${devices.length}  |  DB Total: ${dbTotal}`,
      `✅ Trusted: ${trusted.length}  |  ⚠️ Untrusted: ${intruders.length}`,
      `🪤 Honeypot: ${honeypotLogs.length} trigger(s)`,
      ``,
      ...trusted.map(d => `✅ ${d.ip} | ${d.mac} | ${d.vendor || '?'}`),
      ``,
      ...intruders.map(d => `⚠️ ${d.ip} | ${d.mac} | ${d.vendor || '?'}`),
    ];

    try {
      await Share.share({ message: report.join('\n') });
    } catch { /* cancelled */ }
  }, [devices, trustedMacs, honeypotLogs, subnet, scanMode, dbTotal]);

  // ── Helpers ─────────────────────────────────────────────────────────────────
  const typeEmoji = (type: string) => {
    if (!type) return '📱';
    const t = type.toLowerCase();
    if (t.includes('router')) return '🌐';
    if (t.includes('apple')) return '🍎';
    if (t.includes('android')) return '📱';
    if (t.includes('camera')) return '📷';
    if (t.includes('printer')) return '🖨️';
    if (t.includes('google')) return '🔵';
    if (t.includes('pc')) return '💻';
    if (t.includes('iot')) return '⚡';
    if (t.includes('media')) return '📺';
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
        <View style={styles.cardHeader}>
          <Text style={styles.cardEmoji}>{typeEmoji(item.type || '')}</Text>
          <View style={styles.cardInfo}>
            <Text style={styles.cardIP}>{item.ip}</Text>
            <Text style={styles.cardType}>{item.type || 'Unknown Device'}</Text>
          </View>
          <TouchableOpacity
            style={[styles.trustBtn, isTrusted ? styles.trustedBtnBg : styles.untrustedBtnBg]}
            onPress={() => toggleTrust(item.mac)}
          >
            <Text style={styles.trustBtnText}>{isTrusted ? '✅' : '❌'}</Text>
          </TouchableOpacity>
        </View>

        <View style={styles.cardDetails}>
          <Text style={styles.cardMAC}>{item.mac}</Text>
          <Text style={styles.cardVendor}>{item.vendor || 'Unknown vendor'}</Text>
        </View>

        <View style={styles.cardFooter}>
          <Text style={[styles.badge, isTrusted ? styles.trustedBadge : styles.intruderBadge]}>
            {isTrusted ? '✅ TRUSTED' : '⚠️ INTRUDER'}
          </Text>
          <Text style={styles.hintText}>Tap → Scan  |  Hold → Audit</Text>
        </View>
      </TouchableOpacity>
    );
  };

  // ── Main Render ─────────────────────────────────────────────────────────────
  const bannerHeight = bannerAnim.interpolate({ inputRange: [0, 1], outputRange: [0, 52] });

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#050505" />

      {/* Toast Notification */}
      <Toast message={toastMsg} type={toastType} visible={toastKey > 0} key={toastKey} />

      {/* Honeypot Banner */}
      <Animated.View style={[styles.intrusionBanner, { height: bannerHeight, opacity: bannerAnim }]}>
        <Text style={styles.intrusionText}>
          🚨 INTRUSION — {honeypotLogs.length} honeypot connection(s)
        </Text>
      </Animated.View>

      {/* Header */}
      <View style={styles.header}>
        <View style={styles.titleRow}>
          <View>
            <Text style={styles.title}>🛡️ SENTINEL</Text>
            <Text style={styles.subtitle}>Enterprise Network Security v5.0</Text>
          </View>
          <View style={styles.headerBtns}>
            {/* Database Status */}
            <View style={styles.dbStatus}>
              <View style={[styles.dbDot, dbConnected ? styles.dbDotOn : styles.dbDotOff]} />
              <Text style={styles.dbText}>DB: {dbTotal}</Text>
            </View>
            {/* Settings Button */}
            <TouchableOpacity
              style={styles.settingsBtn}
              onPress={() => { setSettingsInput(serverUrl); setSettingsOpen(true); }}
            >
              <Text style={styles.settingsBtnText}>⚙️</Text>
            </TouchableOpacity>
          </View>
        </View>

        <View style={styles.statsRow}>
          <Text style={styles.stat}>📡 {subnet}</Text>
          <Text style={styles.stat}>🔍 {scanMode}</Text>
          <Text style={styles.stat}>🕐 {lastScanTime || '—'}</Text>
        </View>
        <View style={styles.statsRow}>
          <Text style={styles.stat}>📊 {devices.length} devices</Text>
          <Text style={styles.stat}>✅ {devices.filter(d => trustedMacs.includes(d.mac)).length}</Text>
          <Text style={styles.stat}>⚠️ {devices.filter(d => !trustedMacs.includes(d.mac)).length}</Text>
        </View>
      </View>

      {/* Main Content */}
      {isOffline ? (
        <OfflineScreen
          serverUrl={serverUrl}
          onRetry={fetchScan}
          onOpenSettings={() => { setSettingsInput(serverUrl); setSettingsOpen(true); }}
        />
      ) : loading ? (
        <SkeletonLoader />
      ) : (
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
      )}

      {/* Action Buttons */}
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

      {/* ══ Settings Modal ══ */}
      <Modal visible={settingsOpen} transparent animationType="fade">
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>⚙️ Server Settings</Text>
            <Text style={styles.modalLabel}>Backend URL:</Text>
            <TextInput
              style={styles.modalInput}
              value={settingsInput}
              onChangeText={setSettingsInput}
              placeholder="http://192.168.x.x:3000"
              placeholderTextColor="#444"
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
            />
            <Text style={styles.modalHint}>
              Find your IP: macOS → System Settings → Wi-Fi → Details
            </Text>
            <View style={styles.modalButtons}>
              <TouchableOpacity
                style={styles.modalCancel}
                onPress={() => setSettingsOpen(false)}
              >
                <Text style={styles.modalCancelText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.modalSave}
                onPress={saveServerUrl}
              >
                <Text style={styles.modalSaveText}>Save</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STYLES — Professional Dark Mode
// ═══════════════════════════════════════════════════════════════════════════════

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#050505' },

  // Toast
  toast: { position: 'absolute', top: 0, left: 0, right: 0, zIndex: 999, paddingVertical: 14, paddingHorizontal: 20, alignItems: 'center' },
  toastText: { color: '#fff', fontSize: 13, fontWeight: '700' },

  // Intrusion Banner
  intrusionBanner: { backgroundColor: '#dc2626', justifyContent: 'center', alignItems: 'center', overflow: 'hidden' },
  intrusionText: { color: '#fff', fontSize: 12, fontWeight: '800', letterSpacing: 0.5 },

  // Header
  header: { paddingHorizontal: 20, paddingTop: 14, paddingBottom: 10, borderBottomWidth: 1, borderBottomColor: '#151515' },
  titleRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' },
  title: { fontSize: 24, fontWeight: '900', color: '#00ff88', letterSpacing: 2 },
  subtitle: { fontSize: 10, color: '#444', marginTop: 2, letterSpacing: 0.5 },
  headerBtns: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  dbStatus: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#111', paddingHorizontal: 8, paddingVertical: 5, borderRadius: 6, borderWidth: 1, borderColor: '#222' },
  dbDot: { width: 7, height: 7, borderRadius: 4, marginRight: 5 },
  dbDotOn: { backgroundColor: '#00ff88' },
  dbDotOff: { backgroundColor: '#ff4444' },
  dbText: { color: '#777', fontSize: 11, fontWeight: '600', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  settingsBtn: { backgroundColor: '#111', padding: 6, borderRadius: 6, borderWidth: 1, borderColor: '#222' },
  settingsBtnText: { fontSize: 18 },
  statsRow: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 6 },
  stat: { fontSize: 11, color: '#555' },

  // Device List
  list: { padding: 12, paddingBottom: 100 },

  // Device Card
  card: { borderRadius: 12, padding: 14, marginBottom: 10, borderWidth: 1 },
  trustedCard: { backgroundColor: '#0a1a0f', borderColor: '#153d20' },
  intruderCard: { backgroundColor: '#1a0a0a', borderColor: '#3d1515' },
  cardHeader: { flexDirection: 'row', alignItems: 'center' },
  cardEmoji: { fontSize: 24, marginRight: 10 },
  cardInfo: { flex: 1 },
  cardIP: { fontSize: 15, fontWeight: '700', color: '#eee', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  cardType: { fontSize: 10, color: '#777', marginTop: 2 },
  trustBtn: { padding: 7, borderRadius: 8, borderWidth: 1 },
  trustedBtnBg: { backgroundColor: '#0a2818', borderColor: '#1a5030' },
  untrustedBtnBg: { backgroundColor: '#280a0a', borderColor: '#501515' },
  trustBtnText: { fontSize: 16 },
  cardDetails: { marginTop: 8, paddingTop: 8, borderTopWidth: 1, borderTopColor: '#151515' },
  cardMAC: { fontSize: 10, color: '#444', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  cardVendor: { fontSize: 10, color: '#666', marginTop: 2 },
  cardFooter: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginTop: 8 },
  badge: { fontSize: 10, fontWeight: '700', paddingHorizontal: 8, paddingVertical: 3, borderRadius: 6, overflow: 'hidden' },
  trustedBadge: { color: '#00ff88', backgroundColor: '#0a2a14' },
  intruderBadge: { color: '#ff4444', backgroundColor: '#2a0a0a' },
  hintText: { fontSize: 9, color: '#333', fontStyle: 'italic' },

  // Skeleton Loader
  skeletonContainer: { padding: 20, alignItems: 'center' },
  scanningTitle: { color: '#00ff88', fontSize: 18, fontWeight: '700', marginBottom: 4 },
  scanningHint: { color: '#555', fontSize: 12, marginBottom: 20 },
  skeletonCard: { width: '100%', backgroundColor: '#111', borderRadius: 12, padding: 16, marginBottom: 10, borderWidth: 1, borderColor: '#1a1a1a' },
  skeletonRow: { flexDirection: 'row', alignItems: 'center' },
  skeletonCircle: { width: 36, height: 36, borderRadius: 18, backgroundColor: '#1a1a1a', marginRight: 12 },
  skeletonLines: { flex: 1 },
  skeletonLine: { height: 10, borderRadius: 4, backgroundColor: '#1a1a1a' },

  // Empty State
  emptyState: { alignItems: 'center', paddingTop: 80 },
  emptyEmoji: { fontSize: 48, marginBottom: 12 },
  emptyTitle: { color: '#555', fontSize: 16, fontWeight: '600' },
  emptyHint: { color: '#333', fontSize: 12, marginTop: 4 },

  // Offline Screen
  offlineContainer: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 30 },
  offlineEmoji: { fontSize: 56, marginBottom: 16 },
  offlineTitle: { color: '#ff4444', fontSize: 20, fontWeight: '800', marginBottom: 8 },
  offlineMessage: { color: '#888', fontSize: 14, textAlign: 'center', lineHeight: 22 },
  offlineUrl: { color: '#00ff88', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', fontSize: 13 },
  offlineChecklist: { marginTop: 20, alignSelf: 'stretch' },
  offlineItem: { color: '#666', fontSize: 13, paddingVertical: 4, paddingLeft: 8 },
  retryBtn: { backgroundColor: '#00cc66', paddingVertical: 14, paddingHorizontal: 40, borderRadius: 10, marginTop: 24 },
  retryBtnText: { color: '#000', fontSize: 15, fontWeight: '800' },
  settingsLink: { marginTop: 12 },
  settingsLinkText: { color: '#666', fontSize: 13 },

  // Buttons
  buttonRow: { flexDirection: 'row', padding: 16, paddingBottom: Platform.OS === 'ios' ? 30 : 16, gap: 10, backgroundColor: '#050505', borderTopWidth: 1, borderTopColor: '#151515' },
  scanBtn: { flex: 1, backgroundColor: '#00cc66', paddingVertical: 14, borderRadius: 10, alignItems: 'center' },
  scanBtnDisabled: { backgroundColor: '#003d1f' },
  scanBtnText: { color: '#000', fontSize: 15, fontWeight: '800', letterSpacing: 1 },
  reportBtn: { width: 52, backgroundColor: '#111', paddingVertical: 14, borderRadius: 10, alignItems: 'center', borderWidth: 1, borderColor: '#222' },
  reportBtnText: { fontSize: 20 },

  // Settings Modal
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.85)', justifyContent: 'center', alignItems: 'center', padding: 20 },
  modalContent: { width: '100%', backgroundColor: '#111', borderRadius: 16, padding: 24, borderWidth: 1, borderColor: '#222' },
  modalTitle: { color: '#fff', fontSize: 20, fontWeight: '800', marginBottom: 16 },
  modalLabel: { color: '#888', fontSize: 13, marginBottom: 6 },
  modalInput: { backgroundColor: '#0a0a0a', color: '#00ff88', fontSize: 15, padding: 14, borderRadius: 10, borderWidth: 1, borderColor: '#222', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  modalHint: { color: '#444', fontSize: 11, marginTop: 8, fontStyle: 'italic' },
  modalButtons: { flexDirection: 'row', justifyContent: 'flex-end', marginTop: 20, gap: 10 },
  modalCancel: { paddingVertical: 10, paddingHorizontal: 20, borderRadius: 8, backgroundColor: '#1a1a1a' },
  modalCancelText: { color: '#888', fontSize: 14, fontWeight: '600' },
  modalSave: { paddingVertical: 10, paddingHorizontal: 24, borderRadius: 8, backgroundColor: '#00cc66' },
  modalSaveText: { color: '#000', fontSize: 14, fontWeight: '800' },
});