/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Mobile v6.0 — Professional Enterprise Network Security
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Features:
 *  ► Device Names          — Shows hostnames instead of raw IPs
 *  ► Device Detail Modal   — Full detail view on tap (ports, history, risk)
 *  ► Connection History    — Shows when device was first/last seen
 *  ► Professional UI       — Industry-grade dark mode with glassmorphism
 *  ► Settings Screen       — Change server IP dynamically (persisted)
 *  ► Skeleton Loader       — Animated placeholder during scans
 *  ► Toast Notifications   — Non-intrusive status messages
 *  ► Offline Handling      — Clean "Cannot Connect" screen with Retry
 *  ► Database Status       — Shows total devices logged in Supabase
 *  ► Long-Press Audit      — Credential audit via long press
 *  ► Honeypot Alerts       — Polls every 10s for intrusion events
 *  ► Report Sharing        — Export security report via Share API
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
  ScrollView,
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
  hostname?: string;
  status?: string;
  risk?: string;
  last_seen?: string;
}

interface DeepScanResult {
  hostname?: string;
  open_ports?: Array<{ port: number; banner?: string }>;
  port_count?: number;
  risk_level?: string;
  error?: string;
}

interface HistoryEntry {
  ip: string;
  mac: string;
  vendor?: string;
  type?: string;
  hostname?: string;
  status?: string;
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
//  TOAST COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════

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
//  SKELETON LOADER
// ═══════════════════════════════════════════════════════════════════════════════

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
      <Text style={styles.scanningHint}>Discovering devices on your WiFi</Text>
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
//  OFFLINE SCREEN
// ═══════════════════════════════════════════════════════════════════════════════

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
//  DEVICE DETAIL MODAL
// ═══════════════════════════════════════════════════════════════════════════════

function DeviceDetailModal({
  visible,
  device,
  scanResult,
  history,
  isTrusted,
  loading,
  serverUrl,
  onClose,
  onToggleTrust,
  onAudit,
}: {
  visible: boolean;
  device: Device | null;
  scanResult: DeepScanResult | null;
  history: HistoryEntry[];
  isTrusted: boolean;
  loading: boolean;
  serverUrl: string;
  onClose: () => void;
  onToggleTrust: () => void;
  onAudit: () => void;
}) {
  const [monitoring, setMonitoring] = useState(false);
  const [blocking, setBlocking] = useState(false);
  const [mitmStats, setMitmStats] = useState<any>(null);
  const [errorMsg, setErrorMsg] = useState('');

  // Reset state when device changes
  useEffect(() => {
    setMonitoring(false);
    setBlocking(false);
    setMitmStats(null);
    setErrorMsg('');
  }, [device]);

  // Poll MitM stats
  useEffect(() => {
    let interval: any;
    if (monitoring) {
      interval = setInterval(async () => {
        try {
          const resp = await fetch(`${serverUrl}/api/mitm/stats`);
          const data = await resp.json();
          if (data && data.timestamp) {
            setMitmStats(data);
          }
        } catch { /* ignore */ }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [monitoring, serverUrl]);

  const toggleMonitoring = async () => {
    if (!device) return;
    setErrorMsg('');

    if (monitoring) {
      // Stop
      try {
        await fetch(`${serverUrl}/api/mitm/stop`, { method: 'POST' });
        setMonitoring(false);
      } catch (e) {
        setErrorMsg('Failed to stop');
      }
    } else {
      // Start
      try {
        const resp = await fetch(`${serverUrl}/api/mitm/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: device.ip })
        });
        const data = await resp.json();
        if (data.error) {
          setErrorMsg(data.error);
        } else {
          setMonitoring(true);
        }
      } catch (e) {
        setErrorMsg('Failed to start — check server logs (needs sudo)');
      }
    }
  };

  const toggleBlocking = async () => {
    if (!device) return;
    setErrorMsg('');

    if (blocking) {
      // Stop Blocking
      try {
        await fetch(`${serverUrl}/api/block/stop`, { method: 'POST' });
        setBlocking(false);
      } catch (e) { setErrorMsg('Failed to stop blocking'); }
    } else {
      // Start Blocking
      if (monitoring) {
        setErrorMsg('Stop monitoring first.');
        return;
      }
      try {
        const resp = await fetch(`${serverUrl}/api/block/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: device.ip })
        });
        const data = await resp.json();
        if (data.error) setErrorMsg(data.error);
        else setBlocking(true);
      } catch (e) { setErrorMsg('Failed to block'); }
    }
  };

  if (!device) return null;

  const displayName = device.hostname && device.hostname !== 'Unknown'
    ? device.hostname
    : device.type || 'Unknown Device';

  const riskLevel = scanResult?.risk_level || 'LOW';
  const riskColor = riskLevel === 'HIGH' ? '#ff4444' : riskLevel === 'MEDIUM' ? '#ffaa00' : '#00ff88';

  return (
    <Modal visible={visible} transparent animationType="slide">
      <View style={styles.detailOverlay}>
        <View style={styles.detailContainer}>
          {/* Header */}
          <View style={styles.detailHeader}>
            <View style={styles.detailHeaderLeft}>
              <Text style={styles.detailEmoji}>{typeEmojiStatic(device.type || '')}</Text>
              <View style={{ flex: 1 }}>
                <Text style={styles.detailName} numberOfLines={1}>{displayName}</Text>
                <Text style={styles.detailType}>{device.vendor || 'Unknown Vendor'}</Text>
              </View>
            </View>
            <TouchableOpacity style={styles.detailCloseBtn} onPress={onClose}>
              <Text style={styles.detailCloseBtnText}>✕</Text>
            </TouchableOpacity>
          </View>

          <ScrollView style={styles.detailScroll} showsVerticalScrollIndicator={false}>
            {/* Status Badge */}
            <View style={styles.detailStatusRow}>
              <View style={[styles.detailBadge, { backgroundColor: isTrusted ? '#0a2a14' : '#2a0a0a' }]}>
                <Text style={{ color: isTrusted ? '#00ff88' : '#ff4444', fontSize: 12, fontWeight: '700' }}>
                  {isTrusted ? '✅ TRUSTED' : '⚠️ UNTRUSTED'}
                </Text>
              </View>
              <View style={[styles.detailBadge, { backgroundColor: riskLevel === 'LOW' ? '#0a2a14' : '#2a0a0a' }]}>
                <Text style={{ color: riskColor, fontSize: 12, fontWeight: '700' }}>
                  Risk: {riskLevel}
                </Text>
              </View>
              {monitoring && (
                <View style={[styles.detailBadge, { backgroundColor: '#2a0a0a', borderColor: '#ff4444', borderWidth: 1 }]}>
                  <Text style={{ color: '#ff4444', fontSize: 12, fontWeight: '700' }}>
                    🔴 RECORDING
                  </Text>
                </View>
              )}
              {blocking && (
                <View style={[styles.detailBadge, { backgroundColor: '#4a0a0a', borderColor: '#ff0000', borderWidth: 1 }]}>
                  <Text style={{ color: '#ff0000', fontSize: 12, fontWeight: '700' }}>
                    ⛔ BLOCKED
                  </Text>
                </View>
              )}
            </View>

            {/* ERROR MSG */}
            {errorMsg ? (
              <View style={{ marginBottom: 15, padding: 10, backgroundColor: '#300', borderRadius: 8 }}>
                <Text style={{ color: '#ff4444', fontSize: 12 }}>❌ {errorMsg}</Text>
              </View>
            ) : null}

            {/* TRAFFIC MONITORING (MitM) */}
            <View style={styles.detailSection}>
              <Text style={styles.detailSectionTitle}>TRAFFIC INTERCEPTION (Active)</Text>

              {!monitoring ? (
                <View style={styles.mitmPlaceholder}>
                  <Text style={styles.mitmDesc}>
                    Actively monitor this device's traffic by routing it through Sentinel.
                    Requires root privileges on server.
                  </Text>
                  <TouchableOpacity style={styles.mitmStartBtn} onPress={toggleMonitoring}>
                    <Text style={styles.mitmStartText}>▶ START MONITORING</Text>
                  </TouchableOpacity>
                </View>
              ) : (
                <View style={styles.mitmActive}>
                  <View style={styles.mitmStatsRow}>
                    <View style={styles.mitmStat}>
                      <Text style={styles.mitmVal}>
                        {mitmStats ? (mitmStats.download_bytes / 1024 / 1024).toFixed(2) : '0.00'} MB
                      </Text>
                      <Text style={styles.mitmLbl}>TOTAL DOWN</Text>
                    </View>
                    <View style={styles.mitmStat}>
                      <Text style={styles.mitmVal}>
                        {mitmStats ? (mitmStats.upload_bytes / 1024 / 1024).toFixed(2) : '0.00'} MB
                      </Text>
                      <Text style={styles.mitmLbl}>TOTAL UP</Text>
                    </View>
                  </View>

                  <Text style={styles.mitmSubTitle}>RECENTLY VISITED SITES</Text>
                  {mitmStats && mitmStats.recent_sites && mitmStats.recent_sites.length > 0 ? (
                    mitmStats.recent_sites.map((site: any, idx: number) => (
                      <View key={idx} style={styles.mitmSiteRow}>
                        <Text style={styles.mitmSiteTime}>{new Date(site.timestamp * 1000).toLocaleTimeString()}</Text>
                        <Text style={styles.mitmSiteDomain}>{site.domain}</Text>
                      </View>
                    ))
                  ) : (
                    <Text style={styles.detailMuted}>Waiting for traffic...</Text>
                  )}

                  <TouchableOpacity style={styles.mitmStopBtn} onPress={toggleMonitoring}>
                    <Text style={styles.mitmStopText}>⏹ STOP MONITORING</Text>
                  </TouchableOpacity>
                </View>
              )}
            </View>

            {/* BLOCKING CONTROLS */}
            <View style={styles.detailSection}>
              <Text style={styles.detailSectionTitle}>NETWORK ACCESS CONTROL</Text>
              {blocking ? (
                <View style={styles.blockActive}>
                  <Text style={styles.blockTitle}>⛔ INTERNET ACCESS BLOCKED</Text>
                  <Text style={styles.blockDesc}>This device is currently being blocked via ARP Blackholing.</Text>
                  <TouchableOpacity style={styles.blockStopBtn} onPress={toggleBlocking}>
                    <Text style={styles.blockStopText}>UNBLOCK DEVICE</Text>
                  </TouchableOpacity>
                </View>
              ) : (
                <TouchableOpacity
                  style={[styles.blockStartBtn, monitoring ? styles.disabledBtn : {}]}
                  onPress={toggleBlocking}
                  disabled={monitoring}
                >
                  <Text style={styles.blockStartText}>🚫 BLOCK INTERNET ACCESS</Text>
                </TouchableOpacity>
              )}
            </View>

            {/* Network Info */}
            <View style={styles.detailSection}>
              <Text style={styles.detailSectionTitle}>NETWORK INFO</Text>
              <View style={styles.detailInfoGrid}>
                <InfoRow label="IP Address" value={device.ip} />
                <InfoRow label="MAC Address" value={device.mac} />
                <InfoRow label="Hostname" value={device.hostname || 'Unknown'} />
                <InfoRow label="Vendor" value={device.vendor || 'Unknown'} />
                <InfoRow label="Device Type" value={device.type || 'Unknown'} />
              </View>
            </View>

            {/* Port Scan Results */}
            <View style={styles.detailSection}>
              <Text style={styles.detailSectionTitle}>PORT SCAN</Text>
              {loading ? (
                <View style={styles.detailLoadingRow}>
                  <ActivityIndicator color="#00ff88" size="small" />
                  <Text style={styles.detailLoadingText}>Scanning ports...</Text>
                </View>
              ) : scanResult ? (
                <View>
                  <Text style={styles.detailPortCount}>
                    {scanResult.port_count || 0} open port{(scanResult.port_count || 0) !== 1 ? 's' : ''} found
                  </Text>
                  {scanResult.open_ports && scanResult.open_ports.length > 0 ? (
                    scanResult.open_ports.map((p, idx) => (
                      <View key={idx} style={styles.portRow}>
                        <View style={styles.portDot} />
                        <Text style={styles.portNumber}>:{p.port}</Text>
                        {p.banner ? <Text style={styles.portBanner}>{p.banner}</Text> : null}
                      </View>
                    ))
                  ) : (
                    <Text style={styles.detailMuted}>No open ports detected — good!</Text>
                  )}
                </View>
              ) : (
                <Text style={styles.detailMuted}>Awaiting scan results...</Text>
              )}
            </View>

            {/* Connection History */}
            <View style={styles.detailSection}>
              <Text style={styles.detailSectionTitle}>CONNECTION HISTORY</Text>
              {history.length > 0 ? (
                history.map((h, idx) => (
                  <View key={idx} style={styles.historyRow}>
                    <View style={styles.historyDot} />
                    <View style={{ flex: 1 }}>
                      <Text style={styles.historyIP}>{h.ip}</Text>
                      <Text style={styles.historyTime}>
                        {h.last_seen ? new Date(h.last_seen).toLocaleString() : 'Unknown'}
                      </Text>
                    </View>
                    <Text style={[styles.historyStatus, { color: h.status === 'online' ? '#00ff88' : '#666' }]}>
                      {h.status || 'seen'}
                    </Text>
                  </View>
                ))
              ) : (
                <Text style={styles.detailMuted}>No history available</Text>
              )}
            </View>
          </ScrollView>

          {/* Action Buttons */}
          <View style={styles.detailActions}>
            <TouchableOpacity
              style={[styles.detailActionBtn, isTrusted ? styles.detailActionDanger : styles.detailActionPrimary]}
              onPress={onToggleTrust}
            >
              <Text style={styles.detailActionBtnText}>
                {isTrusted ? '❌ Remove Trust' : '✅ Mark Trusted'}
              </Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.detailActionBtn, styles.detailActionSecondary]}
              onPress={onAudit}
            >
              <Text style={styles.detailActionBtnText}>🔐 Audit Credentials</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.infoRow}>
      <Text style={styles.infoLabel}>{label}</Text>
      <Text style={styles.infoValue} numberOfLines={1}>{value}</Text>
    </View>
  );
}

// ── Helpers (outside component for use in DeviceDetailModal) ──────────────
function typeEmojiStatic(type: string): string {
  if (!type) return '📱';
  const t = type.toLowerCase();
  if (t.includes('router')) return '🌐';
  if (t.includes('apple')) return '🍎';
  if (t.includes('android')) return '📱';
  if (t.includes('camera')) return '📷';
  if (t.includes('printer')) return '🖨️';
  if (t.includes('google')) return '🔵';
  if (t.includes('pc') || t.includes('laptop')) return '💻';
  if (t.includes('iot')) return '⚡';
  if (t.includes('media')) return '📺';
  if (t.includes('smart home')) return '🏠';
  if (t.includes('raspberry')) return '🍓';
  return '📱';
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

  // Device Detail Modal state
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [detailVisible, setDetailVisible] = useState(false);
  const [detailScanResult, setDetailScanResult] = useState<DeepScanResult | null>(null);
  const [detailHistory, setDetailHistory] = useState<HistoryEntry[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);

  // Toast state
  const [toastMsg, setToastMsg] = useState('');
  const [toastType, setToastType] = useState<'success' | 'error' | 'info'>('info');
  const [toastKey, setToastKey] = useState(0);

  // Traffic state
  const [trafficUp, setTrafficUp] = useState('0');
  const [trafficDown, setTrafficDown] = useState('0');
  const [connections, setConnections] = useState(0);

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

  // ── Traffic Stats Polling ───────────────────────────────────────────────────
  useEffect(() => {
    const fetchTraffic = async () => {
      try {
        const resp = await fetch(`${serverUrl}/api/traffic`);
        const data = await resp.json();
        setTrafficUp(data.upload_mb || '0');
        setTrafficDown(data.download_mb || '0');
        setConnections(data.connections || 0);
      } catch { /* ignore */ }
    };

    fetchTraffic();
    const interval = setInterval(fetchTraffic, 15000);
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

  // ── Open Device Detail ──────────────────────────────────────────────────────
  const openDeviceDetail = useCallback(async (device: Device) => {
    setSelectedDevice(device);
    setDetailVisible(true);
    setDetailScanResult(null);
    setDetailHistory([]);
    setDetailLoading(true);

    // Fetch deep scan + history in parallel
    try {
      const [scanResp, histResp] = await Promise.all([
        fetch(`${serverUrl}/api/inspect?ip=${device.ip}`).catch(() => null),
        fetch(`${serverUrl}/api/device-history?mac=${encodeURIComponent(device.mac)}`).catch(() => null),
      ]);

      if (scanResp) {
        const scanData = await scanResp.json();
        setDetailScanResult(scanData);
      }
      if (histResp) {
        const histData = await histResp.json();
        setDetailHistory(histData.history || []);
      }
    } catch {
      // Silently fail — modal will show "awaiting" text
    } finally {
      setDetailLoading(false);
    }
  }, [serverUrl]);

  // ── Credential Audit ──────────────────────────────────────────────────────
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
      `── Trusted Devices ──`,
      ...trusted.map(d => `  ✅ ${d.hostname || d.ip} | ${d.mac} | ${d.vendor || '?'}`),
      ``,
      `── Untrusted Devices ──`,
      ...intruders.map(d => `  ⚠️ ${d.hostname || d.ip} | ${d.mac} | ${d.vendor || '?'}`),
    ];

    try {
      await Share.share({ message: report.join('\n') });
    } catch { /* cancelled */ }
  }, [devices, trustedMacs, honeypotLogs, subnet, scanMode, dbTotal]);

  // ── Get display name for a device ──────────────────────────────────────────
  const getDeviceName = (device: Device): string => {
    if (device.hostname && device.hostname !== 'Unknown') return device.hostname;
    if (device.type && device.type !== 'Unknown Device') return device.type;
    return device.ip;
  };

  // ── Render Device Card ──────────────────────────────────────────────────────
  const renderDevice = ({ item }: { item: Device }) => {
    const isTrusted = trustedMacs.includes(item.mac);
    const deviceName = getDeviceName(item);

    return (
      <TouchableOpacity
        style={[styles.card, isTrusted ? styles.trustedCard : styles.intruderCard]}
        onPress={() => openDeviceDetail(item)}
        onLongPress={() => auditCredentials(item.ip)}
        delayLongPress={600}
        activeOpacity={0.7}
      >
        {/* Card Top Row */}
        <View style={styles.cardHeader}>
          <View style={styles.cardEmojiWrap}>
            <Text style={styles.cardEmoji}>{typeEmojiStatic(item.type || '')}</Text>
          </View>
          <View style={styles.cardInfo}>
            <Text style={styles.cardName} numberOfLines={1}>{deviceName}</Text>
            <Text style={styles.cardType}>{item.vendor || 'Unknown Vendor'}</Text>
          </View>
          <TouchableOpacity
            style={[styles.trustBtn, isTrusted ? styles.trustedBtnBg : styles.untrustedBtnBg]}
            onPress={() => toggleTrust(item.mac)}
          >
            <Text style={styles.trustBtnText}>{isTrusted ? '✅' : '❌'}</Text>
          </TouchableOpacity>
        </View>

        {/* Card Details */}
        <View style={styles.cardDetails}>
          <View style={styles.cardDetailRow}>
            <Text style={styles.cardDetailLabel}>IP</Text>
            <Text style={styles.cardDetailValue}>{item.ip}</Text>
          </View>
          <View style={styles.cardDetailRow}>
            <Text style={styles.cardDetailLabel}>MAC</Text>
            <Text style={styles.cardDetailValue}>{item.mac}</Text>
          </View>
        </View>

        {/* Card Footer */}
        <View style={styles.cardFooter}>
          <View style={[styles.badge, isTrusted ? styles.trustedBadge : styles.intruderBadge]}>
            <Text style={[styles.badgeText, { color: isTrusted ? '#00ff88' : '#ff4444' }]}>
              {isTrusted ? '✅ TRUSTED' : '⚠️ INTRUDER'}
            </Text>
          </View>
          <Text style={styles.hintText}>Tap → Details  |  Hold → Audit</Text>
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
            <Text style={styles.subtitle}>Enterprise Network Security v6.0</Text>
          </View>
          <View style={styles.headerBtns}>
            <View style={styles.dbStatus}>
              <View style={[styles.dbDot, dbConnected ? styles.dbDotOn : styles.dbDotOff]} />
              <Text style={styles.dbText}>DB: {dbTotal}</Text>
            </View>
            <TouchableOpacity
              style={styles.settingsBtn}
              onPress={() => { setSettingsInput(serverUrl); setSettingsOpen(true); }}
            >
              <Text style={styles.settingsBtnText}>⚙️</Text>
            </TouchableOpacity>
          </View>
        </View>

        <View style={styles.statsRow}>
          <View style={styles.statCard}>
            <Text style={styles.statValue}>{devices.length}</Text>
            <Text style={styles.statLabel}>Devices</Text>
          </View>
          <View style={styles.statCard}>
            <Text style={[styles.statValue, { color: '#00ff88' }]}>
              {devices.filter(d => trustedMacs.includes(d.mac)).length}
            </Text>
            <Text style={styles.statLabel}>Trusted</Text>
          </View>
          <View style={styles.statCard}>
            <Text style={[styles.statValue, { color: '#ff4444' }]}>
              {devices.filter(d => !trustedMacs.includes(d.mac)).length}
            </Text>
            <Text style={styles.statLabel}>Untrusted</Text>
          </View>
          <View style={styles.statCard}>
            <Text style={[styles.statValue, { color: '#ffaa00' }]}>{honeypotLogs.length}</Text>
            <Text style={styles.statLabel}>Alerts</Text>
          </View>
        </View>

        <View style={styles.metaRow}>
          <Text style={styles.metaText}>📡 {subnet}</Text>
          <Text style={styles.metaText}>🔍 {scanMode}</Text>
          <Text style={styles.metaText}>🕐 {lastScanTime || '—'}</Text>
        </View>

        {/* Traffic Stats */}
        <View style={styles.trafficRow}>
          <View style={styles.trafficItem}>
            <Text style={styles.trafficIcon}>⬇️</Text>
            <Text style={styles.trafficValue}>{trafficDown} MB</Text>
            <Text style={styles.trafficLabel}>DOWN</Text>
          </View>
          <View style={styles.trafficDivider} />
          <View style={styles.trafficItem}>
            <Text style={styles.trafficIcon}>⬆️</Text>
            <Text style={styles.trafficValue}>{trafficUp} MB</Text>
            <Text style={styles.trafficLabel}>UP</Text>
          </View>
          <View style={styles.trafficDivider} />
          <View style={styles.trafficItem}>
            <Text style={styles.trafficIcon}>🔗</Text>
            <Text style={styles.trafficValue}>{connections}</Text>
            <Text style={styles.trafficLabel}>ACTIVE</Text>
          </View>
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
              <Text style={styles.emptyHint}>Tap "SCAN" to discover devices on your network</Text>
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
            <Text style={styles.scanBtnText}>📡 SCAN</Text>
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

      {/* ══ Device Detail Modal ══ */}
      <DeviceDetailModal
        visible={detailVisible}
        device={selectedDevice}
        scanResult={detailScanResult}
        history={detailHistory}
        isTrusted={selectedDevice ? trustedMacs.includes(selectedDevice.mac) : false}
        loading={detailLoading}
        onClose={() => setDetailVisible(false)}
        onToggleTrust={() => selectedDevice && toggleTrust(selectedDevice.mac)}
        onAudit={() => selectedDevice && auditCredentials(selectedDevice.ip)}
        serverUrl={serverUrl}
      />

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
  header: { paddingHorizontal: 16, paddingTop: 12, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: '#111' },
  titleRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-start' },
  title: { fontSize: 22, fontWeight: '900', color: '#00ff88', letterSpacing: 2 },
  subtitle: { fontSize: 9, color: '#444', marginTop: 1, letterSpacing: 0.5 },
  headerBtns: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  dbStatus: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#0a0a0a', paddingHorizontal: 10, paddingVertical: 6, borderRadius: 8, borderWidth: 1, borderColor: '#1a1a1a' },
  dbDot: { width: 6, height: 6, borderRadius: 3, marginRight: 5 },
  dbDotOn: { backgroundColor: '#00ff88' },
  dbDotOff: { backgroundColor: '#ff4444' },
  dbText: { color: '#666', fontSize: 11, fontWeight: '600', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  settingsBtn: { backgroundColor: '#0a0a0a', padding: 6, borderRadius: 8, borderWidth: 1, borderColor: '#1a1a1a' },
  settingsBtnText: { fontSize: 18 },

  // Stats Row
  statsRow: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 12, gap: 8 },
  statCard: { flex: 1, backgroundColor: '#0a0a0a', borderRadius: 10, paddingVertical: 10, alignItems: 'center', borderWidth: 1, borderColor: '#151515' },
  statValue: { fontSize: 20, fontWeight: '900', color: '#fff', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  statLabel: { fontSize: 9, color: '#555', marginTop: 2, fontWeight: '600', letterSpacing: 0.5, textTransform: 'uppercase' },

  // Meta Row
  metaRow: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 8 },
  metaText: { fontSize: 10, color: '#444' },

  // Device List
  list: { padding: 12, paddingBottom: 100 },

  // Device Card — Professional Redesign
  card: { borderRadius: 14, padding: 14, marginBottom: 10, borderWidth: 1 },
  trustedCard: { backgroundColor: '#081a10', borderColor: '#0d3320' },
  intruderCard: { backgroundColor: '#1a0a0a', borderColor: '#331515' },
  cardHeader: { flexDirection: 'row', alignItems: 'center' },
  cardEmojiWrap: { width: 42, height: 42, borderRadius: 12, backgroundColor: '#111', justifyContent: 'center', alignItems: 'center', marginRight: 12, borderWidth: 1, borderColor: '#1a1a1a' },
  cardEmoji: { fontSize: 22 },
  cardInfo: { flex: 1 },
  cardName: { fontSize: 15, fontWeight: '800', color: '#f0f0f0', letterSpacing: 0.3 },
  cardType: { fontSize: 10, color: '#666', marginTop: 2 },
  trustBtn: { padding: 8, borderRadius: 10, borderWidth: 1 },
  trustedBtnBg: { backgroundColor: '#0a2818', borderColor: '#1a5030' },
  untrustedBtnBg: { backgroundColor: '#280a0a', borderColor: '#501515' },
  trustBtnText: { fontSize: 16 },
  cardDetails: { marginTop: 10, paddingTop: 10, borderTopWidth: 1, borderTopColor: '#151515' },
  cardDetailRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 4 },
  cardDetailLabel: { fontSize: 10, color: '#555', fontWeight: '600', textTransform: 'uppercase', letterSpacing: 0.5 },
  cardDetailValue: { fontSize: 10, color: '#888', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  cardFooter: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 },
  badge: { paddingHorizontal: 10, paddingVertical: 4, borderRadius: 6 },
  badgeText: { fontSize: 10, fontWeight: '700' },
  trustedBadge: { backgroundColor: '#0a2a14' },
  intruderBadge: { backgroundColor: '#2a0a0a' },
  hintText: { fontSize: 8, color: '#333', fontStyle: 'italic' },

  // Skeleton Loader
  skeletonContainer: { padding: 20, alignItems: 'center' },
  scanningTitle: { color: '#00ff88', fontSize: 18, fontWeight: '700', marginBottom: 4 },
  scanningHint: { color: '#555', fontSize: 12, marginBottom: 20 },
  skeletonCard: { width: '100%', backgroundColor: '#0a0a0a', borderRadius: 14, padding: 16, marginBottom: 10, borderWidth: 1, borderColor: '#151515' },
  skeletonRow: { flexDirection: 'row', alignItems: 'center' },
  skeletonCircle: { width: 42, height: 42, borderRadius: 12, backgroundColor: '#151515', marginRight: 12 },
  skeletonLines: { flex: 1 },
  skeletonLine: { height: 10, borderRadius: 4, backgroundColor: '#151515' },

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
  buttonRow: { flexDirection: 'row', padding: 16, paddingBottom: Platform.OS === 'ios' ? 30 : 16, gap: 10, backgroundColor: '#050505', borderTopWidth: 1, borderTopColor: '#111' },
  scanBtn: { flex: 1, backgroundColor: '#00cc66', paddingVertical: 14, borderRadius: 12, alignItems: 'center' },
  scanBtnDisabled: { backgroundColor: '#003d1f' },
  scanBtnText: { color: '#000', fontSize: 15, fontWeight: '900', letterSpacing: 1 },
  reportBtn: { width: 52, backgroundColor: '#0a0a0a', paddingVertical: 14, borderRadius: 12, alignItems: 'center', borderWidth: 1, borderColor: '#1a1a1a' },
  reportBtnText: { fontSize: 20 },

  // Settings Modal
  modalOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.85)', justifyContent: 'center', alignItems: 'center', padding: 20 },
  modalContent: { width: '100%', backgroundColor: '#0d0d0d', borderRadius: 18, padding: 24, borderWidth: 1, borderColor: '#1a1a1a' },
  modalTitle: { color: '#fff', fontSize: 20, fontWeight: '800', marginBottom: 16 },
  modalLabel: { color: '#888', fontSize: 13, marginBottom: 6 },
  modalInput: { backgroundColor: '#070707', color: '#00ff88', fontSize: 15, padding: 14, borderRadius: 12, borderWidth: 1, borderColor: '#1a1a1a', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  modalHint: { color: '#444', fontSize: 11, marginTop: 8, fontStyle: 'italic' },
  modalButtons: { flexDirection: 'row', justifyContent: 'flex-end', marginTop: 20, gap: 10 },
  modalCancel: { paddingVertical: 10, paddingHorizontal: 20, borderRadius: 10, backgroundColor: '#151515' },
  modalCancelText: { color: '#888', fontSize: 14, fontWeight: '600' },
  modalSave: { paddingVertical: 10, paddingHorizontal: 24, borderRadius: 10, backgroundColor: '#00cc66' },
  modalSaveText: { color: '#000', fontSize: 14, fontWeight: '800' },

  // ══ Device Detail Modal ══
  detailOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.92)', justifyContent: 'flex-end' },
  detailContainer: { backgroundColor: '#0a0a0a', borderTopLeftRadius: 24, borderTopRightRadius: 24, maxHeight: '90%', borderWidth: 1, borderColor: '#1a1a1a', borderBottomWidth: 0 },
  detailHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 20, paddingBottom: 12, borderBottomWidth: 1, borderBottomColor: '#151515' },
  detailHeaderLeft: { flexDirection: 'row', alignItems: 'center', flex: 1 },
  detailEmoji: { fontSize: 32, marginRight: 14 },
  detailName: { fontSize: 18, fontWeight: '900', color: '#f0f0f0', letterSpacing: 0.3 },
  detailType: { fontSize: 11, color: '#666', marginTop: 2 },
  detailCloseBtn: { width: 32, height: 32, borderRadius: 16, backgroundColor: '#151515', justifyContent: 'center', alignItems: 'center' },
  detailCloseBtnText: { color: '#666', fontSize: 16, fontWeight: '700' },
  detailScroll: { padding: 20 },
  detailStatusRow: { flexDirection: 'row', gap: 10, marginBottom: 20 },
  detailBadge: { paddingHorizontal: 14, paddingVertical: 6, borderRadius: 8 },
  detailSection: { marginBottom: 24 },
  detailSectionTitle: { color: '#444', fontSize: 10, fontWeight: '800', letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 12 },
  detailInfoGrid: {},
  detailLoadingRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 8 },
  detailLoadingText: { color: '#666', fontSize: 12 },
  detailPortCount: { color: '#888', fontSize: 12, marginBottom: 8 },
  detailMuted: { color: '#444', fontSize: 12, fontStyle: 'italic' },

  // Info Rows
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: '#111' },
  infoLabel: { color: '#555', fontSize: 12, fontWeight: '600' },
  infoValue: { color: '#ccc', fontSize: 12, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', maxWidth: '60%', textAlign: 'right' },

  // Port Rows
  portRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 6 },
  portDot: { width: 6, height: 6, borderRadius: 3, backgroundColor: '#ffaa00', marginRight: 10 },
  portNumber: { color: '#ffaa00', fontSize: 13, fontWeight: '700', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', marginRight: 10 },
  portBanner: { color: '#666', fontSize: 11 },

  // History Rows
  historyRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: '#111' },
  historyDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: '#1a5030', marginRight: 12 },
  historyIP: { color: '#ccc', fontSize: 12, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  historyTime: { color: '#555', fontSize: 10, marginTop: 2 },
  historyStatus: { fontSize: 10, fontWeight: '700', textTransform: 'uppercase', letterSpacing: 0.5 },

  // Detail Actions
  detailActions: { flexDirection: 'row', gap: 10, padding: 20, paddingBottom: Platform.OS === 'ios' ? 36 : 20, borderTopWidth: 1, borderTopColor: '#151515' },
  detailActionBtn: { flex: 1, paddingVertical: 14, borderRadius: 12, alignItems: 'center' },
  detailActionPrimary: { backgroundColor: '#00cc66' },
  detailActionDanger: { backgroundColor: '#cc3333' },
  detailActionSecondary: { backgroundColor: '#151515', borderWidth: 1, borderColor: '#222' },
  detailActionBtnText: { color: '#fff', fontSize: 13, fontWeight: '800' },

  // Traffic Row
  trafficRow: { flexDirection: 'row', justifyContent: 'space-around', alignItems: 'center', marginTop: 10, backgroundColor: '#0a0a0a', borderRadius: 10, paddingVertical: 10, paddingHorizontal: 8, borderWidth: 1, borderColor: '#151515' },
  trafficItem: { alignItems: 'center', flex: 1 },
  trafficIcon: { fontSize: 14, marginBottom: 2 },
  trafficValue: { color: '#00ccff', fontSize: 14, fontWeight: '800', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  trafficLabel: { color: '#555', fontSize: 8, fontWeight: '700', letterSpacing: 1, textTransform: 'uppercase', marginTop: 2 },
  trafficDivider: { width: 1, height: 28, backgroundColor: '#1a1a1a' },

  // MitM Traffic Monitor
  mitmPlaceholder: { padding: 20, backgroundColor: '#1a1a1a', borderRadius: 12, alignItems: 'center', borderWidth: 1, borderColor: '#333', borderStyle: 'dashed' },
  mitmDesc: { color: '#888', fontSize: 13, textAlign: 'center', marginBottom: 20, lineHeight: 20 },
  mitmStartBtn: { backgroundColor: '#cc3333', paddingHorizontal: 24, paddingVertical: 12, borderRadius: 8 },
  mitmStartText: { color: '#fff', fontWeight: '800', fontSize: 12, letterSpacing: 1 },

  mitmActive: { padding: 10 },
  mitmStatsRow: { flexDirection: 'row', gap: 10, marginBottom: 20 },
  mitmStat: { flex: 1, backgroundColor: '#151515', padding: 12, borderRadius: 10, alignItems: 'center', borderWidth: 1, borderColor: '#222' },
  mitmVal: { color: '#00ccff', fontSize: 18, fontWeight: '900', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace', marginBottom: 4 },
  mitmLbl: { color: '#555', fontSize: 10, fontWeight: '700' },

  mitmSubTitle: { color: '#666', fontSize: 10, fontWeight: '800', letterSpacing: 1, marginBottom: 10 },
  mitmSiteRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: '#111' },
  mitmSiteTime: { color: '#444', fontSize: 10, width: 60, fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  mitmSiteDomain: { color: '#ccc', fontSize: 12, flex: 1 },

  mitmStopBtn: { marginTop: 20, backgroundColor: '#1a1a1a', paddingVertical: 12, borderRadius: 8, alignItems: 'center', borderWidth: 1, borderColor: '#333' },
  mitmStopText: { color: '#888', fontWeight: '700', fontSize: 11 },

  // Blocking
  blockActive: { backgroundColor: '#2a0505', padding: 20, borderRadius: 12, alignItems: 'center', borderColor: '#500', borderWidth: 1 },
  blockTitle: { color: '#ff4444', fontSize: 16, fontWeight: '900', marginBottom: 10, letterSpacing: 1 },
  blockDesc: { color: '#aa5555', fontSize: 12, textAlign: 'center', marginBottom: 20 },
  blockStopBtn: { backgroundColor: '#444', paddingHorizontal: 30, paddingVertical: 12, borderRadius: 8 },
  blockStopText: { color: '#fff', fontWeight: '800' },

  blockStartBtn: { backgroundColor: '#330000', padding: 15, borderRadius: 12, alignItems: 'center', borderWidth: 1, borderColor: '#660000', marginVertical: 10 },
  blockStartText: { color: '#ff4444', fontWeight: '900', fontSize: 13, letterSpacing: 1 },
  disabledBtn: { opacity: 0.3 },
});