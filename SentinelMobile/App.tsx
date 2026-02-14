import React, { useState, useEffect } from 'react';
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
  Share
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

interface Device {
  ip: string;
  mac: string;
  status: string;
  vendor?: string;
}

interface HoneypotLog {
  ip: string;
  time: string;
}

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [trustedMacs, setTrustedMacs] = useState<string[]>([]);
  const [honeypotLogs, setHoneypotLogs] = useState<HoneypotLog[]>([]);

  // Connection Logic
  const BASE_URL = Platform.OS === 'android'
    ? 'http://10.0.2.2:3000'
    : 'http://localhost:3000';

  // Load trusted MACs on startup
  useEffect(() => {
    const loadTrusted = async () => {
      try {
        const stored = await AsyncStorage.getItem('trusted_macs');
        if (stored) setTrustedMacs(JSON.parse(stored));
      } catch (e) {
        console.error("Failed to load trusted devices");
      }
    };
    loadTrusted();
  }, []);



  const fetchScan = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${BASE_URL}/api/scan`);
      const data = await response.json();
      setDevices(data.devices || []);

      // Also fetch honeypot logs
      const hpResponse = await fetch(`${BASE_URL}/api/honeypot`);
      const hpData = await hpResponse.json();
      setHoneypotLogs(hpData);

    } catch (error) {
      Alert.alert("Error", "Could not connect to Sentinel Agent.");
    } finally {
      setLoading(false);
    }
  };

  // 🕵️ NEW: DEEP SCAN LOGIC
  const inspectDevice = async (ip: string) => {
    Alert.alert("🕵️ Deep Scan Started", `Analyzing ${ip} for vulnerabilities...`);
    try {
      const response = await fetch(`${BASE_URL}/api/inspect?ip=${ip}`);
      const data = await response.json();

      // OPTIONAL CHAINING FIX
      const portList = data.open_ports?.length > 0 ? data.open_ports.join(', ') : "None";

      Alert.alert(
        `🔎 Analysis Report: ${data.hostname}`,
        `Risk Level: ${data.risk_level}\n\n🔓 Open Ports: ${portList}\n\n(Ports 22/554 are high risk!)`
      );
    } catch (e) {
      Alert.alert("Error", "Deep scan failed.");
    }
  };

  // 🔑 NEW: CREDENTIAL AUDIT
  const auditDevice = async (ip: string) => {
    Alert.alert("🔐 Security Audit", `Checking ${ip} for default 'admin:admin' credentials...`);
    try {
      const response = await fetch(`${BASE_URL}/api/audit?ip=${ip}`);
      const data = await response.json();

      if (data.status === "VULNERABLE") {
        Alert.alert("🚨 CRITICAL ALERT", "This device is using DEFAULT CREDENTIALS (admin:admin). Change password immediately!");
      } else {
        Alert.alert("✅ SECURE", "Device rejected default credentials.");
      }
    } catch (e) {
      Alert.alert("Error", "Audit failed.");
    }
  };

  const toggleTrust = async (mac: string) => {
    let newTrusted;
    if (trustedMacs.includes(mac)) {
      newTrusted = trustedMacs.filter(id => id !== mac);
    } else {
      newTrusted = [...trustedMacs, mac];
    }

    setTrustedMacs(newTrusted);
    try {
      await AsyncStorage.setItem('trusted_macs', JSON.stringify(newTrusted));
    } catch (e) {
      console.error("Failed to save trusted devices");
    }
  };

  // 📄 REPORT GENERATION
  const generateReport = async () => {
    const date = new Date().toLocaleString();
    let report = `🛡️ SENTINEL SECURITY REPORT\nGenerated: ${date}\n\n`;

    report += `--- DEVICE LIST (${devices.length}) ---\n`;
    devices.forEach(d => {
      const name = d.vendor || "Unknown Device";
      const isTrusted = trustedMacs.includes(d.mac);
      report += `[${isTrusted ? "SAFE" : "UNAUTHORIZED"}] ${d.ip} - ${name}\n`;
    });

    if (honeypotLogs.length > 0) {
      report += `\n🚨 INTRUSION ATTEMPTS (${honeypotLogs.length}) ---\n`;
      honeypotLogs.forEach(log => {
        report += `[BLOCKED] IP: ${log.ip} at ${log.time}\n`;
      });
    } else {
      report += `\n✅ No Intrusions Detected.\n`;
    }

    try {
      await Share.share({ message: report });
    } catch (error) {
      Alert.alert("Error", "Could not export report.");
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>🛡️ Sentinel Pro</Text>
        <Text style={styles.subtitle}>
          {devices.length} Devices • {honeypotLogs.length} Intrusions
        </Text>
      </View>

      {/* HONEYPOT BANNER */}
      {honeypotLogs.length > 0 && (
        <View style={styles.banner}>
          <Text style={styles.bannerText}>🚨 HONEYPOT TRIGGERED! ({honeypotLogs.length})</Text>
        </View>
      )}

      <View style={styles.content}>
        <View style={styles.buttonRow}>
          <TouchableOpacity
            style={[styles.scanButton, { flex: 2, marginRight: 10, opacity: loading ? 0.7 : 1 }]}
            onPress={fetchScan}
            disabled={loading}
          >
            {loading ? (
              <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                <ActivityIndicator color="#FFF" />
                <Text style={[styles.buttonText, { marginLeft: 10 }]}>SCANNING...</Text>
              </View>
            ) : (
              <Text style={styles.buttonText}>🚀 SCAN NETWORK</Text>
            )}
          </TouchableOpacity>

          <TouchableOpacity style={[styles.scanButton, { flex: 1, backgroundColor: '#34C759' }]} onPress={generateReport}>
            <Text style={styles.buttonText}>📄 REPORT</Text>
          </TouchableOpacity>
        </View>

        <FlatList
          data={devices}
          keyExtractor={(item) => item.mac}
          extraData={trustedMacs}
          renderItem={({ item }) => {
            const name = item.vendor || "Unknown Device";
            const isTrusted = trustedMacs.includes(item.mac);
            const isIntruder = !isTrusted;

            return (
              <TouchableOpacity
                activeOpacity={0.6}
                onPress={() => toggleTrust(item.mac)}
                onLongPress={() => inspectDevice(item.ip)}
                delayLongPress={500}
              >
                <View style={[styles.card, isIntruder ? styles.intruderCard : styles.safeCard]}>
                  <View style={styles.iconContainer}>
                    <Text style={{ fontSize: 28 }}>
                      {isIntruder ? '🚨' : '🛡️'}
                    </Text>
                  </View>
                  <View style={{ flex: 1 }}>
                    <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Text style={[styles.statusLabel, { color: isIntruder ? '#FF453A' : '#30D158' }]}>
                        {isIntruder ? "UNAUTHORIZED" : "SECURE"}
                      </Text>
                      {isIntruder && (
                        <View style={{ flexDirection: 'row', alignItems: 'center' }}>
                          <View style={styles.riskBadge}>
                            <Text style={styles.riskText}>HIGH RISK</Text>
                          </View>
                          {/* 🔐 KEY ICON BUTTON */}
                          <TouchableOpacity style={styles.keyButton} onPress={() => auditDevice(item.ip)}>
                            <Text style={{ fontSize: 16 }}>🔐</Text>
                          </TouchableOpacity>
                        </View>
                      )}
                    </View>

                    <Text style={styles.deviceName}>{name}</Text>
                    <Text style={styles.deviceIp}>{item.ip}</Text>
                    <Text style={styles.macText}>{item.mac}</Text>

                    {isIntruder && <Text style={styles.hintText}>Long Press to Inspect • Tap 🔐 to Audit</Text>}
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

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000000' },
  header: { padding: 25, paddingTop: 60, backgroundColor: '#1C1C1E', borderBottomWidth: 1, borderBottomColor: '#2C2C2E' },
  title: { fontSize: 34, fontWeight: '900', color: '#FFFFFF', letterSpacing: 0.5 },
  subtitle: { color: '#8E8E93', marginTop: 5, fontSize: 13, fontWeight: '600', textTransform: 'uppercase' },
  content: { padding: 20, flex: 1 },
  buttonRow: { flexDirection: 'row', marginBottom: 25 },
  scanButton: {
    backgroundColor: '#0A84FF',
    padding: 18,
    borderRadius: 14,
    alignItems: 'center',
    shadowColor: '#0A84FF',
    shadowOpacity: 0.4,
    shadowRadius: 10,
    elevation: 8
  },
  buttonText: { fontWeight: '800', fontSize: 16, color: '#FFF' },
  banner: { backgroundColor: '#FF453A', padding: 10, alignItems: 'center' },
  bannerText: { color: '#FFF', fontWeight: 'bold' },
  card: {
    padding: 16,
    borderRadius: 20,
    marginBottom: 16,
    flexDirection: 'row',
    borderWidth: 1,
    // Glassmorphism effect
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 5
  },
  intruderCard: {
    backgroundColor: 'rgba(42, 5, 5, 0.8)',
    borderColor: 'rgba(255, 69, 58, 0.3)'
  },
  safeCard: {
    backgroundColor: 'rgba(5, 42, 5, 0.8)',
    borderColor: 'rgba(52, 199, 89, 0.3)'
  },
  iconContainer: { marginRight: 15 },
  statusLabel: { fontSize: 10, fontWeight: '900', letterSpacing: 1, marginBottom: 4 },
  deviceName: { color: '#fff', fontSize: 17, fontWeight: 'bold' },
  deviceIp: { color: '#999', fontSize: 14, marginTop: 2 },
  macText: { color: '#555', fontSize: 11, marginTop: 4, fontFamily: 'monospace' },
  hintText: { color: '#FF453A', fontSize: 10, marginTop: 5, fontStyle: 'italic', opacity: 0.8 },
  riskBadge: { backgroundColor: '#FF453A', paddingHorizontal: 6, paddingVertical: 2, borderRadius: 4 },
  riskText: { color: '#000', fontSize: 10, fontWeight: 'bold' },
  keyButton: { backgroundColor: '#333', borderRadius: 12, padding: 4, marginLeft: 8 }
});