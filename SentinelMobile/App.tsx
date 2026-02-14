import React, { useState } from 'react';
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
  Modal
} from 'react-native';

interface Device {
  ip: string;
  mac: string;
  status: string;
}

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [trustedMacs, setTrustedMacs] = useState<string[]>([]);

  // Connection Logic
  const BASE_URL = Platform.OS === 'android'
    ? 'http://10.0.2.2:3000'
    : 'http://localhost:3000';

  // 🧠 ENHANCED VENDOR DB
  const getDeviceName = (mac: string) => {
    const cleanMac = mac.toLowerCase();
    if (cleanMac.startsWith("6c")) return " Apple Device";
    if (cleanMac.startsWith("ba")) return "🤖 Android Phone";
    if (cleanMac.startsWith("1:0")) return "🌐 Gateway Router";
    if (cleanMac.startsWith("00:50")) return "🎮 PlayStation";
    if (cleanMac.startsWith("a4")) return "📺 LG Smart TV";
    return "Unknown Device";
  };

  const fetchScan = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${BASE_URL}/api/scan`);
      const data = await response.json();

      if (data.error) {
        Alert.alert("Scan Error", data.message || "Unknown error occurred.");
        return;
      }

      if (data.raw_output) {
        Alert.alert("Scan Error", "Received raw output instead of JSON: " + data.raw_output);
        return;
      }

      setDevices(data.devices || []);
    } catch (error) {
      Alert.alert("Connection Error", "Could not connect to Sentinel Agent. Check if the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const toggleTrust = (mac: string) => {
    if (trustedMacs.includes(mac)) {
      setTrustedMacs(trustedMacs.filter(id => id !== mac)); // Untrust
    } else {
      Alert.alert(
        "Trust Device?",
        "Do you want to mark this device as safe?",
        [
          { text: "Cancel", style: "cancel" },
          {
            text: "Mark as Safe",
            onPress: () => setTrustedMacs([...trustedMacs, mac])
          }
        ]
      );
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.title}>🛡️ Sentinel Pro</Text>
        <Text style={styles.subtitle}>
          {devices.length} Devices Online • {devices.length - trustedMacs.length} Alerts
        </Text>
      </View>

      <View style={styles.content}>
        <TouchableOpacity style={styles.scanButton} onPress={fetchScan}>
          {loading ? (
            <ActivityIndicator color="#000" />
          ) : (
            <Text style={styles.buttonText}>🚀 SCAN NETWORK</Text>
          )}
        </TouchableOpacity>

        <FlatList
          data={devices}
          keyExtractor={(item) => item.mac + item.ip}
          extraData={trustedMacs}
          renderItem={({ item }) => {
            const name = getDeviceName(item.mac);
            // It is trusted if it's in our list OR if it's a known router
            const isTrusted = trustedMacs.includes(item.mac) || name.includes("Router");
            const isIntruder = !isTrusted;

            return (
              <TouchableOpacity
                activeOpacity={0.7}
                onPress={() => toggleTrust(item.mac)}
              >
                <View style={[styles.card, isIntruder ? styles.intruderCard : styles.safeCard]}>
                  <View style={styles.iconContainer}>
                    <Text style={{ fontSize: 28 }}>
                      {isIntruder ? '🚨' : '🛡️'}
                    </Text>
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={[styles.statusLabel, { color: isIntruder ? '#FF453A' : '#30D158' }]}>
                      {isIntruder ? "UNAUTHORIZED" : "SECURE DEVICE"}
                    </Text>
                    <Text style={styles.deviceName}>{name}</Text>
                    <Text style={styles.deviceIp}>{item.ip}</Text>
                    <Text style={styles.macText}>{item.mac}</Text>
                  </View>
                  {isIntruder && (
                    <View style={styles.actionBadge}>
                      <Text style={styles.actionText}>FIX</Text>
                    </View>
                  )}
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
  scanButton: {
    backgroundColor: '#0A84FF',
    padding: 18,
    borderRadius: 14,
    alignItems: 'center',
    marginBottom: 25,
    shadowColor: '#0A84FF',
    shadowOpacity: 0.4,
    shadowRadius: 10,
    elevation: 8
  },
  buttonText: { fontWeight: '800', fontSize: 16, color: '#FFF' },
  card: {
    padding: 16,
    borderRadius: 16,
    marginBottom: 14,
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1
  },
  intruderCard: {
    backgroundColor: '#1A0505',
    borderColor: '#5e1010'
  },
  safeCard: {
    backgroundColor: '#051A05',
    borderColor: '#0e3b12'
  },
  iconContainer: { marginRight: 15 },
  statusLabel: { fontSize: 10, fontWeight: '900', letterSpacing: 1, marginBottom: 4 },
  deviceName: { color: '#fff', fontSize: 17, fontWeight: 'bold' },
  deviceIp: { color: '#999', fontSize: 14, marginTop: 2 },
  macText: { color: '#555', fontSize: 11, marginTop: 4, fontFamily: 'monospace' },
  actionBadge: { backgroundColor: 'rgba(255, 69, 58, 0.2)', paddingHorizontal: 10, paddingVertical: 5, borderRadius: 8 },
  actionText: { color: '#FF453A', fontSize: 10, fontWeight: 'bold' }
});