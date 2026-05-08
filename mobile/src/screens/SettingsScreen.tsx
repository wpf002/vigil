import React, {useEffect, useState} from 'react';
import {
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import {SafeAreaView} from 'react-native-safe-area-context';
import {getBaseUrl, getRefreshToken, setBaseUrl} from '../api/client';
import {logout} from '../api/auth';
import {useAuth} from '../context/AuthContext';

export function SettingsScreen() {
  const {user, signOut} = useAuth();
  const [url, setUrl] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    getBaseUrl().then(setUrl);
  }, []);

  async function save() {
    await setBaseUrl(url);
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  }

  async function handleLogout() {
    const refresh = (await getRefreshToken()) ?? '';
    if (refresh) {
      try {
        await logout(refresh);
      } catch {
        // best effort
      }
    }
    await signOut();
  }

  return (
    <SafeAreaView style={styles.container} edges={['bottom']}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.heading}>Settings</Text>

        <View style={styles.box}>
          <Text style={styles.label}>Account</Text>
          <Text style={styles.value}>{user?.email ?? '—'}</Text>
          <Text style={styles.subValue}>{user?.role}</Text>
        </View>

        <View style={styles.box}>
          <Text style={styles.label}>API base URL</Text>
          <TextInput
            value={url}
            onChangeText={setUrl}
            style={styles.input}
            autoCapitalize="none"
            keyboardType="url"
          />
          <TouchableOpacity onPress={save} style={styles.smallButton}>
            <Text style={styles.smallButtonText}>{saved ? 'Saved ✓' : 'Save'}</Text>
          </TouchableOpacity>
        </View>

        <TouchableOpacity onPress={handleLogout} style={styles.logout}>
          <Text style={styles.logoutText}>Log out</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#0a0a0a'},
  content: {padding: 16},
  heading: {fontFamily: 'Menlo', fontSize: 18, color: '#fff', marginBottom: 14},
  box: {marginBottom: 14, padding: 12, backgroundColor: '#1a1a1a', borderColor: '#27272a', borderWidth: 1, borderRadius: 2},
  label: {fontFamily: 'Menlo', fontSize: 10, color: '#52525b', letterSpacing: 1, marginBottom: 4},
  value: {fontFamily: 'Menlo', fontSize: 14, color: '#fff'},
  subValue: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af', marginTop: 2},
  input: {
    backgroundColor: '#0a0a0a', borderWidth: 1, borderColor: '#27272a',
    borderRadius: 2, paddingHorizontal: 10, paddingVertical: 8,
    color: '#fff', fontFamily: 'Menlo', fontSize: 13, marginBottom: 8,
  },
  smallButton: {alignSelf: 'flex-start', paddingHorizontal: 12, paddingVertical: 6, borderColor: '#27272a', borderWidth: 1, borderRadius: 2},
  smallButtonText: {fontFamily: 'Menlo', fontSize: 12, color: '#9ca3af'},
  logout: {marginTop: 24, padding: 14, borderColor: '#7f1d1d', borderWidth: 1, borderRadius: 2, alignItems: 'center'},
  logoutText: {fontFamily: 'Menlo', color: '#dc2626', fontSize: 13, letterSpacing: 1},
});
