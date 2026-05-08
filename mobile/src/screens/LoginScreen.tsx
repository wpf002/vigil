import React, {useState} from 'react';
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import {SafeAreaView} from 'react-native-safe-area-context';
import {login} from '../api/auth';
import {useAuth} from '../context/AuthContext';

export function LoginScreen() {
  const {setAuthenticated} = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handle() {
    setLoading(true);
    setError(null);
    try {
      const res = await login(email, password);
      setAuthenticated(res.user);
    } catch (e: unknown) {
      setError(extractError(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
        style={styles.flex}>
        <View style={styles.inner}>
          <View style={styles.brand}>
            <View style={styles.dot} />
            <Text style={styles.brandText}>VIGIL</Text>
          </View>
          <Text style={styles.heading}>Analyst sign-in</Text>

          <Text style={styles.label}>Email</Text>
          <TextInput
            style={styles.input}
            value={email}
            onChangeText={setEmail}
            placeholder="you@example.com"
            placeholderTextColor="#52525b"
            autoCapitalize="none"
            keyboardType="email-address"
            autoComplete="email"
          />

          <Text style={styles.label}>Password</Text>
          <TextInput
            style={styles.input}
            value={password}
            onChangeText={setPassword}
            placeholder="••••••••"
            placeholderTextColor="#52525b"
            secureTextEntry
          />

          {error && <Text style={styles.error}>{error}</Text>}

          <TouchableOpacity
            disabled={loading || !email || !password}
            onPress={handle}
            style={[styles.button, (loading || !email || !password) && styles.buttonDisabled]}>
            {loading ? (
              <ActivityIndicator color="#fff" size="small" />
            ) : (
              <Text style={styles.buttonText}>Sign in</Text>
            )}
          </TouchableOpacity>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function extractError(e: unknown): string {
  const err = e as {response?: {data?: {detail?: string}}; message?: string};
  return err.response?.data?.detail ?? err.message ?? 'Sign-in failed.';
}

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#0a0a0a'},
  flex: {flex: 1},
  inner: {flex: 1, padding: 24, justifyContent: 'center'},
  brand: {flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 30},
  dot: {width: 8, height: 8, backgroundColor: '#dc2626'},
  brandText: {fontFamily: 'Menlo', fontSize: 14, letterSpacing: 4, color: '#fff'},
  heading: {fontFamily: 'Menlo', fontSize: 18, color: '#fff', marginBottom: 24},
  label: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af', marginBottom: 4, marginTop: 8},
  input: {
    backgroundColor: '#1a1a1a',
    borderWidth: 1,
    borderColor: '#27272a',
    borderRadius: 2,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: '#fff',
    fontFamily: 'Menlo',
    fontSize: 14,
  },
  error: {color: '#dc2626', fontFamily: 'Menlo', fontSize: 12, marginTop: 12},
  button: {
    marginTop: 24,
    backgroundColor: '#dc2626',
    borderRadius: 2,
    paddingVertical: 12,
    alignItems: 'center',
  },
  buttonDisabled: {opacity: 0.4},
  buttonText: {fontFamily: 'Menlo', color: '#fff', fontSize: 14, letterSpacing: 1},
});
