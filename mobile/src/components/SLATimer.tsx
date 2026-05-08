import React, {useEffect, useState} from 'react';
import {StyleSheet, Text} from 'react-native';

export function SLATimer({deadline, breached}: {deadline: string | null; breached: boolean}) {
  const [, setTick] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 1000);
    return () => clearInterval(id);
  }, []);

  if (breached) {
    return <Text style={[styles.text, styles.breached]}>SLA BREACHED</Text>;
  }
  if (!deadline) {
    return <Text style={styles.text}>—</Text>;
  }

  const ms = new Date(deadline).getTime() - Date.now();
  const seconds = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  const urgent = ms < 5 * 60 * 1000;
  return (
    <Text style={[styles.text, urgent && styles.urgent]}>
      {m}m {s}s
    </Text>
  );
}

const styles = StyleSheet.create({
  text: {
    fontFamily: 'Menlo',
    fontSize: 11,
    color: '#9ca3af',
  },
  urgent: {
    color: '#dc2626',
  },
  breached: {
    color: '#dc2626',
    fontWeight: '700',
  },
});
