import React from 'react';
import {StyleSheet, Text, View} from 'react-native';

export function ConfidenceBar({value}: {value: number}) {
  const pct = Math.max(0, Math.min(1, value));
  const color = pct >= 0.85 ? '#dc2626' : pct >= 0.7 ? '#f59e0b' : '#9ca3af';
  return (
    <View>
      <View style={styles.track}>
        <View style={[styles.fill, {width: `${pct * 100}%`, backgroundColor: color}]} />
      </View>
      <Text style={styles.label}>Confidence: {(pct * 100).toFixed(0)}%</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  track: {
    height: 6,
    backgroundColor: '#27272a',
    borderRadius: 1,
    overflow: 'hidden',
  },
  fill: {
    height: 6,
  },
  label: {
    marginTop: 4,
    fontFamily: 'Menlo',
    fontSize: 10,
    color: '#9ca3af',
  },
});
