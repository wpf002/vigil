import React from 'react';
import {StyleSheet, Text, View} from 'react-native';
import type {EvidenceItem} from '../types';

export function EvidenceList({items}: {items: EvidenceItem[]}) {
  if (!items.length) {
    return <Text style={styles.empty}>No evidence yet.</Text>;
  }
  return (
    <View>
      {items.map((it, i) => (
        <View key={`${it.detection_id}-${i}`} style={styles.row}>
          <Text style={styles.id}>{it.detection_id}</Text>
          <Text style={styles.summary}>{it.summary ?? it.source}</Text>
          <Text style={styles.time}>{new Date(it.fired_at).toLocaleTimeString()}</Text>
        </View>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  empty: {fontFamily: 'Menlo', fontSize: 11, color: '#52525b'},
  row: {
    paddingVertical: 6,
    borderBottomWidth: 1,
    borderBottomColor: '#27272a',
  },
  id: {fontFamily: 'Menlo', fontSize: 11, color: '#dc2626'},
  summary: {fontFamily: 'Menlo', fontSize: 12, color: '#fff', marginTop: 2},
  time: {fontFamily: 'Menlo', fontSize: 10, color: '#52525b', marginTop: 2},
});
