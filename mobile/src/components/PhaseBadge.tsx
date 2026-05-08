import React from 'react';
import {StyleSheet, Text, View} from 'react-native';

export function PhaseBadge({phase}: {phase: string}) {
  return (
    <View style={styles.badge}>
      <Text style={styles.text}>{phase.replace(/-/g, ' ').toUpperCase()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 2,
    backgroundColor: '#27272a',
    borderWidth: 1,
    borderColor: '#3f3f46',
    alignSelf: 'flex-start',
  },
  text: {
    fontFamily: 'Menlo',
    fontSize: 9,
    color: '#9ca3af',
    letterSpacing: 1,
  },
});
