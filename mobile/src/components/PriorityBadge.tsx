import React from 'react';
import {StyleSheet, Text, View} from 'react-native';

const STYLES_BY_PRIORITY = {
  critical: {bg: '#7f1d1d', fg: '#fee2e2'},
  high: {bg: '#9a3412', fg: '#ffedd5'},
  medium: {bg: '#854d0e', fg: '#fef3c7'},
  low: {bg: '#1e3a8a', fg: '#dbeafe'},
} as const;

export function PriorityBadge({priority}: {priority: keyof typeof STYLES_BY_PRIORITY | string}) {
  const style = STYLES_BY_PRIORITY[priority as keyof typeof STYLES_BY_PRIORITY] ?? {
    bg: '#27272a',
    fg: '#9ca3af',
  };
  return (
    <View style={[styles.badge, {backgroundColor: style.bg}]}>
      <Text style={[styles.text, {color: style.fg}]}>{priority.toUpperCase()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 2,
    alignSelf: 'flex-start',
  },
  text: {
    fontFamily: 'Menlo',
    fontSize: 9,
    letterSpacing: 1,
  },
});
