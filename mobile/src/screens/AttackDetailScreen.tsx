import React from 'react';
import {ActivityIndicator, ScrollView, StyleSheet, Text, View} from 'react-native';
import {SafeAreaView} from 'react-native-safe-area-context';
import {useQuery} from '@tanstack/react-query';
import type {StackScreenProps} from '@react-navigation/stack';
import {getAttack} from '../api/attacks';
import {ConfidenceBar} from '../components/ConfidenceBar';
import {EvidenceList} from '../components/EvidenceList';
import {PhaseBadge} from '../components/PhaseBadge';
import type {RootStackParamList} from '../navigation/AppNavigator';

type Props = StackScreenProps<RootStackParamList, 'AttackDetail'>;

export function AttackDetailScreen({route}: Props) {
  const {attack_id} = route.params;
  const q = useQuery({queryKey: ['attack', attack_id], queryFn: () => getAttack(attack_id)});

  if (q.isLoading) {
    return (
      <SafeAreaView style={styles.container}>
        <ActivityIndicator color="#dc2626" />
      </SafeAreaView>
    );
  }
  if (!q.data) {
    return (
      <SafeAreaView style={styles.container}>
        <Text style={styles.error}>Not found.</Text>
      </SafeAreaView>
    );
  }

  const a = q.data;
  return (
    <SafeAreaView style={styles.container} edges={['bottom']}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.name}>{a.name}</Text>
        <View style={styles.row}>
          <PhaseBadge phase={a.current_phase} />
          <Text style={styles.status}>{a.status}</Text>
        </View>

        <View style={styles.section}>
          <ConfidenceBar value={a.confidence} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Narrative</Text>
          {a.narrative ? (
            <Text style={styles.narrative}>{a.narrative}</Text>
          ) : (
            <Text style={styles.narrativeMissing}>—</Text>
          )}
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>All evidence ({a.evidence?.length ?? 0})</Text>
          <EvidenceList items={a.evidence ?? []} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Recommended actions</Text>
          {(a.recommended_actions ?? []).map((act, i) => (
            <View key={i} style={styles.action}>
              <Text style={styles.actionType}>{act.action_type}</Text>
              <Text style={styles.actionTarget}>{act.target_entity}</Text>
              {act.completed && <Text style={styles.actionDone}>✓ completed</Text>}
            </View>
          ))}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#0a0a0a'},
  content: {padding: 16},
  error: {color: '#dc2626', fontFamily: 'Menlo', textAlign: 'center', marginTop: 40},
  name: {fontFamily: 'Menlo', fontSize: 18, color: '#fff', marginBottom: 8},
  row: {flexDirection: 'row', gap: 10, alignItems: 'center', marginBottom: 14},
  status: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af'},
  section: {marginBottom: 18},
  sectionLabel: {fontFamily: 'Menlo', fontSize: 10, color: '#52525b', letterSpacing: 1, marginBottom: 6},
  narrative: {fontFamily: 'Menlo', fontSize: 13, color: '#fff', lineHeight: 19},
  narrativeMissing: {fontFamily: 'Menlo', fontSize: 12, color: '#52525b'},
  action: {paddingVertical: 6, borderBottomColor: '#27272a', borderBottomWidth: 1},
  actionType: {fontFamily: 'Menlo', fontSize: 12, color: '#fff'},
  actionTarget: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af', marginTop: 2},
  actionDone: {fontFamily: 'Menlo', fontSize: 10, color: '#22c55e', marginTop: 2},
});
