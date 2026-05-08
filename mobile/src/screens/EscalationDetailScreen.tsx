import React, {useState} from 'react';
import {
  ActivityIndicator,
  ScrollView,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import {SafeAreaView} from 'react-native-safe-area-context';
import {useMutation, useQuery, useQueryClient} from '@tanstack/react-query';
import type {StackScreenProps} from '@react-navigation/stack';
import {acknowledgeEscalation} from '../api/queue';
import {getAttack} from '../api/attacks';
import {ConfidenceBar} from '../components/ConfidenceBar';
import {EvidenceList} from '../components/EvidenceList';
import {PhaseBadge} from '../components/PhaseBadge';
import type {RootStackParamList} from '../navigation/AppNavigator';

type Props = StackScreenProps<RootStackParamList, 'EscalationDetail'>;

export function EscalationDetailScreen({route, navigation}: Props) {
  const qc = useQueryClient();
  const {queue_id, attack_id} = route.params;
  const [toast, setToast] = useState<string | null>(null);

  const attack = useQuery({queryKey: ['attack', attack_id], queryFn: () => getAttack(attack_id)});

  const ackMut = useMutation({
    mutationFn: () => acknowledgeEscalation(queue_id),
    onSuccess: () => {
      setToast('Acknowledged');
      qc.invalidateQueries({queryKey: ['queue']});
      setTimeout(() => navigation.goBack(), 800);
    },
  });

  if (attack.isLoading) {
    return (
      <SafeAreaView style={styles.container}>
        <ActivityIndicator color="#dc2626" />
      </SafeAreaView>
    );
  }
  if (!attack.data) {
    return (
      <SafeAreaView style={styles.container}>
        <Text style={styles.error}>Attack not found.</Text>
      </SafeAreaView>
    );
  }

  const a = attack.data;

  return (
    <SafeAreaView style={styles.container} edges={['bottom']}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.name}>{a.name}</Text>
        <View style={styles.row}>
          <PhaseBadge phase={a.current_phase} />
          {a.momentum != null && (
            <Text style={styles.momentum}>↗ momentum {(a.momentum * 100).toFixed(0)}%</Text>
          )}
        </View>

        <View style={styles.section}>
          <ConfidenceBar value={a.confidence} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Narrative</Text>
          {a.narrative ? (
            <Text style={styles.narrative}>{a.narrative}</Text>
          ) : (
            <Text style={styles.narrativeMissing}>Generating…</Text>
          )}
        </View>

        {a.analyst_summary && (
          <View style={styles.summaryBox}>
            <Text style={styles.summaryLabel}>Analyst summary</Text>
            <Text style={styles.summary}>{a.analyst_summary}</Text>
          </View>
        )}

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Evidence ({a.evidence?.length ?? 0})</Text>
          <EvidenceList items={a.evidence ?? []} />
        </View>

        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Recommended actions</Text>
          {(a.recommended_actions ?? []).map((act, i) => (
            <View key={i} style={styles.action}>
              <Text style={styles.actionType}>{act.action_type}</Text>
              <Text style={styles.actionTarget}>{act.target_entity}</Text>
              {act.priority === 'immediate' && (
                <Text style={styles.actionPriority}>IMMEDIATE</Text>
              )}
            </View>
          ))}
        </View>
      </ScrollView>

      <View style={styles.actions}>
        <TouchableOpacity
          style={styles.ack}
          onPress={() => ackMut.mutate()}
          disabled={ackMut.isPending}>
          <Text style={styles.ackText}>{ackMut.isPending ? 'Acknowledging…' : 'Acknowledge'}</Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={styles.read}
          onPress={() => navigation.navigate('AttackDetail', {attack_id})}>
          <Text style={styles.readText}>Open attack</Text>
        </TouchableOpacity>
      </View>

      {toast && (
        <View style={styles.toast}>
          <Text style={styles.toastText}>{toast}</Text>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#0a0a0a'},
  content: {padding: 16, paddingBottom: 100},
  error: {color: '#dc2626', fontFamily: 'Menlo', textAlign: 'center', marginTop: 40},
  name: {fontFamily: 'Menlo', fontSize: 18, color: '#fff', marginBottom: 8},
  row: {flexDirection: 'row', alignItems: 'center', gap: 10, marginBottom: 14},
  momentum: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af'},
  section: {marginBottom: 18},
  sectionLabel: {fontFamily: 'Menlo', fontSize: 10, color: '#52525b', letterSpacing: 1, marginBottom: 6},
  narrative: {fontFamily: 'Menlo', fontSize: 13, color: '#fff', lineHeight: 19},
  narrativeMissing: {fontFamily: 'Menlo', fontSize: 12, color: '#52525b', fontStyle: 'italic'},
  summaryBox: {backgroundColor: 'rgba(220,38,38,0.08)', borderColor: 'rgba(220,38,38,0.4)', borderWidth: 1, padding: 12, borderRadius: 2, marginBottom: 14},
  summaryLabel: {fontFamily: 'Menlo', fontSize: 10, color: '#dc2626', letterSpacing: 1, marginBottom: 4},
  summary: {fontFamily: 'Menlo', fontSize: 13, color: '#fff', lineHeight: 19},
  action: {paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: '#27272a'},
  actionType: {fontFamily: 'Menlo', fontSize: 12, color: '#fff'},
  actionTarget: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af', marginTop: 2},
  actionPriority: {fontFamily: 'Menlo', fontSize: 9, color: '#dc2626', letterSpacing: 1, marginTop: 2},
  actions: {position: 'absolute', bottom: 0, left: 0, right: 0, flexDirection: 'row', padding: 16, gap: 8, backgroundColor: '#0a0a0a', borderTopColor: '#27272a', borderTopWidth: 1},
  ack: {flex: 1, backgroundColor: '#dc2626', paddingVertical: 12, borderRadius: 2, alignItems: 'center'},
  ackText: {fontFamily: 'Menlo', color: '#fff', fontSize: 13, letterSpacing: 1},
  read: {paddingHorizontal: 14, paddingVertical: 12, borderColor: '#27272a', borderWidth: 1, borderRadius: 2, alignItems: 'center'},
  readText: {fontFamily: 'Menlo', color: '#9ca3af', fontSize: 13},
  toast: {position: 'absolute', top: 80, alignSelf: 'center', backgroundColor: '#1a1a1a', borderColor: '#27272a', borderWidth: 1, paddingHorizontal: 16, paddingVertical: 10, borderRadius: 2},
  toastText: {fontFamily: 'Menlo', color: '#fff', fontSize: 12},
});
