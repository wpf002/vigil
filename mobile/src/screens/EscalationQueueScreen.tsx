import React, {useEffect, useMemo, useState} from 'react';
import {
  ActivityIndicator,
  FlatList,
  RefreshControl,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import {SafeAreaView} from 'react-native-safe-area-context';
import {useQuery} from '@tanstack/react-query';
import type {StackScreenProps} from '@react-navigation/stack';
import {listQueue} from '../api/queue';
import {PhaseBadge} from '../components/PhaseBadge';
import {PriorityBadge} from '../components/PriorityBadge';
import {SLATimer} from '../components/SLATimer';
import {useAuth} from '../context/AuthContext';
import type {EscalationQueueItem} from '../types';
import type {RootStackParamList} from '../navigation/AppNavigator';

type Props = StackScreenProps<RootStackParamList, 'EscalationQueue'>;

const FILTERS = ['All', 'Critical', 'High', 'Mine'] as const;

export function EscalationQueueScreen({navigation}: Props) {
  const {user} = useAuth();
  const [filter, setFilter] = useState<typeof FILTERS[number]>('All');

  const q = useQuery({
    queryKey: ['queue'],
    queryFn: listQueue,
    refetchInterval: 30_000,
  });

  // Auto-refresh on mount.
  useEffect(() => {
    q.refetch();
  }, []);

  const items = useMemo(() => {
    const list = q.data ?? [];
    switch (filter) {
      case 'Critical':
        return list.filter(i => i.priority === 'critical');
      case 'High':
        return list.filter(i => i.priority === 'high');
      case 'Mine':
        return list.filter(i => i.assigned_to === user?.user_id);
      default:
        return list;
    }
  }, [q.data, filter, user]);

  return (
    <SafeAreaView style={styles.container} edges={['bottom']}>
      <View style={styles.tabs}>
        {FILTERS.map(f => (
          <TouchableOpacity
            key={f}
            onPress={() => setFilter(f)}
            style={[styles.tab, filter === f && styles.tabActive]}>
            <Text style={[styles.tabText, filter === f && styles.tabTextActive]}>{f}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {q.isLoading ? (
        <View style={styles.loading}>
          <ActivityIndicator color="#dc2626" />
        </View>
      ) : (
        <FlatList
          data={items}
          keyExtractor={i => i.queue_id}
          refreshControl={<RefreshControl refreshing={q.isRefetching} onRefresh={q.refetch} tintColor="#dc2626" />}
          contentContainerStyle={items.length === 0 ? styles.emptyContainer : undefined}
          renderItem={({item}) => (
            <Row item={item} onPress={() => navigation.navigate('EscalationDetail', {queue_id: item.queue_id, attack_id: item.attack_id})} />
          )}
          ListEmptyComponent={() => <Text style={styles.empty}>No escalations.</Text>}
        />
      )}
    </SafeAreaView>
  );
}

function Row({item, onPress}: {item: EscalationQueueItem; onPress: () => void}) {
  return (
    <TouchableOpacity onPress={onPress} style={styles.row}>
      <View style={styles.rowHeader}>
        <Text style={styles.tenantName}>{item.tenant_name}</Text>
        <PriorityBadge priority={item.priority} />
      </View>
      <Text style={styles.attackName} numberOfLines={2}>{item.attack_name}</Text>
      <View style={styles.rowFooter}>
        <PhaseBadge phase={item.current_phase} />
        <SLATimer deadline={item.sla_deadline} breached={item.sla_breached} />
      </View>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  container: {flex: 1, backgroundColor: '#0a0a0a'},
  tabs: {flexDirection: 'row', borderBottomWidth: 1, borderBottomColor: '#27272a', paddingHorizontal: 12, paddingVertical: 8, gap: 6},
  tab: {paddingHorizontal: 12, paddingVertical: 6, borderRadius: 2, borderWidth: 1, borderColor: '#27272a'},
  tabActive: {borderColor: '#dc2626', backgroundColor: 'rgba(220,38,38,0.1)'},
  tabText: {fontFamily: 'Menlo', fontSize: 11, color: '#9ca3af', letterSpacing: 1},
  tabTextActive: {color: '#dc2626'},
  loading: {flex: 1, alignItems: 'center', justifyContent: 'center'},
  empty: {fontFamily: 'Menlo', fontSize: 12, color: '#52525b', textAlign: 'center'},
  emptyContainer: {flex: 1, alignItems: 'center', justifyContent: 'center'},
  row: {paddingHorizontal: 16, paddingVertical: 14, borderBottomWidth: 1, borderBottomColor: '#1a1a1a'},
  rowHeader: {flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6},
  tenantName: {fontFamily: 'Menlo', fontSize: 11, color: '#52525b'},
  attackName: {fontFamily: 'Menlo', fontSize: 14, color: '#fff', marginBottom: 8},
  rowFooter: {flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between'},
});
