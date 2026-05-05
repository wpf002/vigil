import { create } from "zustand";
import type {
  AttackListFilters,
  AttackState,
  MITRETactic,
  Momentum,
} from "@/types/attacks";

interface AttackStoreState {
  filters: AttackListFilters;
  selectedAttackId: string | null;
  selectedAttack: AttackState | null;

  setFilter: <K extends keyof AttackListFilters>(
    key: K,
    value: AttackListFilters[K],
  ) => void;
  resetFilters: () => void;
  setPhaseFilter: (phase: MITRETactic | null) => void;
  setMomentumFilter: (momentum: Momentum | null) => void;
  setMinConfidence: (value: number) => void;

  selectAttack: (attackId: string | null) => void;
  setSelectedAttack: (attack: AttackState | null) => void;
}

const DEFAULT_FILTERS: AttackListFilters = {
  phase: null,
  min_confidence: 0,
  momentum: null,
  limit: 50,
  offset: 0,
};

export const useAttackStore = create<AttackStoreState>((set) => ({
  filters: DEFAULT_FILTERS,
  selectedAttackId: null,
  selectedAttack: null,

  setFilter: (key, value) =>
    set((s) => ({ filters: { ...s.filters, [key]: value } })),

  resetFilters: () => set({ filters: DEFAULT_FILTERS }),

  setPhaseFilter: (phase) =>
    set((s) => ({ filters: { ...s.filters, phase } })),

  setMomentumFilter: (momentum) =>
    set((s) => ({ filters: { ...s.filters, momentum } })),

  setMinConfidence: (value) =>
    set((s) => ({ filters: { ...s.filters, min_confidence: value } })),

  selectAttack: (attackId) =>
    set({ selectedAttackId: attackId, selectedAttack: null }),

  setSelectedAttack: (attack) => set({ selectedAttack: attack }),
}));
