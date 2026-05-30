import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Plus, Trash2, Wrench } from "lucide-react";
import {
  createPlaybookDefinition,
  deletePlaybookDefinition,
  listPlaybookDefinitions,
  updatePlaybookDefinition,
  type DefinitionAction,
  type PlaybookDefinition,
} from "@/api/playbooks";
import { PHASE_ORDER } from "@/types/attacks";
import { phaseLabel, titleCase } from "@/lib/format";

const ENRICHMENT_ACTIONS = ["ioc_lookup", "asset_context", "user_context"];
const RESPONSE_ACTIONS = [
  "isolate_host",
  "kill_process",
  "reset_credentials",
  "capture_forensic_snapshot",
  "block_protocol",
  "review_auth_logs",
  "disable_account",
  "block_ip",
];

interface DraftAction extends DefinitionAction {
  priority: string;
}

const EMPTY_ACTION: DraftAction = { action_type: "isolate_host", target: "affected_host", priority: "immediate" };

export function PlaybookBuilder() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [name, setName] = useState("");
  const [mode, setMode] = useState("auto");
  const [phase, setPhase] = useState("");
  const [status, setStatus] = useState("");
  const [minConfidence, setMinConfidence] = useState(0.7);
  const [actions, setActions] = useState<DraftAction[]>([{ ...EMPTY_ACTION }]);

  const defs = useQuery({ queryKey: ["playbook-definitions"], queryFn: listPlaybookDefinitions });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["playbook-definitions"] });

  const createMutation = useMutation({
    mutationFn: () =>
      createPlaybookDefinition({
        name: name.trim(),
        trigger_mode: mode,
        trigger_phase: phase || null,
        trigger_status: status || null,
        min_confidence: minConfidence,
        actions: actions.filter((a) => a.action_type && a.target),
      }),
    onSuccess: () => {
      invalidate();
      setName("");
      setPhase("");
      setStatus("");
      setActions([{ ...EMPTY_ACTION }]);
    },
    onError: (e) => alert(`Could not save playbook: ${e instanceof Error ? e.message : e}`),
  });

  const toggleMutation = useMutation({
    mutationFn: (d: PlaybookDefinition) =>
      updatePlaybookDefinition(d.definition_id, { enabled: !d.enabled }),
    onSuccess: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deletePlaybookDefinition(id),
    onSuccess: invalidate,
  });

  const canSave = name.trim().length > 0 && actions.some((a) => a.action_type && a.target);

  function setAction(i: number, patch: Partial<DraftAction>) {
    setActions((prev) => prev.map((a, idx) => (idx === i ? { ...a, ...patch } : a)));
  }

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <button
        type="button"
        onClick={() => navigate("/playbooks")}
        className="mb-4 flex items-center gap-1 text-[12px] font-mono text-fg-muted hover:text-fg"
      >
        <ArrowLeft size={13} /> Back to Playbooks
      </button>

      <div className="mb-5 flex items-center gap-2">
        <Wrench size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Playbook Builder</h1>
      </div>

      {/* ── builder form ─────────────────────────────────────────── */}
      <div className="vigil-card p-4 mb-6">
        <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-3">
          New Playbook
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          <Field label="Name">
            <input
              className="vigil-input w-full text-sm"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Ransomware Rapid Containment"
            />
          </Field>
          <Field label="Trigger mode">
            <select className="vigil-input w-full text-sm" value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="auto">Auto — fires on matching attacks</option>
              <option value="manual">Manual — analyst-run only</option>
            </select>
          </Field>
          <Field label="Phase">
            <select className="vigil-input w-full text-sm" value={phase} onChange={(e) => setPhase(e.target.value)}>
              <option value="">Any phase</option>
              {PHASE_ORDER.map((p) => (
                <option key={p} value={p}>{phaseLabel(p)}</option>
              ))}
            </select>
          </Field>
          <Field label="Status">
            <select className="vigil-input w-full text-sm" value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">Any status</option>
              <option value="Observed">Observed</option>
              <option value="Confirmed">Confirmed</option>
            </select>
          </Field>
          {mode === "auto" && (
            <Field label={`Min confidence — ${Math.round(minConfidence * 100)}%`}>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={minConfidence}
                onChange={(e) => setMinConfidence(parseFloat(e.target.value))}
                className="accent-accent w-full"
              />
            </Field>
          )}
        </div>

        {/* actions editor */}
        <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
          Actions
        </div>
        <div className="space-y-2 mb-3">
          {actions.map((a, i) => {
            const isEnrich = ENRICHMENT_ACTIONS.includes(a.action_type);
            return (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <select
                  className="vigil-input text-xs"
                  value={a.action_type}
                  onChange={(e) => setAction(i, { action_type: e.target.value })}
                >
                  <optgroup label="Enrichment (read-only)">
                    {ENRICHMENT_ACTIONS.map((t) => (
                      <option key={t} value={t}>{titleCase(t)}</option>
                    ))}
                  </optgroup>
                  <optgroup label="Response">
                    {RESPONSE_ACTIONS.map((t) => (
                      <option key={t} value={t}>{titleCase(t)}</option>
                    ))}
                  </optgroup>
                </select>
                <input
                  className="vigil-input text-xs flex-1 min-w-[140px]"
                  value={a.target}
                  onChange={(e) => setAction(i, { target: e.target.value })}
                  placeholder="target (e.g. affected_host)"
                />
                <select
                  className="vigil-input text-xs"
                  value={a.priority}
                  onChange={(e) => setAction(i, { priority: e.target.value })}
                  disabled={isEnrich}
                  title={isEnrich ? "Enrichment runs first, automatically" : ""}
                >
                  <option value="immediate">Immediate</option>
                  <option value="follow_up">Follow-up</option>
                </select>
                <span
                  className={`text-[9px] uppercase tracking-wider px-1 py-px rounded-sm border ${
                    isEnrich
                      ? "border-info/40 bg-info/10 text-info"
                      : "border-accent/40 bg-accent/10 text-accent-hover"
                  }`}
                >
                  {isEnrich ? "enrich" : "response"}
                </span>
                <button
                  type="button"
                  onClick={() => setActions((prev) => prev.filter((_, idx) => idx !== i))}
                  className="text-fg-faint hover:text-accent"
                  aria-label="Remove action"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            );
          })}
        </div>
        <button
          type="button"
          onClick={() => setActions((prev) => [...prev, { ...EMPTY_ACTION }])}
          className="inline-flex items-center gap-1 text-[11px] font-mono text-fg-muted hover:text-fg mb-4"
        >
          <Plus size={12} /> Add action
        </button>

        <div className="flex justify-end">
          <button
            type="button"
            disabled={!canSave || createMutation.isPending}
            onClick={() => createMutation.mutate()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-mono border border-accent/50 bg-accent/15 text-accent-hover rounded-sm hover:bg-accent/25 disabled:opacity-40"
          >
            {createMutation.isPending ? "Saving…" : "Create Playbook"}
          </button>
        </div>
      </div>

      {/* ── existing definitions ─────────────────────────────────── */}
      <div className="text-[11px] uppercase font-mono text-fg-faint tracking-wider mb-2">
        Your Playbooks ({defs.data?.length ?? 0})
      </div>
      {defs.isLoading ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">Loading…</div>
      ) : (defs.data?.length ?? 0) === 0 ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          No authored playbooks yet. Build one above.
        </div>
      ) : (
        <div className="space-y-2">
          {defs.data!.map((d) => (
            <div key={d.definition_id} className="vigil-card p-3 flex items-center gap-3">
              <div className="flex-1 min-w-0">
                <div className="text-sm font-mono text-fg">{d.name}</div>
                <div className="text-[11px] font-mono text-fg-muted">
                  {d.trigger_mode} · {d.trigger_phase ? phaseLabel(d.trigger_phase as never) : "any phase"}
                  {d.trigger_status ? ` · ${d.trigger_status}` : ""}
                  {d.trigger_mode === "auto" ? ` · ≥${Math.round(d.min_confidence * 100)}%` : ""}
                  {` · ${d.actions.length} action${d.actions.length === 1 ? "" : "s"}`}
                </div>
              </div>
              <button
                type="button"
                onClick={() => toggleMutation.mutate(d)}
                className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-sm border ${
                  d.enabled
                    ? "border-success/40 bg-success/10 text-success"
                    : "border-border-strong bg-surface-2 text-fg-faint"
                }`}
              >
                {d.enabled ? "Enabled" : "Disabled"}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (confirm(`Delete playbook "${d.name}"?`)) deleteMutation.mutate(d.definition_id);
                }}
                className="text-fg-faint hover:text-accent"
                aria-label="Delete playbook"
              >
                <Trash2 size={15} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-1">
        {label}
      </span>
      {children}
    </label>
  );
}
