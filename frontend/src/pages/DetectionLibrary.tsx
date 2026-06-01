import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Radar, Plus, Pencil, Trash2, X } from "lucide-react";
import {
  createDetection,
  deleteDetection,
  listDetections,
  updateDetection,
  type DetectionInput,
} from "@/api/detections";
import { pct, titleCase, phaseLabel } from "@/lib/format";
import { PHASE_ORDER } from "@/types/attacks";
import type { DetectionVersion } from "@/types/detections";

function fpRateClasses(rate: number | null | undefined): string {
  if (rate == null) return "text-fg-faint";
  if (rate < 0.1) return "text-success";
  if (rate < 0.25) return "text-warning";
  return "text-accent-hover";
}

function statusBadgeClasses(status: string): string {
  switch (status) {
    case "active":
      return "border-success/40 bg-success/10 text-success";
    case "deprecated":
      return "border-fg-faint/40 bg-surface-2 text-fg-muted";
    default:
      return "border-border bg-surface-2 text-fg-muted";
  }
}

export function DetectionLibrary() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<DetectionVersion | null>(null);
  const [showForm, setShowForm] = useState(false);

  const query = useQuery({
    queryKey: ["detections"],
    queryFn: listDetections,
    refetchInterval: 30_000,
  });
  const detections = query.data ?? [];

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteDetection(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["detections"] }),
    onError: (e: Error) => alert(`Delete failed: ${e.message}`),
  });

  function openNew() {
    setEditing(null);
    setShowForm(true);
  }
  function openEdit(d: DetectionVersion) {
    setEditing(d);
    setShowForm(true);
  }

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Radar size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Detection Library</h1>
        <span className="ml-auto text-[11px] font-mono text-fg-faint tabular-nums">
          {detections.length} {detections.length === 1 ? "Detection" : "Detections"}
        </span>
        <button
          type="button"
          onClick={openNew}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-mono border border-accent/40 bg-accent/10 text-accent rounded-sm hover:bg-accent/20"
        >
          <Plus size={13} /> New Detection
        </button>
      </div>
      <p className="text-[12px] font-mono text-fg-muted mb-4 -mt-3 max-w-3xl">
        Your <span className="text-fg">detection rules</span> — the logic that fires
        on incoming telemetry to surface attacks. Create, edit, and delete them here;
        automate the response in Playbooks.
      </p>

      {query.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading detections...
        </div>
      ) : query.isError ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load detections: {query.error?.message ?? "unknown error"}
        </div>
      ) : detections.length === 0 ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          No detections yet. Click <b>New Detection</b> to create one.
        </div>
      ) : (
        <div className="vigil-card overflow-hidden">
          <table className="w-full text-sm font-mono">
            <thead className="border-b border-border bg-surface-2">
              <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
                <th className="px-3 py-2">Detection ID</th>
                <th className="px-3 py-2">Tactic</th>
                <th className="px-3 py-2">Technique</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">Fires (30d)</th>
                <th className="px-3 py-2 text-right">FP Rate</th>
                <th className="px-3 py-2">Version</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {detections.map((d) => (
                <DetectionRow
                  key={d.detection_id}
                  detection={d}
                  onClick={() => navigate(`/detections/${encodeURIComponent(d.detection_id)}`)}
                  onEdit={() => openEdit(d)}
                  onDelete={() => {
                    if (confirm(`Delete detection "${d.detection_id}"?`))
                      deleteMut.mutate(d.detection_id);
                  }}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showForm && (
        <DetectionFormModal
          editing={editing}
          onClose={() => setShowForm(false)}
          onSaved={() => {
            setShowForm(false);
            qc.invalidateQueries({ queryKey: ["detections"] });
          }}
        />
      )}
    </div>
  );
}

function DetectionRow({
  detection,
  onClick,
  onEdit,
  onDelete,
}: {
  detection: DetectionVersion;
  onClick: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const perf = detection.performance;
  return (
    <tr
      onClick={onClick}
      className="border-b border-border last:border-0 hover:bg-surface-2 cursor-pointer transition-colors"
    >
      <td className="px-3 py-2 text-fg">{detection.detection_id}</td>
      <td className="px-3 py-2 text-fg-muted">{titleCase(detection.att_ck_tactic)}</td>
      <td className="px-3 py-2 text-fg-faint">{detection.att_ck_technique}</td>
      <td className="px-3 py-2">
        <span className={`vigil-badge ${statusBadgeClasses(detection.status)}`}>
          {titleCase(detection.status)}
        </span>
      </td>
      <td className="px-3 py-2 text-right text-fg tabular-nums">{perf?.total_fires ?? 0}</td>
      <td className={`px-3 py-2 text-right tabular-nums ${fpRateClasses(perf?.fp_rate)}`}>
        {perf?.fp_rate == null ? "—" : pct(perf.fp_rate)}
      </td>
      <td className="px-3 py-2 text-fg-faint">{detection.version}</td>
      <td className="px-3 py-2 text-right" onClick={(e) => e.stopPropagation()}>
        <div className="inline-flex gap-3 justify-end">
          <button
            type="button"
            onClick={onEdit}
            className="text-fg-faint hover:text-fg inline-flex items-center gap-1 text-[11px]"
          >
            <Pencil size={12} /> Edit
          </button>
          <button
            type="button"
            onClick={onDelete}
            className="text-fg-faint hover:text-accent inline-flex items-center gap-1 text-[11px]"
          >
            <Trash2 size={12} /> Delete
          </button>
        </div>
      </td>
    </tr>
  );
}

function DetectionFormModal({
  editing,
  onClose,
  onSaved,
}: {
  editing: DetectionVersion | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [detectionId, setDetectionId] = useState(editing?.detection_id ?? "");
  const [tactic, setTactic] = useState(editing?.att_ck_tactic ?? "credential-access");
  const [technique, setTechnique] = useState(editing?.att_ck_technique ?? "");
  const [notes, setNotes] = useState("");

  const mut = useMutation({
    mutationFn: (body: DetectionInput) =>
      editing ? updateDetection(editing.detection_id, body) : createDetection(body),
    onSuccess: onSaved,
    onError: (e: Error) => alert(`Save failed: ${e.message}`),
  });

  const canSave = detectionId.trim().length > 0 && tactic.length > 0;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="vigil-card p-5 w-full max-w-lg">
        <div className="flex items-center mb-4">
          <h2 className="font-mono text-fg text-lg flex-1">
            {editing ? "Edit Detection" : "New Detection"}
          </h2>
          <button type="button" onClick={onClose} className="text-fg-faint hover:text-fg">
            <X size={16} />
          </button>
        </div>

        <label className="block mb-3">
          <span className="block text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-1">
            Detection ID
          </span>
          <input
            className="vigil-input w-full text-sm"
            value={detectionId}
            disabled={!!editing}
            onChange={(e) => setDetectionId(e.target.value)}
            placeholder="e.g. CUSTOM-RDP-BRUTE-FORCE"
          />
        </label>
        <label className="block mb-3">
          <span className="block text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-1">
            Tactic
          </span>
          <select
            className="vigil-input w-full text-sm"
            value={tactic}
            onChange={(e) => setTactic(e.target.value)}
          >
            {PHASE_ORDER.map((p) => (
              <option key={p} value={p}>{phaseLabel(p)}</option>
            ))}
          </select>
        </label>
        <label className="block mb-3">
          <span className="block text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-1">
            Technique
          </span>
          <input
            className="vigil-input w-full text-sm"
            value={technique}
            onChange={(e) => setTechnique(e.target.value)}
            placeholder="e.g. T1110"
          />
        </label>
        <label className="block mb-4">
          <span className="block text-[10px] uppercase tracking-wider text-fg-faint font-mono mb-1">
            Notes
          </span>
          <textarea
            className="vigil-input w-full text-sm h-20"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="What this detection looks for…"
          />
        </label>

        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 text-[12px] font-mono border border-border bg-surface-2 text-fg-muted rounded-sm hover:text-fg"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!canSave || mut.isPending}
            onClick={() =>
              mut.mutate({
                detection_id: detectionId.trim(),
                att_ck_tactic: tactic,
                att_ck_technique: technique.trim(),
                notes: notes.trim() || undefined,
              })
            }
            className="px-3 py-1.5 text-[12px] font-mono border border-accent/50 bg-accent/15 text-accent-hover rounded-sm hover:bg-accent/25 disabled:opacity-40"
          >
            {mut.isPending ? "Saving…" : editing ? "Save Changes" : "Create Detection"}
          </button>
        </div>
      </div>
    </div>
  );
}
