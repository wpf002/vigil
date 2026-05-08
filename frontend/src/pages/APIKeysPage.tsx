import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Key, Copy, X, Trash2, AlertTriangle } from "lucide-react";
import {
  createAPIKey,
  listAPIKeys,
  revokeAPIKey,
  type APIKeyCreated,
} from "@/api/settings";

const SCOPES = [
  "read:attacks",
  "read:detections",
  "write:signals",
  "read:reports",
];

export function APIKeysPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [created, setCreated] = useState<APIKeyCreated | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const qc = useQueryClient();

  const keys = useQuery({ queryKey: ["api-keys"], queryFn: listAPIKeys });
  const revokeMut = useMutation({
    mutationFn: revokeAPIKey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Key size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">API Keys</h1>
        <button
          onClick={() => setShowCreate(true)}
          className="ml-auto px-3 py-1.5 text-[12px] font-mono border border-accent/40 bg-accent/10 text-accent rounded-sm hover:bg-accent/20"
        >
          Create key
        </button>
      </div>

      {keys.isLoading ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          Loading…
        </div>
      ) : (keys.data ?? []).length === 0 ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          No API keys yet.
        </div>
      ) : (
        <div className="vigil-card overflow-hidden">
          <table className="w-full text-sm font-mono">
            <thead className="border-b border-border bg-surface-2">
              <tr className="text-left text-[11px] uppercase tracking-wider text-fg-faint">
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Prefix</th>
                <th className="px-3 py-2">Scopes</th>
                <th className="px-3 py-2">Usage</th>
                <th className="px-3 py-2">Last Used</th>
                <th className="px-3 py-2">Expires</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {(keys.data ?? []).map((k) => (
                <tr
                  key={k.key_id}
                  className="border-b border-border last:border-0"
                >
                  <td className="px-3 py-2 text-fg">
                    {k.name}
                    {k.revoked && (
                      <span className="ml-2 vigil-badge border-fg-faint/40 bg-surface-2 text-fg-muted">
                        Revoked
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-fg-muted">{k.key_prefix}…</td>
                  <td className="px-3 py-2 text-fg-faint text-[11px]">
                    {k.scopes.join(", ") || "—"}
                  </td>
                  <td className="px-3 py-2 text-fg tabular-nums">
                    {(k.use_count ?? 0).toLocaleString()}
                    <span className="text-fg-faint text-[11px] ml-1">req</span>
                  </td>
                  <td className="px-3 py-2 text-fg-faint">
                    {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-3 py-2 text-fg-faint">
                    {k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "Never"}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {!k.revoked && (
                      <button
                        onClick={() => setConfirming(k.key_id)}
                        className="text-fg-faint hover:text-accent"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreated={(k) => {
            setCreated(k);
            setShowCreate(false);
            qc.invalidateQueries({ queryKey: ["api-keys"] });
          }}
        />
      )}

      {created && <CreatedModal apiKey={created} onClose={() => setCreated(null)} />}

      {confirming && (
        <ConfirmModal
          message="Revoke this API key? Existing integrations using it will start receiving 401s immediately."
          onConfirm={async () => {
            await revokeMut.mutateAsync(confirming);
            setConfirming(null);
          }}
          onCancel={() => setConfirming(null)}
        />
      )}
    </div>
  );
}

function CreateModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (k: APIKeyCreated) => void;
}) {
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>([]);
  const [expiresAt, setExpiresAt] = useState("");

  const mut = useMutation({
    mutationFn: () =>
      createAPIKey(name, scopes, expiresAt || undefined),
    onSuccess: onCreated,
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-sm w-full max-w-md p-5">
        <div className="flex items-center mb-4">
          <h2 className="font-mono text-fg text-lg flex-1">Create API key</h2>
          <button onClick={onClose} className="text-fg-faint hover:text-fg">
            <X size={16} />
          </button>
        </div>
        <label className="block text-[11px] font-mono text-fg-muted mb-1">Name</label>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm mb-3"
          placeholder="ci-deploy"
        />
        <div className="text-[11px] font-mono text-fg-muted mb-1">Scopes</div>
        <div className="space-y-1 mb-3">
          {SCOPES.map((s) => (
            <label key={s} className="flex items-center gap-2 font-mono text-sm text-fg-muted">
              <input
                type="checkbox"
                checked={scopes.includes(s)}
                onChange={(e) =>
                  setScopes((cur) =>
                    e.target.checked ? [...cur, s] : cur.filter((x) => x !== s),
                  )
                }
              />
              <span>{s}</span>
            </label>
          ))}
        </div>
        <label className="block text-[11px] font-mono text-fg-muted mb-1">
          Expires (optional)
        </label>
        <input
          type="date"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
          className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm mb-4"
        />

        {mut.isError && (
          <div className="text-accent text-[11px] font-mono mb-2">
            {(mut.error as Error).message}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-3 py-1.5 border border-border bg-surface-2 text-fg-muted hover:text-fg rounded-sm font-mono text-sm"
          >
            Cancel
          </button>
          <button
            onClick={() => mut.mutate()}
            disabled={!name || mut.isPending}
            className="px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm hover:bg-accent/20 disabled:opacity-50"
          >
            {mut.isPending ? "Creating…" : "Create key"}
          </button>
        </div>
      </div>
    </div>
  );
}

function CreatedModal({ apiKey, onClose }: { apiKey: APIKeyCreated; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-sm w-full max-w-lg p-5">
        <div className="flex items-center mb-3">
          <h2 className="font-mono text-fg text-lg flex-1">API key created</h2>
        </div>
        <div className="vigil-card p-3 mb-3 flex items-center gap-2 text-warning font-mono text-[12px]">
          <AlertTriangle size={13} />
          Store this now — it will not be shown again.
        </div>
        <div className="bg-surface-2 border border-border rounded-sm p-3 mb-3 font-mono text-xs text-fg break-all">
          {apiKey.raw_key}
        </div>
        <div className="flex justify-end gap-2">
          <button
            onClick={() => navigator.clipboard?.writeText(apiKey.raw_key)}
            className="px-3 py-1.5 border border-border bg-surface-2 text-fg-muted hover:text-fg rounded-sm font-mono text-sm flex items-center gap-2"
          >
            <Copy size={12} />
            Copy
          </button>
          <button
            onClick={onClose}
            className="px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm hover:bg-accent/20"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

function ConfirmModal({
  message,
  onConfirm,
  onCancel,
}: {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-sm w-full max-w-md p-5">
        <div className="font-mono text-sm text-fg mb-4">{message}</div>
        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 border border-border bg-surface-2 text-fg-muted hover:text-fg rounded-sm font-mono text-sm"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm hover:bg-accent/20"
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}
