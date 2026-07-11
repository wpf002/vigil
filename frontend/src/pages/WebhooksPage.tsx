import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Webhook, Trash2, X, Send } from "lucide-react";
import { SettingsTabs } from "@/components/SettingsTabs";
import {
  createWebhook,
  deleteWebhook,
  listWebhooks,
  testWebhook,
} from "@/api/settings";

const EVENTS = [
  "attack.created",
  "attack.updated",
  "attack.escalated",
  "attack.resolved",
  "playbook.paused",
];

export function WebhooksPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [testResult, setTestResult] = useState<Record<string, string>>({});
  const qc = useQueryClient();

  const list = useQuery({ queryKey: ["webhooks"], queryFn: listWebhooks });

  const delMut = useMutation({
    mutationFn: deleteWebhook,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });

  const testMut = useMutation({
    mutationFn: testWebhook,
    onSuccess: (data, id) => {
      const msg = data.ok
        ? `OK (${data.status_code})`
        : `Failed: ${data.status_code ?? "no response"} ${data.error ?? ""}`;
      setTestResult((cur) => ({ ...cur, [id]: msg }));
    },
  });

  return (
    <div className="px-6 py-6 max-w-[1100px] mx-auto">
      <div className="mb-5 flex items-center gap-2">
        <Webhook size={18} className="text-fg-muted" />
        <h1 className="text-xl font-mono text-fg">Webhooks</h1>
        <button
          onClick={() => setShowCreate(true)}
          className="ml-auto px-3 py-1.5 text-[12px] font-mono border border-accent/40 bg-accent/10 text-accent rounded-sm hover:bg-accent/20"
        >
          Register webhook
        </button>
      </div>

      <SettingsTabs />

      {list.isLoading ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          Loading…
        </div>
      ) : (list.data ?? []).length === 0 ? (
        <div className="vigil-card p-6 text-center text-fg-muted font-mono text-sm">
          No webhooks registered.
        </div>
      ) : (
        <div className="space-y-2">
          {(list.data ?? []).map((w) => (
            <div key={w.webhook_id} className="vigil-card p-3 font-mono text-sm">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-fg flex-1 truncate">{w.url}</span>
                {w.active ? (
                  <span className="vigil-badge border-success/40 bg-success/10 text-success">
                    Active
                  </span>
                ) : (
                  <span className="vigil-badge border-warning/40 bg-warning/10 text-warning">
                    Disabled
                  </span>
                )}
              </div>
              <div className="text-[11px] text-fg-muted mb-2">
                {w.events.join(", ")}
              </div>
              <div className="flex items-center gap-3 text-[11px] text-fg-faint">
                <span>
                  Last fired:{" "}
                  {w.last_fired_at ? new Date(w.last_fired_at).toLocaleString() : "—"}
                </span>
                <span>Failures: {w.failure_count}</span>
                {testResult[w.webhook_id] && (
                  <span className="text-fg">{testResult[w.webhook_id]}</span>
                )}
                <span className="ml-auto flex items-center gap-2">
                  <button
                    onClick={() => testMut.mutate(w.webhook_id)}
                    disabled={testMut.isPending}
                    className="text-fg-muted hover:text-fg flex items-center gap-1"
                  >
                    <Send size={11} />
                    Test
                  </button>
                  <button
                    onClick={() => delMut.mutate(w.webhook_id)}
                    className="text-fg-faint hover:text-accent"
                  >
                    <Trash2 size={11} />
                  </button>
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false);
            qc.invalidateQueries({ queryKey: ["webhooks"] });
          }}
        />
      )}
    </div>
  );
}

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [url, setUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [events, setEvents] = useState<string[]>([]);

  const mut = useMutation({
    mutationFn: () => createWebhook(url, secret, events),
    onSuccess: onCreated,
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-sm w-full max-w-md p-5">
        <div className="flex items-center mb-4">
          <h2 className="font-mono text-fg text-lg flex-1">Register webhook</h2>
          <button onClick={onClose} className="text-fg-faint hover:text-fg">
            <X size={16} />
          </button>
        </div>
        <label className="block text-[11px] font-mono text-fg-muted mb-1">URL</label>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/vigil-hook"
          className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm mb-3"
        />
        <label className="block text-[11px] font-mono text-fg-muted mb-1">
          Secret (HMAC signing)
        </label>
        <input
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          placeholder="at least 8 chars"
          className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm mb-3"
        />
        <div className="text-[11px] font-mono text-fg-muted mb-1">Events</div>
        <div className="space-y-1 mb-4">
          {EVENTS.map((e) => (
            <label key={e} className="flex items-center gap-2 font-mono text-sm text-fg-muted">
              <input
                type="checkbox"
                checked={events.includes(e)}
                onChange={(ev) =>
                  setEvents((cur) =>
                    ev.target.checked ? [...cur, e] : cur.filter((x) => x !== e),
                  )
                }
              />
              <span>{e}</span>
            </label>
          ))}
        </div>

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
            disabled={!url || !secret || events.length === 0 || mut.isPending}
            className="px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm hover:bg-accent/20 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Register"}
          </button>
        </div>
      </div>
    </div>
  );
}
