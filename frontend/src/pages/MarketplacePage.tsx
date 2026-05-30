import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Store, Download, Star, X } from "lucide-react";
import {
  browseMarketplace,
  importListing,
  publishDetection,
} from "@/api/marketplace";
import { listDetections } from "@/api/detections";
import { titleCase } from "@/lib/format";
import { useAuthStore } from "@/store/authStore";
import type { MarketplaceListing } from "@/types/marketplace";

const TACTICS = [
  "credential-access",
  "lateral-movement",
  "exfiltration",
  "execution",
  "persistence",
  "privilege-escalation",
  "discovery",
  "command-and-control",
];

export function MarketplacePage() {
  const [tacticFilter, setTacticFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [showPublish, setShowPublish] = useState(false);
  const [toast, setToast] = useState<{ msg: string; to?: string } | null>(null);
  const qc = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === "admin" || user?.role === "vigil_admin";

  const filters = useMemo(
    () => ({ tactic: tacticFilter ?? undefined, search: search || undefined }),
    [tacticFilter, search],
  );

  const listings = useQuery({
    queryKey: ["marketplace", filters],
    queryFn: () => browseMarketplace(filters),
  });

  const importMut = useMutation({
    mutationFn: (id: string) => importListing(id),
    onSuccess: () => {
      setToast({ msg: "Imported — view it in your Detections library →", to: "/detections" });
      qc.invalidateQueries({ queryKey: ["marketplace"] });
      qc.invalidateQueries({ queryKey: ["detections"] });
      setTimeout(() => setToast(null), 6000);
    },
    onError: (e: Error) => {
      setToast({ msg: `Import failed: ${e.message}` });
      setTimeout(() => setToast(null), 4000);
    },
  });

  return (
    <div className="px-6 py-6 max-w-[1400px] mx-auto">
      <div className="mb-5 flex items-center gap-2 flex-wrap">
        <Store size={18} className="text-fg-muted shrink-0" />
        <h1 className="text-xl font-mono text-fg whitespace-nowrap">
          Detection Marketplace
        </h1>
        {isAdmin && (
          <button
            onClick={() => setShowPublish(true)}
            className="ml-auto px-3 py-1.5 text-[12px] font-mono border border-accent/40 bg-accent/10 text-accent rounded-sm hover:bg-accent/20 whitespace-nowrap shrink-0"
          >
            Publish Detection
          </button>
        )}
      </div>

      <div className="mb-4 flex items-center gap-2 flex-wrap">
        <input
          type="text"
          placeholder="Search detections…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-3 py-1.5 text-sm font-mono bg-surface border border-border rounded-sm text-fg placeholder:text-fg-faint focus:outline-none focus:border-accent w-64"
        />
        <button
          onClick={() => setTacticFilter(null)}
          className={`px-2 py-1 text-[11px] font-mono rounded-sm border transition-colors ${
            tacticFilter === null
              ? "border-accent/40 bg-accent/10 text-accent"
              : "border-border bg-surface-2 text-fg-muted hover:text-fg"
          }`}
        >
          All
        </button>
        {TACTICS.map((t) => (
          <button
            key={t}
            onClick={() => setTacticFilter(t)}
            className={`px-2 py-1 text-[11px] font-mono rounded-sm border transition-colors ${
              tacticFilter === t
                ? "border-accent/40 bg-accent/10 text-accent"
                : "border-border bg-surface-2 text-fg-muted hover:text-fg"
            }`}
          >
            {titleCase(t)}
          </button>
        ))}
      </div>

      {listings.isLoading ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          Loading marketplace…
        </div>
      ) : listings.isError ? (
        <div className="vigil-card p-8 text-center text-accent font-mono text-sm">
          Failed to load marketplace: {listings.error?.message}
        </div>
      ) : (listings.data ?? []).length === 0 ? (
        <div className="vigil-card p-8 text-center text-fg-muted font-mono text-sm">
          No detections match your filters.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {(listings.data ?? []).map((l) => (
            <ListingCard
              key={l.listing_id}
              listing={l}
              onImport={() => importMut.mutate(l.listing_id)}
              importing={importMut.isPending && importMut.variables === l.listing_id}
            />
          ))}
        </div>
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 px-4 py-2 bg-surface-2 border border-border rounded-sm font-mono text-sm text-fg shadow-lg z-50">
          {toast.to ? (
            <Link to={toast.to} className="text-accent-hover hover:underline">
              {toast.msg}
            </Link>
          ) : (
            toast.msg
          )}
        </div>
      )}

      {showPublish && (
        <PublishModal
          onClose={() => setShowPublish(false)}
          onSuccess={() => {
            setShowPublish(false);
            qc.invalidateQueries({ queryKey: ["marketplace"] });
            setToast({ msg: "Detection published to the Marketplace." });
            setTimeout(() => setToast(null), 3000);
          }}
        />
      )}
    </div>
  );
}

function ListingCard({
  listing,
  onImport,
  importing,
}: {
  listing: MarketplaceListing;
  onImport: () => void;
  importing: boolean;
}) {
  return (
    <div className="vigil-card p-4 flex flex-col">
      <div className="flex items-start gap-2 mb-2">
        <div className="font-mono text-sm text-fg flex-1 truncate">{listing.name}</div>
        {listing.is_curated && (
          <span className="vigil-badge border-warning/40 bg-warning/10 text-warning flex items-center gap-1">
            <Star size={9} />
            VIGIL Curated
          </span>
        )}
      </div>
      <div className="text-[11px] font-mono text-fg-muted mb-2 flex items-center gap-2">
        <span className="vigil-badge border-border bg-surface-2 text-fg-muted">
          {titleCase(listing.att_ck_tactic)}
        </span>
        <span className="text-fg-faint">{listing.att_ck_technique}</span>
      </div>
      {listing.description && (
        <div className="text-[12px] font-mono text-fg-muted mb-3 line-clamp-3">
          {listing.description}
        </div>
      )}
      <div className="mt-auto flex items-center justify-between text-[11px] font-mono text-fg-faint">
        <span className="flex items-center gap-1 tabular-nums">
          <Download size={10} />
          {listing.downloads}
        </span>
        <button
          onClick={onImport}
          disabled={importing}
          className="px-2 py-1 border border-border bg-surface-2 text-fg-muted hover:text-fg hover:border-accent/40 rounded-sm disabled:opacity-50"
        >
          {importing ? "Importing…" : "Import"}
        </button>
      </div>
    </div>
  );
}

function PublishModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const detections = useQuery({ queryKey: ["detections"], queryFn: listDetections });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [description, setDescription] = useState("");

  const mut = useMutation({
    mutationFn: () => publishDetection(selectedId!, description || undefined),
    onSuccess,
  });

  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-sm w-full max-w-lg p-5">
        <div className="flex items-center mb-4">
          <h2 className="font-mono text-fg text-lg flex-1">Publish to marketplace</h2>
          <button onClick={onClose} className="text-fg-faint hover:text-fg">
            <X size={16} />
          </button>
        </div>

        <label className="block text-[11px] font-mono text-fg-muted mb-1">
          Detection
        </label>
        <select
          value={selectedId ?? ""}
          onChange={(e) => setSelectedId(e.target.value || null)}
          className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm mb-3"
        >
          <option value="">Choose a detection…</option>
          {(detections.data ?? []).map((d) => (
            <option key={d.detection_id} value={d.detection_id}>
              {d.detection_id} — {d.att_ck_tactic}
            </option>
          ))}
        </select>

        <label className="block text-[11px] font-mono text-fg-muted mb-1">
          Description (optional)
        </label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          rows={3}
          className="w-full px-3 py-1.5 bg-surface-2 border border-border text-fg font-mono text-sm rounded-sm mb-3"
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
            disabled={!selectedId || mut.isPending}
            className="px-3 py-1.5 border border-accent/40 bg-accent/10 text-accent rounded-sm font-mono text-sm hover:bg-accent/20 disabled:opacity-50"
          >
            {mut.isPending ? "Publishing…" : "Publish"}
          </button>
        </div>
      </div>
    </div>
  );
}
