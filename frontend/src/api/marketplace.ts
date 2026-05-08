import { detectionClient } from "./detections";
import type { MarketplaceListing, MarketplaceStats } from "@/types/marketplace";

interface ApiEnvelope<T> {
  data: T;
  meta?: Record<string, unknown>;
  error?: string | null;
}

function unwrap<T>(env: ApiEnvelope<T>): T {
  if (env.error) throw new Error(env.error);
  return env.data;
}

export interface MarketplaceFilters {
  tactic?: string;
  technique?: string;
  is_curated?: boolean;
  search?: string;
}

export async function browseMarketplace(
  filters: MarketplaceFilters = {},
): Promise<MarketplaceListing[]> {
  const res = await detectionClient.get<ApiEnvelope<MarketplaceListing[]>>(
    "/marketplace",
    { params: filters },
  );
  return unwrap(res.data);
}

export async function getListing(id: string): Promise<MarketplaceListing> {
  const res = await detectionClient.get<ApiEnvelope<MarketplaceListing>>(
    `/marketplace/${id}`,
  );
  return unwrap(res.data);
}

export async function publishDetection(
  detection_id: string,
  description?: string,
): Promise<MarketplaceListing> {
  const res = await detectionClient.post<ApiEnvelope<MarketplaceListing>>(
    "/marketplace/publish",
    { detection_id, description },
  );
  return unwrap(res.data);
}

export async function importListing(
  listing_id: string,
): Promise<{ listing: MarketplaceListing; import_id: string; local_detection_id: string | null }> {
  const res = await detectionClient.post<
    ApiEnvelope<{ listing: MarketplaceListing; import_id: string; local_detection_id: string | null }>
  >(`/marketplace/${listing_id}/import`);
  return unwrap(res.data);
}

export async function withdrawListing(listing_id: string): Promise<MarketplaceListing> {
  const res = await detectionClient.delete<ApiEnvelope<MarketplaceListing>>(
    `/marketplace/${listing_id}`,
  );
  return unwrap(res.data);
}

export async function getMarketplaceStats(): Promise<MarketplaceStats> {
  const res = await detectionClient.get<ApiEnvelope<MarketplaceStats>>(
    "/marketplace/stats",
  );
  return unwrap(res.data);
}
