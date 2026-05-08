export interface MarketplaceListing {
  listing_id: string;
  detection_id: string;
  publisher_tenant_id: string;
  name: string;
  description: string | null;
  att_ck_tactic: string;
  att_ck_technique: string;
  version: string;
  is_curated: boolean;
  downloads: number;
  status: "active" | "withdrawn";
  published_at: string | null;
  updated_at: string | null;
  yaml_preview: string | null;
}

export interface MarketplaceStats {
  total_listings: number;
  downloads_by_tactic: { tactic: string; downloads: number }[];
  top_imported: {
    listing_id: string;
    detection_id: string;
    name: string;
    downloads: number;
    att_ck_tactic: string;
  }[];
}
