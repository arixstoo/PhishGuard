export const STUB_MODEL_VERSION: string;
export function stubModel(featureExtractor: {
  version: string;
  reference_data_sha256: string;
  normalization_version: string;
}): Record<string, unknown>;
