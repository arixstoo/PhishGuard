/**
 * Modèle de **test** pour les parcours de bout en bout (étape 5.10), jamais publié.
 *
 * Le vrai modèle (`models/url_v2.json`) n'est pas versionné : la CI ne l'a pas. Les tests
 * Playwright ont pourtant besoin de verdicts exacts. Ce modèle au format d'export de
 * l'étape 4.11 (un seul arbre LightGBM) est construit à la main pour donner, sur les URLs
 * des parcours, **les mêmes verdicts que `url_v2`** (mesurés à l'étape 5.4) :
 *
 *   hôte en IP, marque dans l'hôte, au moins 2 mots-clés dans l'hôte, homographe de marque
 *   → probabilité 0,98 (phishing) ; sinon 0,02 (sûr).
 *
 * Il passe par le même chargement défensif que le vrai (`loadUrlModel`) : l'empreinte de
 * l'extracteur vient des données générées, il suit donc l'extracteur sans retouche.
 * `node build.mjs --test --stub-model` l'embarque dans `dist-test/` à la place du modèle
 * signé ; le build refuse `--stub-model` sans `--test`.
 */

export const STUB_MODEL_VERSION = "e2e_stub";

const FEATURES = ["host_is_ip", "brand_in_host", "host_kw_hits", "homograph_brand"];
const PHISHING = 4; // sigmoïde(4) ≈ 0,982
const SAFE = -4; // sigmoïde(-4) ≈ 0,018

const leaf = (value, index) => ({ leaf_index: index, leaf_value: value, leaf_count: 1 });
const split = (feature, threshold, left, right, index) => ({
  split_index: index,
  split_feature: feature,
  split_gain: 1,
  threshold,
  decision_type: "<=",
  default_left: true,
  missing_type: "None",
  internal_value: 0,
  internal_count: 1,
  left_child: left,
  right_child: right,
});

/** @param {{ version: string, reference_data_sha256: string, normalization_version: string }} featureExtractor */
export function stubModel(featureExtractor) {
  // Chaque coupure envoie à droite (phishing) au-delà du seuil, sinon à la suivante.
  const tree = split(
    0, 0.5,
    split(1, 0.5,
      split(2, 1.5,
        split(3, 0.5, leaf(SAFE, 0), leaf(PHISHING, 1), 3),
        leaf(PHISHING, 2), 2),
      leaf(PHISHING, 3), 1),
    leaf(PHISHING, 4), 0,
  );
  return {
    format: "phishguard-url-lightgbm",
    format_version: 1,
    model_version: STUB_MODEL_VERSION,
    trained_at: null,
    feature_names: FEATURES,
    feature_extractor: featureExtractor,
    objective: { name: "binary", sigmoid: 1 },
    thresholds: { fpr_0_5pct: 0.5 },
    decision_rule: "score > threshold",
    tld_table: null,
    calibration: { format_version: 1, method: "isotonic", x: [0, 1], y: [0, 1], params: {}, metadata: {} },
    lightgbm_version: "stub",
    booster: {
      name: "tree",
      version: "v4",
      num_class: 1,
      num_tree_per_iteration: 1,
      max_feature_idx: FEATURES.length - 1,
      objective: "binary sigmoid:1",
      feature_names: FEATURES,
      tree_info: [{ tree_index: 0, num_leaves: 5, shrinkage: 1, tree_structure: tree }],
    },
  };
}
