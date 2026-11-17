/**
 * Page « coller et analyser » (étape 5.12).
 *
 * - Le texte collé et ses liens (5 au plus) sont analysés par l'API de ce serveur :
 *   POST /v1/analyze/text et /v1/analyze/url, en parallèle. Verdict global : le plus grave.
 * - **Tout ce qui vient du serveur ou du texte collé est inséré par textContent**, jamais
 *   comme HTML : un message piégé ne peut pas exécuter de script dans la page.
 * - Rien n'est stocké (ni cookie, ni stockage local) ; aucun lien n'est rendu cliquable :
 *   seul l'hôte est affiché, en ASCII (un homographe apparaît sous sa forme Punycode).
 */

const MAX_CHARS = 5000;
const MAX_URLS = 5;
const MAX_URL_CHARS = 2048;
const TIMEOUT_MS = 10000;
const VERDICTS = ["safe", "suspicious", "phishing"];
const RANK = { safe: 0, suspicious: 1, phishing: 2 };
const URL_RE = /\bhttps?:\/\/[^\s<>"'«»“”‘’]+|\bwww\.[^\s<>"'«»“”‘’]+/gi;
const TRAILING = /[.,;:!?)\]}…]+$/;

const TEXTS = {
  fr: {
    title: "Vérifier un message ou un lien",
    language: "Langue",
    lead: "Collez un SMS, un message ou un lien qui vous paraît douteux : PhishGuard vous dit s'il ressemble à du phishing, et pourquoi.",
    warning: "Ne collez pas de mot de passe ou de données personnelles.",
    warningDetail: "Le texte est envoyé à ce serveur pour être analysé, puis oublié.",
    label: "Message ou lien à vérifier",
    analyze: "Analyser",
    analyzing: "Analyse…",
    clear: "Effacer",
    counter: "{n} / {max} caractères",
    empty: "Collez d'abord un message ou un lien.",
    tooLong: "Le texte dépasse {max} caractères : gardez seulement la partie suspecte.",
    footer: "PhishGuard ne visite jamais les liens : il les analyse comme du texte. Un verdict « sûr » n'est pas une garantie ; en cas de doute, contactez l'organisme par ses coordonnées officielles.",
    source: "Code source et politique de confidentialité",
    verdict_safe: "Aucun signe de phishing",
    verdict_suspicious: "Suspect",
    verdict_phishing: "Phishing probable",
    item_safe: "sûr",
    item_suspicious: "suspect",
    item_phishing: "phishing",
    item_failed: "non analysé",
    message: "Le message",
    link: "Lien vers {host}",
    advice: "Conseil",
    score: "Score de risque : {score} / 100",
    skipped: "{n} autre(s) lien(s) non analysé(s) : {max} au plus par message.",
    partial: "Une partie de l'analyse n'a pas abouti : ce verdict est incomplet.",
    rateLimited: "Trop d'analyses en peu de temps. Réessayez dans {s} secondes.",
    unavailable: "Le serveur d'analyse ne répond pas. Réessayez dans un moment.",
    announce: "Résultat : {verdict}.",
  },
  en: {
    title: "Check a message or a link",
    language: "Language",
    lead: "Paste a text message, a message or a link that looks dubious: PhishGuard tells you whether it looks like phishing, and why.",
    warning: "Do not paste passwords or personal data.",
    warningDetail: "The text is sent to this server to be analysed, then forgotten.",
    label: "Message or link to check",
    analyze: "Analyse",
    analyzing: "Analysing…",
    clear: "Clear",
    counter: "{n} / {max} characters",
    empty: "Paste a message or a link first.",
    tooLong: "The text exceeds {max} characters: keep only the suspicious part.",
    footer: "PhishGuard never visits links: it analyses them as text. A “safe” verdict is not a guarantee; when in doubt, contact the organisation through its official channels.",
    source: "Source code and privacy policy",
    verdict_safe: "No sign of phishing",
    verdict_suspicious: "Suspicious",
    verdict_phishing: "Likely phishing",
    item_safe: "safe",
    item_suspicious: "suspicious",
    item_phishing: "phishing",
    item_failed: "not analysed",
    message: "The message",
    link: "Link to {host}",
    advice: "Advice",
    score: "Risk score: {score} / 100",
    skipped: "{n} more link(s) not analysed: {max} at most per message.",
    partial: "Part of the analysis failed: this verdict is incomplete.",
    rateLimited: "Too many analyses in a short time. Try again in {s} seconds.",
    unavailable: "The analysis server is not responding. Try again in a moment.",
    announce: "Result: {verdict}.",
  },
  ar: {
    title: "التحقق من رسالة أو رابط",
    language: "اللغة",
    lead: "الصق رسالة نصية أو رسالة أو رابطًا يبدو لك مريبًا: يخبرك PhishGuard إن كان يشبه التصيد الاحتيالي، ولماذا.",
    warning: "لا تلصق كلمات مرور أو بيانات شخصية.",
    warningDetail: "يُرسل النص إلى هذا الخادم ليُحلَّل، ثم يُنسى.",
    label: "الرسالة أو الرابط المراد التحقق منه",
    analyze: "تحليل",
    analyzing: "جارٍ التحليل…",
    clear: "مسح",
    counter: "{n} / {max} حرفًا",
    empty: "الصق رسالة أو رابطًا أولًا.",
    tooLong: "يتجاوز النص {max} حرفًا: احتفظ بالجزء المريب فقط.",
    footer: "لا يزور PhishGuard الروابط أبدًا: يحللها كنص. الحكم «آمن» ليس ضمانًا؛ عند الشك، تواصل مع الجهة عبر قنواتها الرسمية.",
    source: "الشيفرة المصدرية وسياسة الخصوصية",
    verdict_safe: "لا توجد علامات تصيد احتيالي",
    verdict_suspicious: "مريب",
    verdict_phishing: "تصيد احتيالي محتمل",
    item_safe: "آمن",
    item_suspicious: "مريب",
    item_phishing: "تصيد احتيالي",
    item_failed: "لم يُحلَّل",
    message: "الرسالة",
    link: "رابط إلى {host}",
    advice: "نصيحة",
    score: "درجة الخطر: {score} / 100",
    skipped: "{n} رابط (روابط) أخرى لم تُحلَّل: {max} كحد أقصى لكل رسالة.",
    partial: "لم يكتمل جزء من التحليل: هذا الحكم غير مكتمل.",
    rateLimited: "تحليلات كثيرة في وقت قصير. أعد المحاولة بعد {s} ثانية.",
    unavailable: "خادم التحليل لا يستجيب. أعد المحاولة بعد قليل.",
    announce: "النتيجة: {verdict}.",
  },
};
const ICONS = { safe: "✅", suspicious: "⚠️", phishing: "⛔", failed: "❔" };
// Typographie : espace avant les deux-points en français seulement.
const COLON = { fr: " : ", en: ": ", ar: ": " };

const $ = (id) => document.getElementById(id);
let language = pickLanguage();

function pickLanguage() {
  for (const code of navigator.languages ?? [navigator.language]) {
    const base = String(code).slice(0, 2).toLowerCase();
    if (base in TEXTS) return base;
  }
  return "fr";
}

/** Texte traduit ; les valeurs substituées ne sont jamais réinterprétées (un seul passage). */
function t(key, values = {}) {
  return TEXTS[language][key].replace(/\{(\w+)\}/g, (match, name) => (name in values ? String(values[name]) : match));
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function applyLanguage() {
  document.documentElement.lang = language;
  document.documentElement.dir = language === "ar" ? "rtl" : "ltr";
  document.title = `PhishGuard : ${t("title")}`;
  for (const node of document.querySelectorAll("[data-i18n]")) node.textContent = t(node.dataset.i18n);
  $("language").value = language;
  updateCounter();
}

function updateCounter() {
  $("counter").textContent = t("counter", { n: $("text").value.length, max: MAX_CHARS });
}

// --------------------------------------------------------------------------- //
// Liens du texte
// --------------------------------------------------------------------------- //

/** Liens distincts du texte, dans l'ordre : `{ urls, skipped }`. */
export function extractUrls(text) {
  const seen = new Set();
  const urls = [];
  let skipped = 0;
  for (const match of text.matchAll(URL_RE)) {
    let url = match[0].replace(TRAILING, "");
    if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
    if (url.length > MAX_URL_CHARS || seen.has(url)) continue;
    seen.add(url);
    if (urls.length < MAX_URLS) urls.push(url);
    else skipped++;
  }
  return { urls, skipped };
}

/** Hôte affichable en ASCII (la classe URL convertit un nom internationalisé en Punycode). */
export function hostOf(url) {
  try {
    return new URL(url).hostname || "?";
  } catch {
    return "?";
  }
}

// --------------------------------------------------------------------------- //
// API
// --------------------------------------------------------------------------- //

class ApiError extends Error {
  constructor(code, retryAfter = 0) {
    super(code);
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

/** Sous-ensemble vérifié de la réponse (contrat AnalysisResponse 1.x). */
function parseResponse(value) {
  const ok =
    value &&
    VERDICTS.includes(value.verdict) &&
    Number.isInteger(value.score) &&
    value.score >= 0 &&
    value.score <= 100 &&
    Array.isArray(value.reasons) &&
    value.reasons.every((r) => r && typeof r.message === "string") &&
    typeof value.advice === "string";
  if (!ok) throw new ApiError("invalid");
  return {
    verdict: value.verdict,
    score: value.score,
    channel: value.channel,
    reasons: value.reasons.slice(0, 3).map((r) => r.message.slice(0, 400)),
    advice: value.advice.slice(0, 600),
  };
}

async function post(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch {
    throw new ApiError("network");
  }
  if (response.status === 429) throw new ApiError("rate-limited", Number(response.headers.get("Retry-After")) || 60);
  if (!response.ok) throw new ApiError(`http-${response.status}`);
  try {
    return parseResponse(await response.json());
  } catch {
    throw new ApiError("invalid");
  }
}

async function analyze(text) {
  const { urls, skipped } = extractUrls(text);
  // Un lien seul, sans autre texte : inutile d'analyser le « message ».
  const bare = text.trim().replace(TRAILING, "");
  const withText = !(urls.length === 1 && (urls[0] === bare || urls[0] === `http://${bare}`));
  const jobs = [];
  if (withText) jobs.push(post("/v1/analyze/text", { text, channel: "messaging", language, analyst: false }));
  for (const url of urls) jobs.push(post("/v1/analyze/url", { url, language, analyst: false, use_threat_intel: false }));
  const settled = await Promise.allSettled(jobs);
  const results = settled.map((s) => (s.status === "fulfilled" ? s.value : null));
  const limited = settled.find((s) => s.status === "rejected" && s.reason?.code === "rate-limited");
  return {
    text: withText ? results.shift() : undefined,
    links: urls.map((url, i) => ({ url, result: results[i] })),
    skipped,
    limited: limited ? limited.reason.retryAfter : 0,
    failed: settled.some((s) => s.status === "rejected"),
  };
}

// --------------------------------------------------------------------------- //
// Affichage (textContent seulement)
// --------------------------------------------------------------------------- //

function strictest(results) {
  return results.reduce((worst, r) => (worst === null || RANK[r.verdict] > RANK[worst.verdict] || (r.verdict === worst.verdict && r.score > worst.score) ? r : worst), null);
}

function item(label, result) {
  const verdict = result ? result.verdict : "failed";
  const li = el("li", undefined, `item ${verdict}`);
  const head = el("p", undefined, "item-head");
  head.append(el("span", ICONS[verdict], "icon"), el("span", `${label}${COLON[language]}`), el("strong", t(`item_${verdict}`)));
  li.append(head);
  if (result && result.verdict !== "safe" && result.reasons.length > 0) {
    const list = el("ul", undefined, "reasons");
    for (const reason of result.reasons) list.append(el("li", reason));
    li.append(list);
  }
  return li;
}

function render(outcome) {
  const section = $("result");
  section.replaceChildren();
  section.hidden = false;
  const done = [outcome.text, ...outcome.links.map((l) => l.result)].filter(Boolean);
  const worst = strictest(done);
  if (worst === null) {
    const message = outcome.limited ? t("rateLimited", { s: outcome.limited }) : t("unavailable");
    section.className = "card failed";
    section.append(el("h2", message));
    section.firstChild.id = "verdict-title";
    section.firstChild.tabIndex = -1;
    $("status").textContent = message;
    section.firstChild.focus();
    return;
  }
  section.className = `card ${worst.verdict}`;
  const title = el("h2", undefined, "verdict");
  title.id = "verdict-title";
  title.tabIndex = -1;
  title.append(el("span", ICONS[worst.verdict], "icon"), el("span", t(`verdict_${worst.verdict}`)));
  section.append(title, el("p", t("score", { score: worst.score }), "score"));

  const items = el("ul", undefined, "items");
  if (outcome.text !== undefined) items.append(item(t("message"), outcome.text));
  for (const { url, result } of outcome.links) items.append(item(t("link", { host: hostOf(url) }), result));
  section.append(items);
  if (outcome.skipped) section.append(el("p", t("skipped", { n: outcome.skipped, max: MAX_URLS }), "note"));
  if (outcome.failed) section.append(el("p", outcome.limited ? t("rateLimited", { s: outcome.limited }) : t("partial"), "note"));
  const advice = el("p", undefined, "advice");
  advice.append(el("strong", `${t("advice")}${COLON[language]}`), el("span", worst.advice));
  section.append(advice);
  $("status").textContent = t("announce", { verdict: t(`verdict_${worst.verdict}`) });
  title.focus();
}

function showError(message) {
  const error = $("text-error");
  error.textContent = message;
  error.hidden = !message;
  $("text").setAttribute("aria-invalid", message ? "true" : "false");
}

async function onSubmit(event) {
  event.preventDefault();
  const text = $("text").value;
  if (!text.trim()) return showError(t("empty")), $("text").focus();
  if (text.length > MAX_CHARS) return showError(t("tooLong", { max: MAX_CHARS })), $("text").focus();
  showError("");
  const button = $("analyze");
  button.disabled = true;
  button.textContent = t("analyzing");
  try {
    render(await analyze(text));
  } finally {
    button.disabled = false;
    button.textContent = t("analyze");
  }
}

function init() {
  $("form").addEventListener("submit", onSubmit);
  $("text").addEventListener("input", updateCounter);
  $("clear").addEventListener("click", () => {
    $("text").value = "";
    $("result").hidden = true;
    $("result").replaceChildren();
    showError("");
    updateCounter();
    $("text").focus();
  });
  $("language").addEventListener("change", (event) => {
    language = event.target.value in TEXTS ? event.target.value : "fr";
    applyLanguage();
  });
  applyLanguage();
}

if (typeof document !== "undefined") init();
