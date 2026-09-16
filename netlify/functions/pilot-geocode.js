// AURAA — Pilot Geocoding Proxy v2
// Multi-strategy: tries Nominatim with progressively looser queries,
// then falls back to Photon (Komoot) for better Lagos street coverage.
// No client-side autocomplete requests.

const CACHE = new Map();
let lastNominatimAt = 0;

const LAGOS_BOUNDS = {
  minLat: 6.25,
  maxLat: 6.80,
  minLng: 2.95,
  maxLng: 3.85,
};

const LAGOS_CENTER = { lat: 6.5244, lng: 3.3792 };

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
    body: JSON.stringify(body),
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function cleanText(value, max = 180) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

function inLagosBounds(lat, lng) {
  return (
    Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    lat >= LAGOS_BOUNDS.minLat &&
    lat <= LAGOS_BOUNDS.maxLat &&
    lng >= LAGOS_BOUNDS.minLng &&
    lng <= LAGOS_BOUNDS.maxLng
  );
}

function dedup(results) {
  const seen = new Set();
  return results.filter(r => {
    const key = `${r.lat.toFixed(4)},${r.lng.toFixed(4)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function formatNominatim(item) {
  const address = item.address || {};
  const area =
    address.suburb ||
    address.city_district ||
    address.quarter ||
    address.town ||
    address.city ||
    "Lagos";
  const name = cleanText(
    item.name ||
    [address.house_number, address.road, address.suburb]
      .filter(Boolean).join(", ") ||
    item.display_name
  );
  return {
    name,
    full: cleanText(item.display_name, 300),
    area: cleanText(area, 100),
    lat: Number(item.lat),
    lng: Number(item.lon),
    source: "nominatim",
  };
}

function formatPhoton(feature) {
  const p = feature.properties || {};
  const coords = feature.geometry?.coordinates || [];
  const area = p.district || p.locality || p.city || "Lagos";
  const name = cleanText(
    [p.housenumber, p.street || p.name].filter(Boolean).join(", ") ||
    p.name ||
    [p.street, p.district].filter(Boolean).join(", ")
  );
  return {
    name,
    full: cleanText([name, area, p.state, p.country].filter(Boolean).join(", "), 300),
    area: cleanText(area, 100),
    lat: Number(coords[1]),
    lng: Number(coords[0]),
    source: "photon",
  };
}

const userAgent = "AURAA-Pilot/1.0 (https://app.auraahq.com)";

async function nominatimSearch(query, options = {}) {
  const now = Date.now();
  const wait = Math.max(0, 1100 - (now - lastNominatimAt));
  if (wait > 0) await sleep(wait);
  lastNominatimAt = Date.now();

  const params = new URLSearchParams({
    q: query,
    format: "jsonv2",
    limit: String(options.limit || 8),
    addressdetails: "1",
    countrycodes: "ng",
    dedupe: "1",
    viewbox: "2.95,6.80,3.85,6.25",
  });
  // Use viewbox as a preference bias, NOT a hard boundary.
  // bounded=0 (default) means results outside viewbox are ranked lower, not excluded.

  const email = process.env.NOMINATIM_EMAIL;
  if (email) params.set("email", email);

  const ua = process.env.AURAA_GEOCODER_USER_AGENT || userAgent;

  const response = await fetch(
    `https://nominatim.openstreetmap.org/search?${params.toString()}`,
    { headers: { "Accept": "application/json", "User-Agent": ua } }
  );
  if (response.status === 429 || !response.ok) return [];
  const data = await response.json();
  return Array.isArray(data)
    ? data.map(formatNominatim).filter(r => inLagosBounds(r.lat, r.lng))
    : [];
}

async function photonSearch(query) {
  // Photon (Komoot) — free geocoder with OSM data, different index.
  // Biased toward Lagos center. No rate-limit header but be polite.
  const params = new URLSearchParams({
    q: query,
    lat: String(LAGOS_CENTER.lat),
    lon: String(LAGOS_CENTER.lng),
    limit: "8",
    lang: "en",
  });

  const response = await fetch(
    `https://photon.komoot.io/api/?${params.toString()}`,
    { headers: { "Accept": "application/json", "User-Agent": userAgent } }
  );
  if (!response.ok) return [];
  const data = await response.json();
  return Array.isArray(data?.features)
    ? data.features.map(formatPhoton).filter(r => inLagosBounds(r.lat, r.lng))
    : [];
}

exports.handler = async function handler(event) {
  if (event.httpMethod !== "GET") {
    return json(405, { error: "method_not_allowed", results: [] });
  }

  const q = cleanText(event.queryStringParameters?.q, 180);
  if (q.length < 2) {
    return json(400, { error: "query_too_short", results: [] });
  }

  const cacheKey = q.toLowerCase();
  if (CACHE.has(cacheKey)) {
    return json(200, { results: CACHE.get(cacheKey), cached: true });
  }

  try {
    let results = [];

    // Strategy 1: Raw query — best for specific addresses like "10a Olaniba"
    results = await nominatimSearch(q);

    // Strategy 2: Append "Lagos" — helps when raw query is too vague
    if (results.length < 2) {
      const r2 = await nominatimSearch(`${q}, Lagos`);
      results = dedup([...results, ...r2]);
    }

    // Strategy 3: Photon fallback — different OSM index, often finds
    // streets and house numbers that Nominatim misses in Lagos
    if (results.length < 2) {
      const r3 = await photonSearch(q);
      results = dedup([...results, ...r3]);
    }

    // Strategy 4: Photon with "Lagos" suffix
    if (results.length < 2) {
      const r4 = await photonSearch(`${q} Lagos`);
      results = dedup([...results, ...r4]);
    }

    results = results.slice(0, 6);

    // Cache management
    if (CACHE.size >= 80) {
      const oldestKey = CACHE.keys().next().value;
      if (oldestKey) CACHE.delete(oldestKey);
    }
    CACHE.set(cacheKey, results);

    return json(200, { results, cached: false });
  } catch (error) {
    console.error("[AURAA pilot geocode]", error?.message || error);
    return json(502, { error: "geocoder_request_failed", results: [] });
  }
};
