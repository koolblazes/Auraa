// AURAA — Pilot Geocoding Proxy
// Uses explicit user-triggered searches only.
// Keeps the public Nominatim service behind a same-origin Netlify Function.
// No client-side autocomplete requests.

const CACHE = new Map();
let lastRequestAt = 0;

const LAGOS_BOUNDS = {
  minLat: 6.30,
  maxLat: 6.75,
  minLng: 3.00,
  maxLng: 3.80,
};

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

function formatResult(item) {
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
    [
      address.house_number,
      address.road,
      address.suburb,
    ].filter(Boolean).join(", ") ||
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

exports.handler = async function handler(event) {
  if (event.httpMethod !== "GET") {
    return json(405, {
      error: "method_not_allowed",
      results: [],
    });
  }

  const q = cleanText(event.queryStringParameters?.q, 180);

  if (q.length < 2) {
    return json(400, {
      error: "query_too_short",
      results: [],
    });
  }

  const cacheKey = q.toLowerCase();

  if (CACHE.has(cacheKey)) {
    return json(200, {
      results: CACHE.get(cacheKey),
      cached: true,
    });
  }

  // Public Nominatim policy requires reasonable request frequency.
  // Keep at least 1 second between outbound requests per warm function instance.
  const now = Date.now();
  const wait = Math.max(0, 1000 - (now - lastRequestAt));
  if (wait > 0) {
    await sleep(wait);
  }
  lastRequestAt = Date.now();

  const params = new URLSearchParams({
    q: `${q}, Lagos, Nigeria`,
    format: "jsonv2",
    limit: "5",
    addressdetails: "1",
    bounded: "1",
    viewbox: "3.0,6.75,3.8,6.30",
  });

  const email = process.env.NOMINATIM_EMAIL;
  if (email) {
    params.set("email", email);
  }

  const userAgent =
    process.env.AURAA_GEOCODER_USER_AGENT ||
    "AURAA-Pilot/1.0 (https://app.auraahq.com)";

  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/search?${params.toString()}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "User-Agent": userAgent,
        },
      }
    );

    if (response.status === 429) {
      return json(503, {
        error: "geocoder_rate_limited",
        results: [],
      });
    }

    if (!response.ok) {
      return json(502, {
        error: "geocoder_unavailable",
        results: [],
      });
    }

    const data = await response.json();

    const results = Array.isArray(data)
      ? data
          .map(formatResult)
          .filter(item => inLagosBounds(item.lat, item.lng))
          .slice(0, 5)
      : [];

    // Small in-memory cache for repeated searches on a warm function.
    if (CACHE.size >= 50) {
      const oldestKey = CACHE.keys().next().value;
      if (oldestKey) CACHE.delete(oldestKey);
    }

    CACHE.set(cacheKey, results);

    return json(200, {
      results,
      cached: false,
    });
  } catch (error) {
    console.error("[AURAA pilot geocode]", error?.message || error);

    return json(502, {
      error: "geocoder_request_failed",
      results: [],
    });
  }
};
