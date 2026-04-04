import type { Config, Context } from "@netlify/functions";

// Market data with realistic price simulation
// In production, replace with a real price feed API (CoinGecko, Binance, etc.)
const BASE_PRICES: Record<string, number> = {
  BTC: 65000,
  ETH: 3200,
  BNB: 600,
  SOL: 145,
  XRP: 0.58,
  ADA: 0.45,
  AVAX: 35,
  DOGE: 0.15,
  USDT: 1,
  USDC: 1,
};

const SUPPORTED_SYMBOLS = Object.keys(BASE_PRICES);

// Price volatility per asset (percentage range for simulation)
const VOLATILITY: Record<string, number> = {
  BTC: 0.005, ETH: 0.007, BNB: 0.008, SOL: 0.012,
  XRP: 0.010, ADA: 0.011, AVAX: 0.013, DOGE: 0.020,
  USDT: 0, USDC: 0,
};

// Simulate a realistic price with small random variation
function simulatePrice(symbol: string, basePrice: number): number {
  const vol = VOLATILITY[symbol] || 0.005;
  const change = (Math.random() * 2 - 1) * vol;
  return parseFloat((basePrice * (1 + change)).toFixed(symbol === "DOGE" || symbol === "XRP" || symbol === "ADA" ? 4 : 2));
}

// Generate 24h OHLCV data points for a symbol
function generateOhlcv(symbol: string, basePrice: number, points = 24): Array<Record<string, unknown>> {
  const vol = (VOLATILITY[symbol] || 0.005) * 3;
  const data = [];
  let price = basePrice * (1 - vol * 12);
  const now = Date.now();

  for (let i = points - 1; i >= 0; i--) {
    const open = price;
    const high = open * (1 + Math.random() * vol);
    const low = open * (1 - Math.random() * vol);
    const close = low + Math.random() * (high - low);
    const volume = basePrice * (1000 + Math.random() * 9000);

    data.push({
      timestamp: new Date(now - i * 3600 * 1000).toISOString(),
      open: parseFloat(open.toFixed(2)),
      high: parseFloat(high.toFixed(2)),
      low: parseFloat(low.toFixed(2)),
      close: parseFloat(close.toFixed(2)),
      volume: parseFloat(volume.toFixed(2)),
    });

    price = close;
  }

  return data;
}

function getClientIp(req: Request, context: Context): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-nf-client-connection-ip") ||
    context.ip ||
    "unknown";
}

// Simple rate limiter
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
function isRateLimited(ip: string): boolean {
  const now = Date.now();
  for (const [k, v] of rateLimitMap.entries()) {
    if (now - v.windowStart > 60000) rateLimitMap.delete(k);
  }
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > 60000) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > 60; // 60 requests per minute for market data
}

export default async (req: Request, context: Context) => {
  const ip = getClientIp(req, context);

  if (isRateLimited(ip)) {
    return Response.json({ error: "Too many requests" }, { status: 429 });
  }

  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const url = new URL(req.url);
  const type = url.searchParams.get("type") || "prices";
  const symbol = (url.searchParams.get("symbol") || "").toUpperCase();

  // ─── GET prices (all or single) ────────────────────────────────────────
  if (type === "prices") {
    if (symbol) {
      if (!SUPPORTED_SYMBOLS.includes(symbol)) {
        return Response.json({ error: "Unsupported symbol" }, { status: 400 });
      }
      const price = simulatePrice(symbol, BASE_PRICES[symbol]);
      const vol = VOLATILITY[symbol] || 0;
      return Response.json({
        symbol,
        price,
        change24h: parseFloat(((Math.random() * 2 - 1) * vol * 100 * 10).toFixed(2)),
        volume24h: parseFloat((BASE_PRICES[symbol] * (10000 + Math.random() * 90000)).toFixed(0)),
        updatedAt: new Date().toISOString(),
      });
    }

    // Return all prices
    const prices: Record<string, unknown> = {};
    for (const sym of SUPPORTED_SYMBOLS) {
      const price = simulatePrice(sym, BASE_PRICES[sym]);
      const vol = VOLATILITY[sym] || 0;
      prices[sym] = {
        price,
        change24h: parseFloat(((Math.random() * 2 - 1) * vol * 100 * 10).toFixed(2)),
        volume24h: parseFloat((BASE_PRICES[sym] * (10000 + Math.random() * 90000)).toFixed(0)),
      };
    }

    return Response.json({
      prices,
      updatedAt: new Date().toISOString(),
    });
  }

  // ─── GET ohlcv (candlestick data) ──────────────────────────────────────
  if (type === "ohlcv") {
    if (!symbol || !SUPPORTED_SYMBOLS.includes(symbol)) {
      return Response.json({ error: "Valid symbol required for OHLCV data" }, { status: 400 });
    }

    const ohlcv = generateOhlcv(symbol, BASE_PRICES[symbol]);
    return Response.json({
      symbol,
      interval: "1h",
      data: ohlcv,
      updatedAt: new Date().toISOString(),
    });
  }

  // ─── GET symbols (list of supported trading pairs) ─────────────────────
  if (type === "symbols") {
    return Response.json({
      symbols: SUPPORTED_SYMBOLS,
      pairs: SUPPORTED_SYMBOLS
        .filter((s) => s !== "USDT" && s !== "USDC")
        .map((s) => `${s}/USDT`),
    });
  }

  // ─── GET rates (for swap calculations) ─────────────────────────────────
  if (type === "rates") {
    const from = (url.searchParams.get("from") || "").toUpperCase();
    const to = (url.searchParams.get("to") || "").toUpperCase();

    if (!from || !to) {
      return Response.json({ error: "from and to symbols required" }, { status: 400 });
    }

    if (!SUPPORTED_SYMBOLS.includes(from) || !SUPPORTED_SYMBOLS.includes(to)) {
      return Response.json({ error: "Unsupported trading pair" }, { status: 400 });
    }

    const fromPrice = simulatePrice(from, BASE_PRICES[from]);
    const toPrice = simulatePrice(to, BASE_PRICES[to]);
    const rate = fromPrice / toPrice;

    return Response.json({
      from,
      to,
      rate: parseFloat(rate.toFixed(8)),
      fromPrice,
      toPrice,
      fee: 0.005, // 0.5% swap fee
      updatedAt: new Date().toISOString(),
    });
  }

  return Response.json({ error: "Invalid type parameter. Use: prices, ohlcv, symbols, or rates" }, { status: 400 });
};

export const config: Config = {
  path: "/api/market-data",
  method: ["GET"],
};
