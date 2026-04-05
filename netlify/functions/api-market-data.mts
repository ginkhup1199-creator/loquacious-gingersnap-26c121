import type { Config, Context } from "@netlify/functions";
import {
  secureJson,
  getClientIp,
} from "../lib/security.js";

// Market data with realistic price simulation.
// In production, replace with a real price feed API (CoinGecko, Binance, etc.)
const BASE_PRICES: Record<string, number> = {
  BTC: 65000, ETH: 3200, BNB: 600, SOL: 145, XRP: 0.58,
  ADA: 0.45, AVAX: 35, DOGE: 0.15, USDT: 1, USDC: 1,
  DOT: 7.20, LINK: 14.50, TRX: 0.12, MATIC: 0.75, SHIB: 0.000025,
  LTC: 82.40, BCH: 450.10, UNI: 7.80, NEAR: 6.50, APT: 9.20,
  XLM: 0.11, ATOM: 8.90, XMR: 130.50, FIL: 5.80, IMX: 2.10,
  KAS: 0.14, HBAR: 0.08, ETC: 28.40, INJ: 25.60, RNDR: 8.40,
  VET: 0.04, LDO: 2.10, OP: 2.50, CRO: 0.14, ARB: 1.10,
  MNT: 0.85, MKR: 2800, GRT: 0.28, STX: 2.10, ALGO: 0.18,
  QNT: 95.50, AAVE: 90.20, SNX: 2.80, EGLD: 40.50, THETA: 2.10,
  SAND: 0.45, AXS: 7.20, MANA: 0.42, FTM: 0.80, GALA: 0.04,
};

const SUPPORTED_SYMBOLS = Object.keys(BASE_PRICES);

// Price volatility per asset (percentage range for simulation)
const VOLATILITY: Record<string, number> = {
  BTC: 0.005, ETH: 0.007, BNB: 0.008, SOL: 0.012, XRP: 0.010,
  ADA: 0.011, AVAX: 0.013, DOGE: 0.020, USDT: 0, USDC: 0,
  DOT: 0.015, LINK: 0.014, TRX: 0.012, MATIC: 0.016, SHIB: 0.025,
  LTC: 0.010, BCH: 0.012, UNI: 0.015, NEAR: 0.018, APT: 0.020,
  XLM: 0.013, ATOM: 0.014, XMR: 0.010, FIL: 0.018, IMX: 0.020,
  KAS: 0.022, HBAR: 0.015, ETC: 0.012, INJ: 0.022, RNDR: 0.020,
  VET: 0.015, LDO: 0.018, OP: 0.020, CRO: 0.012, ARB: 0.020,
  MNT: 0.018, MKR: 0.012, GRT: 0.018, STX: 0.020, ALGO: 0.015,
  QNT: 0.015, AAVE: 0.016, SNX: 0.018, EGLD: 0.015, THETA: 0.018,
  SAND: 0.020, AXS: 0.022, MANA: 0.020, FTM: 0.020, GALA: 0.025,
};

// Decimal places per asset
const DECIMALS: Record<string, number> = {
  BTC: 2, ETH: 2, BNB: 2, SOL: 2, XRP: 4,
  ADA: 4, AVAX: 2, DOGE: 4, USDT: 4, USDC: 4,
  DOT: 3, LINK: 3, TRX: 4, MATIC: 4, SHIB: 8,
  LTC: 2, BCH: 2, UNI: 3, NEAR: 3, APT: 3,
  XLM: 4, ATOM: 3, XMR: 2, FIL: 3, IMX: 3,
  KAS: 4, HBAR: 4, ETC: 2, INJ: 2, RNDR: 3,
  VET: 5, LDO: 3, OP: 3, CRO: 4, ARB: 3,
  MNT: 4, MKR: 2, GRT: 4, STX: 3, ALGO: 4,
  QNT: 2, AAVE: 2, SNX: 3, EGLD: 2, THETA: 3,
  SAND: 4, AXS: 3, MANA: 4, FTM: 4, GALA: 5,
};

// Simulate a realistic price with small random variation
function simulatePrice(symbol: string, basePrice: number): number {
  const vol = VOLATILITY[symbol] ?? 0.005;
  const change = (Math.random() * 2 - 1) * vol;
  const decimals = DECIMALS[symbol] ?? 2;
  return parseFloat((basePrice * (1 + change)).toFixed(decimals));
}

// Generate 24h OHLCV data points for a symbol
function generateOhlcv(symbol: string, basePrice: number, points = 24): Array<Record<string, number | string>> {
  const vol = (VOLATILITY[symbol] ?? 0.005) * 3;
  const decimals = DECIMALS[symbol] ?? 2;
  const data: Array<Record<string, number | string>> = [];
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
      open: parseFloat(open.toFixed(decimals)),
      high: parseFloat(high.toFixed(decimals)),
      low: parseFloat(low.toFixed(decimals)),
      close: parseFloat(close.toFixed(decimals)),
      volume: parseFloat(volume.toFixed(2)),
    });

    price = close;
  }

  return data;
}

export default async (req: Request, context: Context) => {
  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const url = new URL(req.url);
  const type = url.searchParams.get("type") || "prices";
  const symbol = (url.searchParams.get("symbol") || "").toUpperCase();

  // Validate symbol if provided
  if (symbol && !SUPPORTED_SYMBOLS.includes(symbol)) {
    return secureJson({ error: "Unsupported symbol" }, 400);
  }

  if (type === "symbols") {
    return secureJson({ symbols: SUPPORTED_SYMBOLS }, 200, true);
  }

  if (type === "ohlcv") {
    const sym = symbol || "BTC";
    const basePrice = BASE_PRICES[sym];
    return secureJson(
      { symbol: sym, data: generateOhlcv(sym, basePrice) },
      200, true
    );
  }

  if (type === "swap-rates") {
    const rates: Record<string, number> = {};
    for (const [sym, base] of Object.entries(BASE_PRICES)) {
      rates[sym] = simulatePrice(sym, base);
    }
    return secureJson({ rates, timestamp: new Date().toISOString() }, 200, true);
  }

  // Default: prices
  if (symbol) {
    const basePrice = BASE_PRICES[symbol];
    const price = simulatePrice(symbol, basePrice);
    const change24h = parseFloat(((Math.random() * 10) - 5).toFixed(2));
    return secureJson({
      symbol,
      price,
      change24h,
      timestamp: new Date().toISOString(),
    }, 200, true);
  }

  const prices: Record<string, { price: number; change24h: number }> = {};
  for (const [sym, base] of Object.entries(BASE_PRICES)) {
    prices[sym] = {
      price: simulatePrice(sym, base),
      change24h: parseFloat(((Math.random() * 10) - 5).toFixed(2)),
    };
  }

  return secureJson({ prices, timestamp: new Date().toISOString() }, 200, true);
};

export const config: Config = {
  path: "/api/market-data",
  method: ["GET"],
};
