import type { Config, Context } from "@netlify/functions";
import {
  secureJson,
  getClientIp,
} from "../lib/security.js";

// Market data with realistic price simulation.
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

// Decimal places per asset
const DECIMALS: Record<string, number> = {
  BTC: 2, ETH: 2, BNB: 2, SOL: 2,
  XRP: 4, ADA: 4, AVAX: 2, DOGE: 4,
  USDT: 4, USDC: 4,
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
