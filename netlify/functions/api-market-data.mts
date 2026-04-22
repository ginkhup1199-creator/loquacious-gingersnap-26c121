import type { Config, Context } from "@netlify/functions";
import {
  secureJson,
  getClientIp,
} from "../lib/security.js";

// Supported symbols mapped to their Binance ticker pairs
const SYMBOL_PAIRS: Record<string, string> = {
  BTC: "BTCUSDT", ETH: "ETHUSDT", BNB: "BNBUSDT", SOL: "SOLUSDT", XRP: "XRPUSDT",
  ADA: "ADAUSDT", AVAX: "AVAXUSDT", DOGE: "DOGEUSDT", DOT: "DOTUSDT", LINK: "LINKUSDT",
  TRX: "TRXUSDT", MATIC: "MATICUSDT", SHIB: "SHIBUSDT", LTC: "LTCUSDT", BCH: "BCHUSDT",
  UNI: "UNIUSDT", NEAR: "NEARUSDT", APT: "APTUSDT", XLM: "XLMUSDT", ATOM: "ATOMUSDT",
  FIL: "FILUSDT", HBAR: "HBARUSDT", ETC: "ETCUSDT", INJ: "INJUSDT", RNDR: "RNDRUSDT",
  LDO: "LDOUSDT", OP: "OPUSDT", ARB: "ARBUSDT", MKR: "MKRUSDT", GRT: "GRTUSDT",
  STX: "STXUSDT", ALGO: "ALGOUSDT", AAVE: "AAVEUSDT", SNX: "SNXUSDT", THETA: "THETAUSDT",
  SAND: "SANDUSDT", AXS: "AXSUSDT", MANA: "MANAUSDT", FTM: "FTMUSDT", GALA: "GALAUSDT",
  XMR: "XMRUSDT", IMX: "IMXUSDT", KAS: "KASUSDT", VET: "VETUSDT",
  CRO: "CROUSDT", MNT: "MNTUSDT", QNT: "QNTUSDT", EGLD: "EGLDUSDT",
};

// Stablecoins — always return 1.0000
const STABLECOINS = new Set(["USDT", "USDC"]);

const SUPPORTED_SYMBOLS = [...Object.keys(SYMBOL_PAIRS), ...STABLECOINS];

// Decimal places per asset
const DECIMALS: Record<string, number> = {
  BTC: 2, ETH: 2, BNB: 2, SOL: 2, XRP: 4,
  ADA: 4, AVAX: 2, DOGE: 4, USDT: 4, USDC: 4,
  DOT: 3, LINK: 3, TRX: 4, MATIC: 4, SHIB: 8,
  LTC: 2, BCH: 2, UNI: 3, NEAR: 3, APT: 3,
  XLM: 4, ATOM: 3, FIL: 3, HBAR: 4, ETC: 2,
  INJ: 2, RNDR: 3, LDO: 3, OP: 3, ARB: 3,
  MKR: 2, GRT: 4, STX: 3, ALGO: 4, AAVE: 2,
  SNX: 3, THETA: 3, SAND: 4, AXS: 3, MANA: 4, FTM: 4, GALA: 5,
  XMR: 2, IMX: 3, KAS: 4, VET: 5, CRO: 4, MNT: 3, QNT: 2, EGLD: 2,
};

// Fallback prices used only if Binance API is unreachable
const FALLBACK_PRICES: Record<string, number> = {
  BTC: 94000, ETH: 1800, BNB: 600, SOL: 145, XRP: 0.58,
  ADA: 0.45, AVAX: 35, DOGE: 0.15, USDT: 1, USDC: 1,
  DOT: 7.20, LINK: 14.50, TRX: 0.12, MATIC: 0.75, SHIB: 0.000025,
  LTC: 82.40, BCH: 450.10, UNI: 7.80, NEAR: 6.50, APT: 9.20,
  XLM: 0.11, ATOM: 8.90, FIL: 5.80, HBAR: 0.08, ETC: 28.40,
  INJ: 25.60, RNDR: 8.40, LDO: 2.10, OP: 2.50, ARB: 1.10,
  MKR: 2800, GRT: 0.28, STX: 2.10, ALGO: 0.18, AAVE: 90.20,
  SNX: 2.80, THETA: 2.10, SAND: 0.45, AXS: 7.20, MANA: 0.42, FTM: 0.80, GALA: 0.04,
  XMR: 215.00, IMX: 1.40, KAS: 0.12, VET: 0.028, CRO: 0.09, MNT: 0.80, QNT: 105.00, EGLD: 30.00,
};

// Fetch live prices from Binance public API (no key required)
async function fetchBinancePrices(): Promise<Record<string, number> | null> {
  try {
    const pairs = Object.values(SYMBOL_PAIRS).join('%22,%22');
    const url = `https://api.binance.com/api/v3/ticker/24hr?symbols=[%22${pairs}%22]`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const data = await res.json() as Array<{ symbol: string; lastPrice: string; priceChangePercent: string }>;
    const prices: Record<string, { price: number; change24h: number }> = {};
    for (const item of data) {
      const sym = Object.entries(SYMBOL_PAIRS).find(([, pair]) => pair === item.symbol)?.[0];
      if (sym) {
        const dec = DECIMALS[sym] ?? 2;
        prices[sym] = {
          price: parseFloat(parseFloat(item.lastPrice).toFixed(dec)),
          change24h: parseFloat(parseFloat(item.priceChangePercent).toFixed(2)),
        };
      }
    }
    return prices as unknown as Record<string, number>;
  } catch {
    return null;
  }
}

// Fetch 24h OHLCV klines from Binance for a single symbol
async function fetchBinanceOhlcv(symbol: string): Promise<Array<Record<string, number | string>> | null> {
  try {
    const pair = SYMBOL_PAIRS[symbol];
    if (!pair) return null;
    const url = `https://api.binance.com/api/v3/klines?symbol=${pair}&interval=1h&limit=24`;
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const raw = await res.json() as number[][];
    const dec = DECIMALS[symbol] ?? 2;
    return raw.map((k) => ({
      timestamp: new Date(k[0]).toISOString(),
      open: parseFloat(parseFloat(String(k[1])).toFixed(dec)),
      high: parseFloat(parseFloat(String(k[2])).toFixed(dec)),
      low: parseFloat(parseFloat(String(k[3])).toFixed(dec)),
      close: parseFloat(parseFloat(String(k[4])).toFixed(dec)),
      volume: parseFloat(parseFloat(String(k[5])).toFixed(2)),
    }));
  } catch {
    return null;
  }
}

// Fallback OHLCV generator used if Binance is unreachable
function generateOhlcv(symbol: string, basePrice: number, points = 24): Array<Record<string, number | string>> {
  const vol = 0.005;
  const dec = DECIMALS[symbol] ?? 2;
  const data: Array<Record<string, number | string>> = [];
  let price = basePrice;
  const now = Date.now();
  for (let i = points - 1; i >= 0; i--) {
    const open = price;
    const high = open * (1 + Math.random() * vol);
    const low = open * (1 - Math.random() * vol);
    const close = low + Math.random() * (high - low);
    data.push({
      timestamp: new Date(now - i * 3600 * 1000).toISOString(),
      open: parseFloat(open.toFixed(dec)),
      high: parseFloat(high.toFixed(dec)),
      low: parseFloat(low.toFixed(dec)),
      close: parseFloat(close.toFixed(dec)),
      volume: parseFloat((basePrice * (1000 + Math.random() * 9000)).toFixed(2)),
    });
    price = close;
  }
  return data;
}

export default async (req: Request, context: Context) => {
  try {
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

  if (type === "swap-rates") {
    const livePrices = await fetchBinancePrices() as unknown as Record<string, { price: number; change24h: number }> | null;
    const rates: Record<string, number> = {};
    for (const sym of SUPPORTED_SYMBOLS) {
      if (STABLECOINS.has(sym)) { rates[sym] = 1; }
      else if (livePrices && (livePrices as Record<string, { price: number; change24h: number }>)[sym]) {
        rates[sym] = (livePrices as Record<string, { price: number; change24h: number }>)[sym].price;
      } else { rates[sym] = FALLBACK_PRICES[sym] ?? 0; }
    }
    return secureJson({ rates, source: livePrices ? "binance" : "fallback", timestamp: new Date().toISOString() }, 200, true);
  }

  // OHLCV request for a specific symbol
  if (type === "ohlcv" && symbol) {
    if (!SYMBOL_PAIRS[symbol] && !STABLECOINS.has(symbol)) {
      return secureJson({ error: "Symbol not supported" }, 400);
    }
    if (STABLECOINS.has(symbol)) {
      return secureJson({ symbol, ohlcv: generateOhlcv(symbol, 1), timestamp: new Date().toISOString() }, 200, true);
    }
    const live = await fetchBinanceOhlcv(symbol);
    const ohlcv = live ?? generateOhlcv(symbol, FALLBACK_PRICES[symbol] ?? 1);
    return secureJson({ symbol, ohlcv, source: live ? "binance" : "fallback", timestamp: new Date().toISOString() }, 200, true);
  }

  // Single symbol price request
  if (symbol) {
    if (STABLECOINS.has(symbol)) {
      return secureJson({ symbol, price: 1.0, change24h: 0, source: "stable", timestamp: new Date().toISOString() }, 200, true);
    }
    const livePrices = await fetchBinancePrices() as unknown as Record<string, { price: number; change24h: number }> | null;
    if (livePrices && livePrices[symbol]) {
      return secureJson({ symbol, ...livePrices[symbol], source: "binance", timestamp: new Date().toISOString() }, 200, true);
    }
    const fallback = FALLBACK_PRICES[symbol];
    if (!fallback) return secureJson({ error: "Symbol not supported" }, 400);
    return secureJson({ symbol, price: fallback, change24h: 0, source: "fallback", timestamp: new Date().toISOString() }, 200, true);
  }

  // All prices request
  const livePrices = await fetchBinancePrices() as unknown as Record<string, { price: number; change24h: number }> | null;
  const prices: Record<string, { price: number; change24h: number }> = {};
  for (const sym of SUPPORTED_SYMBOLS) {
    if (STABLECOINS.has(sym)) {
      prices[sym] = { price: 1.0, change24h: 0 };
    } else if (livePrices && (livePrices as Record<string, { price: number; change24h: number }>)[sym]) {
      prices[sym] = (livePrices as Record<string, { price: number; change24h: number }>)[sym];
    } else {
      prices[sym] = { price: FALLBACK_PRICES[sym] ?? 0, change24h: 0 };
    }
  }

  return secureJson({ prices, source: livePrices ? "binance" : "fallback", timestamp: new Date().toISOString() }, 200, true);
  } catch {
    return secureJson({ prices: {}, source: "fallback", timestamp: new Date().toISOString() }, 200, true);
  }
};

export const config: Config = {
  path: "/api/v2/market-data",
  method: ["GET"],
};
