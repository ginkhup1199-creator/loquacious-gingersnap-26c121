import type { Config, Context } from "@netlify/functions";
import {
  secureJson,
  getClientIp,
} from "../lib/security.js";

interface PricePoint {
  price: number;
  change24h: number;
}

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

const COINGECKO_IDS: Record<string, string> = {
  BTC: "bitcoin", ETH: "ethereum", BNB: "binancecoin", SOL: "solana", XRP: "ripple",
  ADA: "cardano", AVAX: "avalanche-2", DOGE: "dogecoin", DOT: "polkadot", LINK: "chainlink",
  TRX: "tron", MATIC: "matic-network", SHIB: "shiba-inu", LTC: "litecoin", BCH: "bitcoin-cash",
  UNI: "uniswap", NEAR: "near", APT: "aptos", XLM: "stellar", ATOM: "cosmos",
  FIL: "filecoin", HBAR: "hedera-hashgraph", ETC: "ethereum-classic", INJ: "injective-protocol", RNDR: "render-token",
  LDO: "lido-dao", OP: "optimism", ARB: "arbitrum", MKR: "maker", GRT: "the-graph",
  STX: "blockstack", ALGO: "algorand", AAVE: "aave", SNX: "havven", THETA: "theta-token",
  SAND: "the-sandbox", AXS: "axie-infinity", MANA: "decentraland", FTM: "fantom", GALA: "gala",
  XMR: "monero", IMX: "immutable-x", KAS: "kaspa", VET: "vechain", CRO: "crypto-com-chain",
  MNT: "mantle", QNT: "quant-network", EGLD: "elrond-erd-2",
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

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

// Fetch live prices from Binance public API (no key required)
// Uses batches to avoid oversized URLs.
async function fetchBinancePrices(): Promise<Record<string, PricePoint> | null> {
  try {
    const entries = Object.entries(SYMBOL_PAIRS);
    const chunks = chunkArray(entries, 15);
    const prices: Record<string, PricePoint> = {};

    for (const part of chunks) {
      const symbols = encodeURIComponent(JSON.stringify(part.map(([, pair]) => pair)));
      const url = `https://api.binance.com/api/v3/ticker/24hr?symbols=${symbols}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) continue;
      const data = await res.json() as Array<{ symbol: string; lastPrice: string; priceChangePercent: string }>;
      for (const item of data) {
        const sym = part.find(([, pair]) => pair === item.symbol)?.[0];
        if (!sym) continue;
        const dec = DECIMALS[sym] ?? 2;
        prices[sym] = {
          price: parseFloat(parseFloat(item.lastPrice).toFixed(dec)),
          change24h: parseFloat(parseFloat(item.priceChangePercent).toFixed(2)),
        };
      }
    }

    return Object.keys(prices).length > 0 ? prices : null;
  } catch {
    return null;
  }
}

async function fetchCoinGeckoPrices(symbols: string[]): Promise<Record<string, PricePoint> | null> {
  try {
    const ids = symbols
      .map((s) => COINGECKO_IDS[s])
      .filter(Boolean)
      .join(",");
    if (!ids) return null;

    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${encodeURIComponent(ids)}&vs_currencies=usd&include_24hr_change=true`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;

    const data = await res.json() as Record<string, { usd?: number; usd_24h_change?: number }>;
    const out: Record<string, PricePoint> = {};

    for (const sym of symbols) {
      const id = COINGECKO_IDS[sym];
      if (!id || !data[id] || typeof data[id].usd !== "number") continue;
      const dec = DECIMALS[sym] ?? 2;
      out[sym] = {
        price: parseFloat(data[id].usd!.toFixed(dec)),
        change24h: parseFloat((data[id].usd_24h_change ?? 0).toFixed(2)),
      };
    }

    return Object.keys(out).length > 0 ? out : null;
  } catch {
    return null;
  }
}

async function fetchBybitTicker(symbol: string): Promise<PricePoint | null> {
  try {
    const pair = SYMBOL_PAIRS[symbol];
    if (!pair) return null;
    const url = `https://api.bybit.com/v5/market/tickers?category=linear&symbol=${pair}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    const payload = await res.json() as {
      retCode?: number;
      result?: { list?: Array<{ lastPrice?: string; price24hPcnt?: string }> };
    };
    const ticker = payload.result?.list?.[0];
    if (!ticker?.lastPrice) return null;
    const dec = DECIMALS[symbol] ?? 2;
    const pct = Number(ticker.price24hPcnt ?? "0") * 100;
    return {
      price: parseFloat(Number(ticker.lastPrice).toFixed(dec)),
      change24h: parseFloat(pct.toFixed(2)),
    };
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

async function fetchBybitOhlcv(symbol: string): Promise<Array<Record<string, number | string>> | null> {
  try {
    const pair = SYMBOL_PAIRS[symbol];
    if (!pair) return null;
    const url = `https://api.bybit.com/v5/market/kline?category=linear&symbol=${pair}&interval=60&limit=24`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    const payload = await res.json() as { result?: { list?: string[][] } };
    const list = payload.result?.list;
    if (!Array.isArray(list) || list.length === 0) return null;

    const dec = DECIMALS[symbol] ?? 2;
    // Bybit returns latest first, so reverse to oldest->newest.
    const ordered = [...list].reverse();
    return ordered.map((k) => ({
      timestamp: new Date(Number(k[0])).toISOString(),
      open: parseFloat(Number(k[1]).toFixed(dec)),
      high: parseFloat(Number(k[2]).toFixed(dec)),
      low: parseFloat(Number(k[3]).toFixed(dec)),
      close: parseFloat(Number(k[4]).toFixed(dec)),
      volume: parseFloat(Number(k[5]).toFixed(2)),
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

  if (type === "swap-rates") {
    const livePrices = await fetchBinancePrices();
    const cgPrices = livePrices ? null : await fetchCoinGeckoPrices(SUPPORTED_SYMBOLS);
    const rates: Record<string, number> = {};
    for (const sym of SUPPORTED_SYMBOLS) {
      if (STABLECOINS.has(sym)) { rates[sym] = 1; }
      else if (livePrices && livePrices[sym]) {
        rates[sym] = livePrices[sym].price;
      } else if (cgPrices && cgPrices[sym]) {
        rates[sym] = cgPrices[sym].price;
      } else { rates[sym] = FALLBACK_PRICES[sym] ?? 0; }
    }
    const source = livePrices ? "binance" : (cgPrices ? "coingecko" : "fallback");
    return secureJson({ rates, source, timestamp: new Date().toISOString() }, 200, true);
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
    const bybit = live ? null : await fetchBybitOhlcv(symbol);
    const ohlcv = live ?? bybit ?? generateOhlcv(symbol, FALLBACK_PRICES[symbol] ?? 1);
    const source = live ? "binance" : (bybit ? "bybit" : "fallback");
    return secureJson({ symbol, ohlcv, source, timestamp: new Date().toISOString() }, 200, true);
  }

  // Single symbol price request
  if (symbol) {
    if (STABLECOINS.has(symbol)) {
      return secureJson({ symbol, price: 1.0, change24h: 0, source: "stable", timestamp: new Date().toISOString() }, 200, true);
    }
    const livePrices = await fetchBinancePrices();
    const cgPrices = livePrices ? null : await fetchCoinGeckoPrices([symbol]);
    if (livePrices && livePrices[symbol]) {
      return secureJson({ symbol, ...livePrices[symbol], source: "binance", timestamp: new Date().toISOString() }, 200, true);
    }
    if (cgPrices && cgPrices[symbol]) {
      return secureJson({ symbol, ...cgPrices[symbol], source: "coingecko", timestamp: new Date().toISOString() }, 200, true);
    }
    const bybit = await fetchBybitTicker(symbol);
    if (bybit) {
      return secureJson({ symbol, ...bybit, source: "bybit", timestamp: new Date().toISOString() }, 200, true);
    }
    const fallback = FALLBACK_PRICES[symbol];
    if (!fallback) return secureJson({ error: "Symbol not supported" }, 400);
    return secureJson({ symbol, price: fallback, change24h: 0, source: "fallback", timestamp: new Date().toISOString() }, 200, true);
  }

  // All prices request
  const livePrices = await fetchBinancePrices();
  const missingForCg = SUPPORTED_SYMBOLS.filter((s) => !STABLECOINS.has(s) && !(livePrices && livePrices[s]));
  const cgPrices = missingForCg.length > 0 ? await fetchCoinGeckoPrices(missingForCg) : null;
  const prices: Record<string, PricePoint> = {};
  for (const sym of SUPPORTED_SYMBOLS) {
    if (STABLECOINS.has(sym)) {
      prices[sym] = { price: 1.0, change24h: 0 };
    } else if (livePrices && livePrices[sym]) {
      prices[sym] = livePrices[sym];
    } else if (cgPrices && cgPrices[sym]) {
      prices[sym] = cgPrices[sym];
    } else {
      prices[sym] = { price: FALLBACK_PRICES[sym] ?? 0, change24h: 0 };
    }
  }
  const source = livePrices ? "binance" : (cgPrices ? "coingecko" : "fallback");
  return secureJson({ prices, source, timestamp: new Date().toISOString() }, 200, true);
};

export const config: Config = {
  path: "/api/v2/market-data",
  method: ["GET"],
};
