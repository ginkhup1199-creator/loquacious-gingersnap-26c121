import type { Config, Context } from "@netlify/functions";
import { secureJson } from "../lib/security.js";

interface CryptoInfo {
  symbol: string;
  name: string;
  price: number;
  change24h: number;
  pair: string;
}

const CRYPTO_INFO: Record<string, { name: string; pair: string }> = {
  BTC: { name: "Bitcoin", pair: "BTCUSDT" },
  ETH: { name: "Ethereum", pair: "ETHUSDT" },
  BNB: { name: "BNB", pair: "BNBUSDT" },
  SOL: { name: "Solana", pair: "SOLUSDT" },
  XRP: { name: "XRP", pair: "XRPUSDT" },
  ADA: { name: "Cardano", pair: "ADAUSDT" },
  AVAX: { name: "Avalanche", pair: "AVAXUSDT" },
  DOGE: { name: "Dogecoin", pair: "DOGEUSDT" },
  DOT: { name: "Polkadot", pair: "DOTUSDT" },
  LINK: { name: "Chainlink", pair: "LINKUSDT" },
  TRX: { name: "TRON", pair: "TRXUSDT" },
  MATIC: { name: "Polygon", pair: "MATICUSDT" },
  SHIB: { name: "Shiba Inu", pair: "SHIBUSDT" },
  LTC: { name: "Litecoin", pair: "LTCUSDT" },
  BCH: { name: "Bitcoin Cash", pair: "BCHUSDT" },
  UNI: { name: "Uniswap", pair: "UNIUSDT" },
  NEAR: { name: "NEAR Protocol", pair: "NEARUSDT" },
  APT: { name: "Aptos", pair: "APTUSDT" },
  XLM: { name: "Stellar", pair: "XLMUSDT" },
  ATOM: { name: "Cosmos", pair: "ATOMUSDT" },
  FIL: { name: "Filecoin", pair: "FILUSDT" },
  HBAR: { name: "Hedera", pair: "HBARUSDT" },
  ETC: { name: "Ethereum Classic", pair: "ETCUSDT" },
  INJ: { name: "Injective", pair: "INJUSDT" },
  RNDR: { name: "Render", pair: "RNDRUSDT" },
  LDO: { name: "Lido DAO", pair: "LDOUSDT" },
  OP: { name: "Optimism", pair: "OPUSDT" },
  ARB: { name: "Arbitrum", pair: "ARBUSDT" },
  MKR: { name: "Maker", pair: "MKRUSDT" },
  GRT: { name: "The Graph", pair: "GRTUSDT" },
  STX: { name: "Stacks", pair: "STXUSDT" },
  ALGO: { name: "Algorand", pair: "ALGOUSDT" },
  AAVE: { name: "Aave", pair: "AAVEUSDT" },
  SNX: { name: "Synthetix", pair: "SNXUSDT" },
  THETA: { name: "Theta Network", pair: "THETAUSDT" },
  SAND: { name: "The Sandbox", pair: "SANDUSDT" },
  AXS: { name: "Axie Infinity", pair: "AXSUSDT" },
  MANA: { name: "Decentraland", pair: "MANAUSDT" },
  FTM: { name: "Fantom", pair: "FTMUSDT" },
  GALA: { name: "Gala", pair: "GALAUSDT" },
  XMR: { name: "Monero", pair: "XMRUSDT" },
  IMX: { name: "Immutable", pair: "IMXUSDT" },
  KAS: { name: "Kaspa", pair: "KASUSDT" },
  VET: { name: "VeChain", pair: "VETUSDT" },
  CRO: { name: "Cronos", pair: "CROUSDT" },
  MNT: { name: "Mantle", pair: "MNTUSDT" },
  QNT: { name: "Quant", pair: "QNTUSDT" },
  EGLD: { name: "MultiversX", pair: "EGLDUSDT" },
  USDT: { name: "Tether", pair: "USDT" },
  USDC: { name: "USD Coin", pair: "USDC" },
};

export default async (req: Request, context: Context) => {
  if (!process.env.ADMIN_TOKEN) {
    return secureJson({ error: "Service not configured" }, 503);
  }

  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  try {
    // Fetch all live prices from market-data API
    const pricesRes = await fetch(new URL("/api/v2/market-data", req.url).toString(), {
      method: "GET",
      headers: { "User-Agent": "NexusTrade/1.0" },
    });

    if (!pricesRes.ok) {
      console.warn("Failed to fetch market-data for k-lineup");
      // Return lineup with fallback prices
      return secureJson(
        {
          lineup: Object.entries(CRYPTO_INFO).map(([symbol, info]) => ({
            symbol,
            name: info.name,
            pair: info.pair,
            price: 0,
            change24h: 0,
            source: "offline",
          })),
          status: "offline",
          timestamp: new Date().toISOString(),
        },
        200,
        true
      );
    }

    const pricesData = await pricesRes.json() as {
      prices?: Record<string, { price: number; change24h: number }>;
      source?: string;
      providerStats?: Record<string, number>;
    };

    const lineup: CryptoInfo[] = [];
    const prices = pricesData.prices || {};

    for (const [symbol, info] of Object.entries(CRYPTO_INFO)) {
      const priceData = prices[symbol] || { price: 0, change24h: 0 };
      lineup.push({
        symbol,
        name: info.name,
        price: priceData.price,
        change24h: priceData.change24h,
        pair: info.pair,
      });
    }

    // Sort by market cap estimate (BTC first, then major alts)
    const majorSymbols = ["BTC", "ETH", "BNB", "SOL", "XRP", "ADA", "AVAX", "DOGE"];
    lineup.sort((a, b) => {
      const aIdx = majorSymbols.indexOf(a.symbol);
      const bIdx = majorSymbols.indexOf(b.symbol);
      if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
      if (aIdx !== -1) return -1;
      if (bIdx !== -1) return 1;
      return a.symbol.localeCompare(b.symbol);
    });

    console.log(`K-lineup: ${lineup.length} cryptos, source=${pricesData.source}`);

    return secureJson(
      {
        lineup,
        total: lineup.length,
        source: pricesData.source || "mixed",
        providerStats: pricesData.providerStats,
        timestamp: new Date().toISOString(),
      },
      200,
      true
    );
  } catch (err) {
    console.error("K-lineup error:", err instanceof Error ? err.message : String(err));
    return secureJson(
      {
        error: "Failed to fetch crypto lineup",
        timestamp: new Date().toISOString(),
      },
      500
    );
  }
};

export const config: Config = {
  path: "/api/v2/k-lineup",
  method: ["GET"],
};
