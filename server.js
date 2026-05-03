/**
 * Express wrapper for Netlify Functions.
 *
 * Dynamically loads every *.mts handler from netlify/functions/, reads the
 * exported `config.path` / `config.method` metadata, and registers matching
 * Express routes.  Each handler receives a standard Web API `Request` object
 * and a minimal Netlify `Context` shim, then the returned Web API `Response`
 * is forwarded back to the Express response.
 */

import { register } from "node:module";
import { pathToFileURL } from "node:url";

// Register tsx so Node can import TypeScript (.mts) files at runtime.
register("tsx/esm", pathToFileURL("./"));

import express from "express";
import { readdir } from "node:fs/promises";
import { resolve, join } from "node:path";

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

// Parse raw body as a Buffer so we can forward it into the Web Request.
app.use(express.raw({ type: "*/*", limit: "10mb" }));

/**
 * Converts an Express request into a Web API Request object.
 */
function toWebRequest(req) {
  const protocol = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers.host || `localhost:${PORT}`;
  const url = `${protocol}://${host}${req.originalUrl}`;

  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const v of value) headers.append(key, v);
    } else if (value !== undefined) {
      headers.set(key, value);
    }
  }

  const hasBody = req.body && req.body.length > 0;
  const init = {
    method: req.method,
    headers,
    body: hasBody ? req.body : undefined,
    // Required so Node's fetch implementation doesn't reject bodies on GET/HEAD
    duplex: hasBody ? "half" : undefined,
  };

  return new Request(url, init);
}

/**
 * Minimal Netlify Context shim — only `ip` is used by the handlers.
 */
function makeContext(req) {
  return {
    ip:
      (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      req.socket?.remoteAddress ||
      "(unknown)",
    // Stub out the rest of the Context interface so handlers don't throw.
    account: {},
    deploy: {},
    flags: {},
    geo: {},
    params: {},
    requestId: "",
    server: {},
    site: {},
    next: async () => new Response("Not found", { status: 404 }),
    log: console,
    cookies: { get: () => undefined, set: () => {}, delete: () => {} },
  };
}

/**
 * Sends a Web API Response back through Express.
 */
async function sendWebResponse(webResponse, res) {
  res.status(webResponse.status);

  for (const [key, value] of webResponse.headers.entries()) {
    res.setHeader(key, value);
  }

  const body = await webResponse.arrayBuffer();
  res.end(Buffer.from(body));
}

/**
 * Registers a single Netlify function module as Express route(s).
 */
function registerHandler(handler, config) {
  const paths = Array.isArray(config.path) ? config.path : [config.path];
  const methods = Array.isArray(config.method)
    ? config.method.map((m) => m.toLowerCase())
    : [config.method.toLowerCase()];

  for (const routePath of paths) {
    for (const method of methods) {
      if (typeof app[method] !== "function") {
        console.warn(`[server] Skipping unsupported HTTP method: ${method.toUpperCase()} ${routePath}`);
        continue;
      }

      app[method](routePath, async (req, res) => {
        try {
          const webReq = toWebRequest(req);
          const context = makeContext(req);
          const webRes = await handler(webReq, context);
          await sendWebResponse(webRes, res);
        } catch (err) {
          console.error(`[server] Handler error for ${method.toUpperCase()} ${routePath}:`, err);
          if (!res.headersSent) {
            res.status(500).json({ error: "Internal server error" });
          }
        }
      });

      console.log(`[server] Registered ${method.toUpperCase()} ${routePath}`);
    }
  }
}

async function loadFunctions() {
  const functionsDir = resolve("netlify/functions");
  const entries = await readdir(functionsDir);
  const moduleFiles = entries.filter((f) => f.endsWith(".mts") || f.endsWith(".mjs") || f.endsWith(".ts") || f.endsWith(".js"));

  let registered = 0;

  for (const file of moduleFiles) {
    const filePath = join(functionsDir, file);
    try {
      const mod = await import(filePath);
      const handler = mod.default;
      const config = mod.config;

      if (typeof handler !== "function") {
        console.warn(`[server] ${file}: no default export function, skipping`);
        continue;
      }
      if (!config?.path) {
        console.warn(`[server] ${file}: no config.path, skipping`);
        continue;
      }

      registerHandler(handler, config);
      registered++;
    } catch (err) {
      console.error(`[server] Failed to load ${file}:`, err);
    }
  }

  console.log(`[server] Loaded ${registered} function(s) from netlify/functions/`);
}

await loadFunctions();

app.listen(PORT, HOST, () => {
  console.log(`[server] Listening on http://${HOST}:${PORT}`);
});
