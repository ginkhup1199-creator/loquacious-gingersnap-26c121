import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const functionsDir = join(process.cwd(), "netlify", "functions");
const docsFunctionFile = join(functionsDir, "api-v2-docs.mts");

function listFunctionFiles() {
  return readdirSync(functionsDir)
    .filter((name) => name.startsWith("api-") && name.endsWith(".mts"))
    .map((name) => join(functionsDir, name));
}

function extractConfigPath(source) {
  const configBlock = source.match(/export\s+const\s+config\s*:\s*Config\s*=\s*\{[\s\S]*?\};/m);
  if (!configBlock) return null;
  const pathMatch = configBlock[0].match(/path\s*:\s*"([^"]+)"/m);
  return pathMatch ? pathMatch[1] : null;
}

function extractDocsEndpoints(source) {
  const endpointsBlock = source.match(/const\s+ENDPOINTS\s*=\s*\[([\s\S]*?)\];/m);
  if (!endpointsBlock) return null;

  const paths = [];
  const pathRegex = /path\s*:\s*"([^"]+)"/g;
  for (const match of endpointsBlock[1].matchAll(pathRegex)) {
    paths.push(match[1]);
  }

  return paths;
}

function hasLegacyDocsLanguage(source) {
  return /legacy/i.test(source);
}

const files = listFunctionFiles();
const pathToFile = new Map();
const errors = [];

for (const filePath of files) {
  const source = readFileSync(filePath, "utf8");
  const endpointPath = extractConfigPath(source);

  if (!endpointPath) {
    errors.push(`Missing export config path in ${filePath}`);
    continue;
  }

  if (!endpointPath.startsWith("/api/v2/")) {
    errors.push(`Non-v2 endpoint path '${endpointPath}' in ${filePath}`);
  }

  const existing = pathToFile.get(endpointPath);
  if (existing) {
    errors.push(`Duplicate endpoint path '${endpointPath}' in both ${existing} and ${filePath}`);
    continue;
  }

  pathToFile.set(endpointPath, filePath);
}

const docsSource = readFileSync(docsFunctionFile, "utf8");
const docsEndpoints = extractDocsEndpoints(docsSource);

if (!docsEndpoints || docsEndpoints.length === 0) {
  errors.push(`Missing or empty ENDPOINTS list in ${docsFunctionFile}`);
} else {
  const docsPathSet = new Set();

  for (const docsPath of docsEndpoints) {
    if (!docsPath.startsWith("/api/v2/")) {
      errors.push(`Docs endpoint path '${docsPath}' is not a v2 path in ${docsFunctionFile}`);
    }

    if (docsPathSet.has(docsPath)) {
      errors.push(`Duplicate docs endpoint path '${docsPath}' in ${docsFunctionFile}`);
      continue;
    }
    docsPathSet.add(docsPath);

    if (!pathToFile.has(docsPath)) {
      errors.push(
        `Docs endpoint path '${docsPath}' in ${docsFunctionFile} does not map to any function config path`,
      );
    }
  }
}

if (hasLegacyDocsLanguage(docsSource)) {
  errors.push(`Legacy wording detected in ${docsFunctionFile}; keep v2 docs canonical`);
}

if (errors.length > 0) {
  console.error("Endpoint guard failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log(`Endpoint guard passed: ${pathToFile.size} unique /api/v2/* function paths validated.`);