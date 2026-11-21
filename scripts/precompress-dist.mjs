import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

const assetsDir = join(process.cwd(), "dist", "assets");

try {
  for (const name of readdirSync(assetsDir)) {
    if (!/\.(js|css|svg)$/i.test(name)) continue;
    const p = join(assetsDir, name);
    if (!statSync(p).isFile()) continue;
    const raw = readFileSync(p);
    if (raw.length < 256) continue;

    const br = brotliCompressSync(raw, {
      params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
    });
    if (br.length < raw.length) {
      writeFileSync(`${p}.br`, br);
    }

    const gz = gzipSync(raw, { level: 9 });
    if (gz.length < raw.length) {
      writeFileSync(`${p}.gz`, gz);
    }
  }
} catch (err) {
  console.error("precompress-dist failed:", err);
  process.exit(1);
}
