#!/usr/bin/env node
// Behaviour test for workers/pximg-relay/index.js with a stubbed fetch.
import assert from "node:assert";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const workerPath = path.resolve(here, "../../workers/pximg-relay/index.js");
const worker = (await import(pathToFileURL(workerPath).href)).default;

let seen = null;
globalThis.fetch = async (url, init) => {
  seen = { url, init };
  return new Response(new Uint8Array([1, 2, 3]), {
    status: 200,
    headers: {
      "content-type": "image/jpeg",
      "set-cookie": "leak=1",
      "cache-control": "max-age=60",
      "content-length": "3",
    },
  });
};

const call = (pathname, init = {}) =>
  worker.fetch(new Request(`https://relay.example${pathname}`, init), {}, {});

let failures = 0;
const check = (label, fn) => {
  try {
    fn();
    console.log(`ok   ${label}`);
  } catch (error) {
    failures += 1;
    console.log(`FAIL ${label} ${error.message}`);
  }
};

await (async () => {
  const posted = await call("/pximg/img-original/a.jpg", { method: "POST" });
  check("non-GET is rejected", () => assert.equal(posted.status, 405));

  const wrong = await call("/img-original/a.jpg");
  check("requests outside the prefix are rejected", () => assert.equal(wrong.status, 404));

  const ok = await call("/pximg/img-original/a.jpg?x=1", {
    headers: { "user-agent": "browser/1", accept: "image/*", range: "bytes=0-1" },
  });
  check("path is rewritten onto pximg", () =>
    assert.equal(seen.url, "https://i.pximg.net/img-original/a.jpg?x=1"));
  check("referer is set for pximg", () =>
    assert.equal(seen.init.headers.get("referer"), "https://www.pixiv.net/"));
  check("browser user agent passes through", () =>
    assert.equal(seen.init.headers.get("user-agent"), "browser/1"));
  check("range passes through", () => assert.equal(seen.init.headers.get("range"), "bytes=0-1"));
  check("caching is requested", () => assert.equal(seen.init.cf.cacheEverything, true));
  check("set-cookie does not reach the client", () => assert.equal(ok.headers.get("set-cookie"), null));
  check("successful images are cached long", () =>
    assert.match(ok.headers.get("cache-control"), /immutable/));
  const bytes = new Uint8Array(await ok.arrayBuffer());
  check("body is streamed through", () => assert.deepEqual([...bytes], [1, 2, 3]));
  check("status passes through", () => assert.equal(ok.status, 200));

  seen = null;
  await call("/pximg/img-original/b.jpg", { method: "HEAD" });
  check("HEAD reaches the origin", () => assert.equal(seen.init.method, "HEAD"));
})();

if (failures) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall checks passed");
