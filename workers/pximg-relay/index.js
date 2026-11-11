const PREFIX = "/pximg";
const ORIGIN = "https://i.pximg.net";
const REFERER = "https://www.pixiv.net/";
const UA = "Piku/3.7.0";
const MAX_AGE = 604800;

const PASS_THROUGH = ["accept", "range", "if-none-match", "if-modified-since"];

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405 });
    }
    if (url.pathname !== PREFIX && !url.pathname.startsWith(`${PREFIX}/`)) {
      return new Response("not found", { status: 404 });
    }

    const target = ORIGIN + url.pathname.slice(PREFIX.length) + url.search;
    const headers = new Headers({
      referer: REFERER,
      "user-agent": request.headers.get("user-agent") || UA,
    });
    for (const name of PASS_THROUGH) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }

    const response = await fetch(target, {
      method: request.method,
      headers,
      cf: { cacheEverything: true, cacheTtl: MAX_AGE },
      redirect: "follow",
    });

    const out = new Headers(response.headers);
    out.delete("set-cookie");
    // A cached error would outlive the mistake that caused it.
    if (response.ok) out.set("cache-control", `public, max-age=${MAX_AGE}, immutable`);
    return new Response(response.body, { status: response.status, headers: out });
  },
};
