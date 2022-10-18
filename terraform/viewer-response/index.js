function handler(event) {
    var response = event.response;

    if (typeof(response) == "undefined") {
      console.log("handler: WARNING event.response UNDEFINED! Ensure this function is set to viewer response.");
      if (typeof(event.request) != "undefined") {
        return event.request;
      }
      return;
    }

    var uri = typeof(event.request) == "undefined" ? "/" : (
      typeof(event.request.uri) == "undefined" ? "/" : event.request.uri
    );
    var to_cache = false;
    if (
      uri.indexOf("/assets/") == 0
      || uri.indexOf("/.well-known/") == 0
      || uri.indexOf("/security.txt") == 0
      || uri.indexOf("/robots.txt") == 0
    ) {
      to_cache = true;
    }

    var headers = response.headers;

    var currentHeaderKeys = Object.keys(headers);

    if ('server' in headers) {
        delete headers['server'];
    }
    if ('x-powered-by' in headers) {
        delete headers['x-powered-by'];
    }

    if (!currentHeaderKeys.includes('cache-control')) {
      headers['cache-control'] = {
        value: to_cache ? "public, max-age=3600" : "private, no-store"
      };
    }

    if (!currentHeaderKeys.includes('strict-transport-security')) {
      headers['strict-transport-security'] = { value: "max-age=31536000; includeSubdomains; preload" };
    }

    if (!currentHeaderKeys.includes('expect-ct')) {
      headers['expect-ct'] = { value: "max-age=0" };
    }

    if (!currentHeaderKeys.includes('content-security-policy')) {
      headers['content-security-policy'] = { value: "default-src 'self';" };
    }

    if (!currentHeaderKeys.includes('x-content-type-options')) {
      headers['x-content-type-options'] = { value: "nosniff" };
    }

    if (!currentHeaderKeys.includes('x-frame-options')) {
      headers['x-frame-options'] = { value: "DENY" };
    }

    if (!currentHeaderKeys.includes('referrer-policy')) {
      headers['referrer-policy'] = { value: "strict-origin-when-cross-origin" };
    }

    var perms = [
      ["geolocation", null],
      ["microphone", null],
      ["camera", null],
      ["payment", null],
      ["xr-spatial-tracking", null],
      ["magnetometer", null],
      ["payment", null],
      ["sync-xhr", "'self'"],
    ];

    if (!currentHeaderKeys.includes('permissions-policy')) {
      headers['permissions-policy'] = {
        // format: feature1=(sources), feature2=(sources)
        value: perms.map(p => p[0] + "=(" + (
          p[1] == null ? "" : p[1].replace("'self'", "self")
        ) + ")").join(", ")
      };
    }

    if (!currentHeaderKeys.includes('feature-policy')) {
      headers['feature-policy'] = {
        // format: feature1 sources; feature2 sources;
        value: perms.map(p => p[0] + " " + (p[1] == null ? "'none'" : p[1])).join("; ")
      };
    }

    if (!currentHeaderKeys.includes('cross-origin-embedder-policy')) {
      headers['cross-origin-embedder-policy'] = { value: "unsafe-none" };
    }

    if (!currentHeaderKeys.includes('cross-origin-opener-policy')) {
      headers['cross-origin-opener-policy'] = { value: "same-origin" };
    }

    if (!currentHeaderKeys.includes('cross-origin-resource-policy')) {
      headers['cross-origin-resource-policy'] = { value: "same-origin" };
    }

    //Return modified response
    return response;
}

if (typeof(module) === "object") {
    module.exports = handler;
}
