function handler(event) {
    var request = event.request;

    var client_ip = '';
    if (
      typeof(event.viewer) == "object" &&
      typeof(event.viewer['ip']) == "string"
    ) {
      client_ip = event.viewer.ip;
    } else if (
      typeof(request.headers['x-forwarded-for']) == "object"
    ) {
      client_ip = request.headers['x-forwarded-for'].value;
    }

    request.headers['true-client-ip'] = { value: client_ip };

    var host = '';
    if (typeof(request.headers['host']) == "object") {
        host = request.headers['host'].value;
    } else if (typeof(request.headers[':authority']) == "object") {
        host = request.headers[':authority'].value;
    }
    host = host.split(":")[0];
    request.headers['true-host'] = { value: host };

    var ua = '';
    if (typeof(request.headers['user-agent']) == "object") {
        ua = request.headers['user-agent'].value;
    }
    request.headers['true-user-agent'] = { value: ua };

    var norm_uri = (typeof(request.uri) == "string" ? request.uri : "/")
      .toLowerCase()
      .split("?")[0]
      .split("#")[0]
      .replace(/\/+/, '\/');

    if (norm_uri.match(/^(\/.well[-_]known)?\/security\.txt$/)) {
      return redirect(
        "https://vulnerability-reporting.service.security.gov.uk/.well-known/security.txt",
        true
      );
    }

    if (norm_uri.match(/^\/not-recognised(\.html?)?$/)) {
      return redirect(
        "/help#dont-recognise-email-or-text",
        true
      );
    }

    if (norm_uri.match(/^\/.well[-_]known\/change-password$/)) {
      return redirect(
        "/help#how-do-i-change-my-password",
        true
      );
    }

    return request;
}

function redirect(url, cache, type, type_string) {
    if (typeof(type) == "undefined") {
      type = 302;
    }
    if (typeof(type_string) == "undefined") {
      type_string = "Found";
    }

    if (typeof(cache) == "undefined") {
      cache = false;
    }

    var response = {
      "statusCode": type,
      "statusDescription": type_string,
      "headers": {
        "location": {
          "value": url
        }
      }
    };

    if (cache) {
      response["headers"]['cache-control'] = {
        value: 'public, max-age=3600, immutable'
      };
    }

    return response;
}

if (typeof(module) === "object") {
    module.exports = handler;
}
