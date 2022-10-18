const expect         = require("chai").expect;
const viewer_response = require("./index.min.js");

fixture_1 = {
  "version": "1.0",
  "context": {
    "distributionDomainName": "d111111abcdef8.cloudfront.net",
    "distributionId": "EDFDVBD6EXAMPLE",
    "eventType": "viewer-response",
    "requestId": "EXAMPLEntjQpEXAMPLE_SG5Z-EXAMPLEPmPfEXAMPLEu3EqEXAMPLE=="
  },
  "viewer": {
    "ip": "198.51.100.11"
  },
  "request": {
    "method": "GET",
    "uri": "/media/index.mpd",
    "querystring": {
      "ID": {
        "value": "42"
      },
      "Exp": {
        "value": "1619740800"
      },
      "TTL": {
        "value": "1440"
      },
      "NoValue": {
        "value": ""
      },
      "querymv": {
        "value": "val1",
        "multiValue": [
          {
            "value": "val1"
          },
          {
            "value": "val2,val3"
          }
        ]
      }
    },
    "headers": {
      "host": {
        "value": "video.example.com"
      },
      "user-agent": {
        "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"
      },
      "accept": {
        "value": "application/json",
        "multiValue": [
          {
            "value": "application/json"
          },
          {
            "value": "application/xml"
          },
          {
            "value": "text/html"
          }
        ]
      },
      "accept-language": {
        "value": "en-GB,en;q=0.5"
      },
      "accept-encoding": {
        "value": "gzip, deflate, br"
      },
      "origin": {
        "value": "https://website.example.com"
      },
      "referer": {
        "value": "https://website.example.com/videos/12345678?action=play"
      },
      "cloudfront-viewer-country": {
        "value": "GB"
      }
    },
    "cookies": {
      "Cookie1": {
        "value": "value1"
      },
      "Cookie2": {
        "value": "value2"
      },
      "cookie_consent": {
        "value": "true"
      },
      "cookiemv": {
        "value": "value3",
        "multiValue": [
          {
            "value": "value3"
          },
          {
            "value": "value4"
          }
        ]
      }
    }
  },
  "response": {
    "statusCode": 200,
    "statusDescription": "OK",
    "headers": {
      "date": {
        "value": "Mon, 04 Apr 2021 18:57:56 GMT"
      },
      "server": {
        "value": "gunicorn/19.9.0"
      },
      "access-control-allow-origin": {
        "value": "*"
      },
      "access-control-allow-credentials": {
        "value": "true"
      },
      "content-type": {
        "value": "application/json"
      },
      "content-length": {
        "value": "701"
      }
    },
    "cookies": {
      "ID": {
        "value": "id1234",
        "attributes": "Expires=Wed, 05 Apr 2021 07:28:00 GMT"
      },
      "Cookie1": {
        "value": "val1",
        "attributes": "Secure; Path=/; Domain=example.com; Expires=Wed, 05 Apr 2021 07:28:00 GMT",
        "multiValue": [
          {
            "value": "val1",
            "attributes": "Secure; Path=/; Domain=example.com; Expires=Wed, 05 Apr 2021 07:28:00 GMT"
          },
          {
            "value": "val2",
            "attributes": "Path=/cat; Domain=example.com; Expires=Wed, 10 Jan 2021 07:28:00 GMT"
          }
        ]
      }
    }
  }
}

describe("viewer_response", function() {
  it('fixture_1 should add headers', function(done) {
    var res = viewer_response(fixture_1);

    const headers = Object.keys(res["headers"]);

    expect(headers).to.not.include('content-security-policy-report-only');
    expect(headers).to.not.include('server');
    expect(headers).to.include('x-frame-options');

    expect(headers).to.include('cache-control');
    expect(res["headers"]["cache-control"].value).to.equal("private, no-store");

    done();
  });
});
