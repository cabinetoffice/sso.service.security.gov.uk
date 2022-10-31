# == caching policies ==

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_cache_policy" "sso_wsgi_cache" {
  name        = "Custom-SSO-WSGI-Cache-${terraform.workspace}"
  default_ttl = 30
  max_ttl     = 60
  min_ttl     = 1
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "whitelist"
      cookies {
        items = [
          "__Host-Session",
          "__host-session",
          "__Host-Browser",
          "__host-browser",
          "__Host-RememberMe",
          "__host-rememberme"
        ]
      }
    }
    headers_config {
      header_behavior = "whitelist"
      headers {
        items = [
          "CloudFront-Viewer-Country-Name",
          "Origin",
          "Access-Control-Request-Method",
          "Access-Control-Request-Headers",
          "X-Forwarded-For",
          "true-client-ip",
          "true-user-agent",
          "true-host",
          "x-cloudfront",
        ]
      }
    }
    query_strings_config {
      query_string_behavior = "all"
    }
  }
}

data "aws_cloudfront_cache_policy" "caching_enabled" {
  name = "Managed-CachingOptimized"
}

# == origin request policies ==

data "aws_cloudfront_origin_request_policy" "all" {
  name = "Managed-AllViewer"
}

data "aws_cloudfront_origin_request_policy" "s3_for_caching" {
  name = "Managed-CORS-S3Origin"
}

resource "aws_cloudfront_origin_request_policy" "sso_wsgi" {
  name    = "Custom-SSO-WSGI-Origin-${terraform.workspace}"
  comment = ""

  cookies_config {
    cookie_behavior = "whitelist"
    cookies {
      items = [
        "__Host-Session",
        "__host-session",
        "__Host-Browser",
        "__host-browser",
        "__Host-RememberMe",
        "__host-rememberme"
      ]
    }
  }
  headers_config {
    header_behavior = "whitelist"
    headers {
      items = [
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
        "X-Forwarded-For",
        "true-client-ip",
        "true-user-agent",
        "true-host",
        "x-cloudfront",
      ]
    }
  }
  query_strings_config {
    query_string_behavior = "all"
  }
}

# == functions ==

// API viewer request to set the "true-client-ip" and "true-host" headers
resource "aws_cloudfront_function" "viewer_request" {
  name    = "viewer-request-sso-${terraform.workspace}"
  runtime = "cloudfront-js-1.0"
  comment = "viewer-request-sso-${terraform.workspace}"
  publish = true
  code    = file("viewer-request/index.min.js")
}

// all viewer responses to set the security headers
resource "aws_cloudfront_function" "viewer_response" {
  name    = "viewer-response-sso-${terraform.workspace}"
  runtime = "cloudfront-js-1.0"
  comment = "viewer-response-sso-${terraform.workspace}"
  publish = true
  code    = file("viewer-response/index.min.js")
}

# == distribution ==

resource "aws_cloudfront_distribution" "cdn" {
  lifecycle {
    ignore_changes = [
      http_version
    ]
  }

  origin {
    domain_name = aws_s3_bucket.cdn_source_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.cdn_source_bucket.cloudfront_access_identity_path
    }
  }

  origin {
    domain_name = split("/", aws_lambda_function_url.wsgi_latest.function_url)[2]
    origin_id   = local.lambda_origin_id

    custom_origin_config {
      http_port  = "80"
      https_port = "443"

      origin_ssl_protocols   = ["TLSv1.2"]
      origin_protocol_policy = "https-only"
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = local.primary_domain
  default_root_object = ""

  aliases = local.use_acm ? [local.primary_domain, "www.${local.primary_domain}"] : []

  default_cache_behavior {
    allowed_methods  = [
      "GET",
      "HEAD",
      "DELETE",
      "OPTIONS",
      "PATCH",
      "POST",
      "PUT"
    ]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.lambda_origin_id

    cache_policy_id          = aws_cloudfront_cache_policy.sso_wsgi_cache.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.sso_wsgi.id
    compress               = false
    viewer_protocol_policy = "redirect-to-https"

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.viewer_request.arn
    }

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.viewer_response.arn
    }
  }

  ordered_cache_behavior {
    path_pattern     = "/assets/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_enabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.s3_for_caching.id
    compress                 = true
    viewer_protocol_policy   = "redirect-to-https"

    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.viewer_response.arn
    }
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = { "Name" : local.primary_domain }

  viewer_certificate {
    cloudfront_default_certificate = local.use_acm ? false : true
    acm_certificate_arn            = local.use_acm ? aws_acm_certificate.cdn[0].arn : null
    ssl_support_method             = local.use_acm ? "sni-only" : null
    minimum_protocol_version       = local.use_acm ? "TLSv1.2_2021" : null
  }
}
