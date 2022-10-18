data "aws_route53_zone" "z" {
  count = local.use_acm ? 1 : 0
  name = local.primary_domain
}

# === CDN TLS certificate ===

resource "aws_acm_certificate" "cdn" {
  count = local.use_acm ? 1 : 0
  provider = aws.us_east_1

  domain_name       = local.primary_domain
  validation_method = "DNS"

  subject_alternative_names = [
    "www.${local.primary_domain}"
  ]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "acm_validation" {
  for_each = {
    for dvo in (local.use_acm ? aws_acm_certificate.cdn[0].domain_validation_options : []) : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.z[0].zone_id
}
