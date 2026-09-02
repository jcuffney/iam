# cuffney.com's DNS lives in Cloudflare; only these records are managed here.
#
# proxied = false (grey cloud) is LOAD-BEARING, not cosmetic: proxying through
# Cloudflare would make every client appear as a Cloudflare egress IP, which
# collapses per-IP rate limiting into shared buckets and poisons audit IPs.
# ACM's TLS on API Gateway already covers transport security.

resource "cloudflare_dns_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api.domain_validation_options :
    dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  }

  zone_id = var.cloudflare_zone_id
  name    = trimsuffix(each.value.name, ".")
  type    = each.value.type
  content = trimsuffix(each.value.value, ".")
  ttl     = 60
  proxied = false
}

resource "cloudflare_dns_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = var.api_domain
  type    = "CNAME"
  content = aws_apigatewayv2_domain_name.api.domain_name_configuration[0].target_domain_name
  ttl     = 1     # auto
  proxied = false # grey cloud — see header comment
}
