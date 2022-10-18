variable "IS_CI" {
  type    = bool
  default = false
}

locals {
  s3_origin_id       = "${terraform.workspace}-sso-s3"
  primary_domain     = "${terraform.workspace == "prod" ? "sso.service.security.gov.uk" : (
    terraform.workspace == "nonprod" ? "sso.nonprod-service.security.gov.uk" : "test.sso.service.security.gov.uk"
  )}"

  use_acm            = terraform.workspace == "prod" ? true : (terraform.workspace == "nonprod" ? true : false)

  lambda_origin_id   = "${terraform.workspace}-sso-lambda"
  lambda_name        = "sso-lambda-${terraform.workspace}"
  iam_role           = "sso-lambda-role-${terraform.workspace}"
  iam_policy         = "sso-lambda-policy-${terraform.workspace}"
}
