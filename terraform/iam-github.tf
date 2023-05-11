resource "aws_iam_role" "github_role" {
  name               = "sso-github-deployment-${terraform.workspace}"
  assume_role_policy = data.aws_iam_policy_document.github_ipd.json
}

# See also the following AWS managed policy: AWSLambdaBasicExecutionRole
resource "aws_iam_policy" "github_policy" {
  name        = "sso-github-deployment-${terraform.workspace}"
  path        = "/"

  policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
          {
              Effect   = "Allow",
              Action   = [
                  "route53:List*",
                  "route53:Get*",
                  "route53:Change*",
                  "acm:List*",
                  "acm:Get*",
                  "acm:Describe*",
                  "iam:Get*",
                  "iam:List*",
                  "iam:Delete*",
                  "iam:CreatePolicyVersion",
                  "iam:Update*",
                  "logs:Put*",
                  "logs:Describe*",
                  "logs:List*",
                  "s3:List*",
                  "s3:Head*",
                  "lambda:List*",
                  "lambda:Get*",
                  "ec2:Describe*",
                  "cloudfront:List*",
                  "cloudfront:Get*",
                  "cloudfront:Describe*",
              ],
              Resource = "*"
          },
          {
              Effect   = "Allow",
              Action   = [
                  "lambda:TagResource",
                  "lambda:UntagResource",
                  "lambda:Update*",
                  "lambda:Create*",
                  "lambda:Delete*",
                  "lambda:Put*",
                  "lambda:Publish*",
              ],
              Resource = [
                  "arn:aws:lambda:*:*:function:${local.lambda_name}"
              ]
          },
          {
              Effect   = "Allow",
              Action   = [
                  "s3:*"
              ],
              Resource = [
                  aws_s3_bucket.cdn_source_bucket.arn,
                  aws_s3_bucket.clients_bucket.arn,
                  aws_s3_bucket.sessions_bucket.arn,
                  "${aws_s3_bucket.cdn_source_bucket.arn}/*",
                  "${aws_s3_bucket.clients_bucket.arn}/*",
                  "${aws_s3_bucket.sessions_bucket.arn}/*",
              ]
          },
          {
              Effect   = "Allow",
              Action   = [
                "s3:PutObject",
                "s3:GetObject",
              ],
              Resource = [
                  "arn:aws:s3:::co-security-gov-uk-tfstate/env:/${terraform.workspace}/sso-service-security-gov-uk.tfstate",
                  "arn:aws:s3:::sso-service-security-gov-uk.tfstate/sso-service-security-gov-uk.tfstate"
              ]
          },
          {
              Effect   = "Allow",
              Action   = [
                "cloudfront:Associate*",
                "cloudfront:Create*",
                "cloudfront:Delete*",
                "cloudfront:Publish*",
                "cloudfront:Test*",
                "cloudfront:Update*",
              ],
              Resource = [
                  "arn:aws:cloudfront::*:cache-policy/${aws_cloudfront_cache_policy.sso_wsgi_cache.id}",
                  "arn:aws:cloudfront::*:cache-policy/${data.aws_cloudfront_cache_policy.caching_disabled.id}",
                  "arn:aws:cloudfront::*:cache-policy/${data.aws_cloudfront_cache_policy.caching_enabled.id}",
                  "arn:aws:cloudfront::*:origin-request-policy/${aws_cloudfront_origin_request_policy.sso_wsgi.id}",
                  "arn:aws:cloudfront::*:origin-request-policy/${data.aws_cloudfront_origin_request_policy.all.id}",
                  "arn:aws:cloudfront::*:origin-request-policy/${data.aws_cloudfront_origin_request_policy.s3_for_caching.id}",
                  aws_cloudfront_function.viewer_request.arn,
                  aws_cloudfront_function.viewer_response.arn,
                  aws_cloudfront_distribution.cdn.arn,
              ]
          }
      ]
  })
}

resource "aws_iam_role_policy_attachment" "github_pa" {
  role       = aws_iam_role.github_role.name
  policy_arn = aws_iam_policy.github_policy.arn
}

data "aws_iam_policy_document" "github_ipd" {
  statement {
    effect = "Allow"

    principals {
      type = "Federated"

      identifiers = [
        "arn:aws:iam::765294862901:oidc-provider/token.actions.githubusercontent.com",
      ]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:cabinetoffice/sso.service.security.gov.uk:*"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "token.actions.githubusercontent.com:iss"
      values   = ["https://token.actions.githubusercontent.com"]
    }
  }
}
