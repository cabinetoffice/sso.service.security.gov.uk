resource "aws_lambda_function_url" "wsgi_latest" {
  function_name      = aws_lambda_function.lambda.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_function" "lambda" {
  filename         = "../target.zip"
  source_code_hash = filebase64sha256("../target.zip")

  description      = "${terraform.workspace}: SSO Lambda WSGI"
  function_name    = local.lambda_name
  role             = aws_iam_role.lambda_role.arn
  handler          = "wsgi.lambda_handler"
  runtime          = "python3.9"

  publish = true

  memory_size = 256
  timeout     = 30

  lifecycle {
    ignore_changes = [
      last_modified,
      environment
    ]
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_pa,
    aws_cloudwatch_log_group.lambda_lg,
  ]
}

resource "aws_iam_role" "lambda_role" {
  name               = local.iam_role
  assume_role_policy = data.aws_iam_policy_document.arpd.json
}

resource "aws_cloudwatch_log_group" "lambda_lg" {
  name              = "/aws/lambda/${local.lambda_name}"
  retention_in_days = 14
}

# See also the following AWS managed policy: AWSLambdaBasicExecutionRole
resource "aws_iam_policy" "lambda_policy" {
  name        = local.iam_policy
  path        = "/"
  description = "IAM policy for logging from a lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "kms:GetPublicKey",
          "kms:DescribeKey",
          "kms:Verify",
          "kms:Sign"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:kms:eu-west-2:765294862901:key/*",
      },
      {
        Action = [
          "kms:ListKeys"
        ]
        Effect   = "Allow"
        Resource = "*",
      },
      {
        Action = [
          "s3:PutObject",
          "s3:Get*",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.clients_bucket.id}/*",
          "arn:aws:s3:::${aws_s3_bucket.clients_bucket.id}",
          "arn:aws:s3:::${aws_s3_bucket.sessions_bucket.id}/*",
          "arn:aws:s3:::${aws_s3_bucket.sessions_bucket.id}"
        ],
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_pa" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

data "aws_iam_policy_document" "arpd" {
  statement {
    sid    = "AllowAwsToAssumeRole"
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type = "Service"

      identifiers = [
        "lambda.amazonaws.com",
      ]
    }
  }
}
