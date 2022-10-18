provider "aws" {
  region = "eu-west-2"

  default_tags {
    tags = {
      "Service" : "sso.service.security.gov.uk",
      "Reference" : "https://github.com/cabinetoffice/sso.service.security.gov.uk",
      "Environment" : terraform.workspace
    }
  }
}

provider "aws" {
  region = "us-east-1"
  alias  = "us_east_1"

  default_tags {
    tags = {
      "Service" : "sso.service.security.gov.uk",
      "Reference" : "https://github.com/cabinetoffice/sso.service.security.gov.uk",
      "Environment" : terraform.workspace
    }
  }
}

terraform {
  backend "s3" {
    bucket = "co-security-gov-uk-tfstate"
    key    = "sso-service-security-gov-uk.tfstate"
    region = "eu-west-2"
  }
}
