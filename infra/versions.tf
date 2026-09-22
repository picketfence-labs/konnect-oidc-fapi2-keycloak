terraform {
  required_version = ">= 1.11.0"

  required_providers {
    konnect = {
      source  = "kong/konnect"
      version = "~> 3.22.0"
    }
    auth0 = {
      source  = "auth0/auth0"
      version = "~> 1.57.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.1"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}

provider "konnect" {}
provider "auth0" {}
