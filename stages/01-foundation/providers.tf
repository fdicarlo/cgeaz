terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
  }

  # Backend values come from labs/03-foundation/backend.hcl (written by bootstrap.sh;
  # CI writes the same file from repository variables).
  # Init with: terraform init -backend-config=../../labs/03-foundation/backend.hcl
  backend "azurerm" {
    key              = "01-foundation.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
  # Explicit targeting: the subscription is a reviewed input, never whatever
  # `az account show` happens to point at on the operator's laptop.
  subscription_id = var.subscription_id
}
