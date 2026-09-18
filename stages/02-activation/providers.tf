terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
    # azurerm has a RESOURCE for Defender plan pricing but no data source —
    # azapi fills that gap by reading any ARM resource. This is the discovery
    # pattern for anything the azurerm provider can't yet interrogate.
    azapi = {
      source  = "azure/azapi"
      version = "~> 2.12"
    }
  }

  backend "azurerm" {
    key              = "02-activation.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azapi" {
  subscription_id = var.subscription_id
}
