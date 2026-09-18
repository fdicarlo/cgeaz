terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.81"
    }
  }

  backend "azurerm" {
    key              = "06-enforcement.tfstate"
    use_azuread_auth = true
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "terraform_remote_state" "foundation" {
  backend = "azurerm"
  config = {
    resource_group_name  = var.state_resource_group
    storage_account_name = var.state_storage_account
    container_name       = "tfstate"
    key                  = "01-foundation.tfstate"
    use_azuread_auth     = true
  }
}
