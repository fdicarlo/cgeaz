# Tier 0 lint (docs/RUBRIC.md, dimension 1). Run: tflint --init && tflint --recursive
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.28.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}
