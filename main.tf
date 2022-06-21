variable "api_url" {
  #--- UNCOMMENT FOR TEAM OR ORG TENANTS
  default = "https://tme-lab-works.console.ves.volterra.io/api"
  #--- UNCOMMENT FOR INDIVIDUAL/FREEMIUM
  # default = "https://console.ves.volterra.io/api"
}

# This points the absolute path of the api credentials file you downloaded from Volterra
variable "api_p12_file" {
  default = ""
}
# export VES_P12_PASSWORD=<your ssl pass>

variable "api_p12_password" {
  default = ""
}

# Below is an option to pass access key and secret key as you probably don't want to save it in a file
# Use env variable before you run `terraform apply` command
# export TF_VAR_aws_access_key=<your aws access key>
# export TF_VAR_aws_secret_key=<your aws secret key>

variable "aws_access_key" {
  default = ""
}

variable "aws_secret_key" {
  default = ""
}

variable "aws_region" {
  default = "us-east-2"
}

variable "aws_az" {
  default = "us-east-2a"
}


variable "namespace" {
  default = ""
}

variable "name" {
  default = ""
}

variable "app_fqdn" {
  default = ""
}



# This is the VPC CIDR for AWS
variable "aws_vpc_cidr" {
  default = "192.168.0.0/16"
}

# Map to hold different CE CIDR, if you are not using default aws_vpc_cidr then you need to change the below map as well
variable "aws_subnet_ce_cidr" {
  default = {
    "outside"  = "192.168.32.0/19"
    "inside"   = "192.168.128.0/19"
    "workload"   = "192.168.192.0/19"
  }
}

# Map to hold different EKS cidr with key as desired AZ on which the subnet should exist
variable "aws_subnet_eks_cidr" {
  default = {
    "us-east-2a" = "192.168.224.0/19"
    "us-east-2b" = "192.168.64.0/19"
    "us-east-2c" = "192.168.96.0/19"
  }
}

variable "allow_tls_prefix_list" {
  type        = list(string)
  description = "Allow TLS prefix list"
  default     = ["gcr.io", "storage.googleapis.com", "docker.io", "docker.com", "amazonaws.com", "gitlab.com", "elastic.co", "gitlab-static.net", "console.ves.volterra.io", "registry.npmjs.org"]
}


locals{
  namespace = var.namespace != "" ? var.namespace : var.name
}


module "skg" {
  source                    = "github.com/vtobi/terraform-F5-XC-secure-k8s-gateway"
  skg_name                  = var.name
  volterra_namespace        = local.namespace
  volterra_namespace_exists = true
  app_domain                = var.app_fqdn
  aws_secret_key            = var.aws_secret_key
  aws_access_key            = var.aws_access_key
  aws_region                = var.aws_region
  aws_az                    = var.aws_az
  aws_vpc_cidr              = var.aws_vpc_cidr
  aws_subnet_ce_cidr        = var.aws_subnet_ce_cidr
  aws_subnet_eks_cidr       = var.aws_subnet_eks_cidr
  allow_tls_prefix_list     = var.allow_tls_prefix_list
}

output "kubeconfig_filename" {
  value = module.skg.kubeconfig_filename
}

output "app_url" {
  value = var.app_fqdn
}
