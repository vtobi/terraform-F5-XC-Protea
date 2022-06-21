resource "volterra_origin_pool" "ssh" {
  depends_on = [kubernetes_deployment.cowrie]
  name                   = format("%s-ssh-pool", var.name)
  namespace              = local.namespace
  description            = format("Origin pool pointing to Protea Cowrie SSH k8s service running on CE")
  loadbalancer_algorithm = "ROUND ROBIN"
  origin_servers {
    k8s_service {
      inside_network  = true
      outside_network = false
      vk8s_networks   = false
      service_name    = "cowrie.default"
      site_locator {
        site {
          name      = module.skg.f5_xc_aws_vpc_site[0]
          namespace = "system"
        }
      }
    }
  }

  port               = 2222
  no_tls             = true
  endpoint_selection = "LOCAL_PREFERRED"
}

resource "volterra_origin_pool" "telnet" {
  depends_on = [kubernetes_deployment.cowrie]
  name                   = format("%s-telnet-pool", var.name)
  namespace              = local.namespace
  description            = format("Origin pool pointing to Protea Cowrie Telnet k8s service running on CE")
  loadbalancer_algorithm = "ROUND ROBIN"
  origin_servers {
    k8s_service {
      inside_network  = true
      outside_network = false
      vk8s_networks   = false
      service_name    = "cowrie.default"
      site_locator {
        site {
          name      = module.skg.f5_xc_aws_vpc_site[0]
          namespace = "system"
        }
      }
    }
  }

  port               = 2223
  no_tls             = true
  endpoint_selection = "LOCAL_PREFERRED"
}

resource "volterra_tcp_loadbalancer" "cowrie-ssh" {
  depends_on = [volterra_origin_pool.ssh]
  name                            = format("%s-ssh-lb", var.name)
  namespace                       = local.namespace
  description                     = format("SSH loadbalancer object for %s origin server", var.name)
  domains                         = [var.app_fqdn]
  advertise_on_public_default_vip = true
  dns_volterra_managed            = true

  listen_port                     = 22
  origin_pools_weights {
      pool {
        name = volterra_origin_pool.ssh.name
        namespace = local.namespace
      }
  }
}

resource "volterra_tcp_loadbalancer" "cowrie-telnet" {
  depends_on = [volterra_origin_pool.telnet]
  name                            = format("%s-telnet-lb", var.name)
  namespace                       = local.namespace
  description                     = format("Telnet loadbalancer object for %s origin server", var.name)
  domains                         = [var.app_fqdn]
  advertise_on_public_default_vip = true
  dns_volterra_managed            = true

  listen_port                     = 23
  origin_pools_weights {
      pool {
        name = volterra_origin_pool.telnet.name
        namespace = local.namespace
      }
  }

}


#resource "volterra_app_firewall" "this" {
#  for_each                 = toset(var.eks_only ? [] : [var.name])
#  name                     = format("%s-waf", var.name)
#  description              = format("WAF in block mode for %s", var.name)
#  namespace                = local.namespace
#  allow_all_response_codes = true
#}

#resource "volterra_http_loadbalancer" "this" {
#  for_each                        = toset(var.eks_only ? [] : [var.name])
#  name                            = format("%s-lb", var.name)
#  namespace                       = local.namespace
#  description                     = format("HTTPS loadbalancer object for %s origin server", var.skg_name)
#  domains                         = [var.app_fqdn]
#  advertise_on_public_default_vip = true
#  default_route_pools {
#    pool {
#      name      = volterra_origin_pool.this[each.key].name
#      namespace = local.namespace
#    }
#  }
#  https_auto_cert {
#    add_hsts      = var.enable_hsts
#    http_redirect = var.enable_redirect
#    no_mtls       = true
#  }
#  app_firewall {
#    name      = volterra_app_firewall.this[each.key].name
#    namespace = local.namespace
#  }
#  disable_waf                     = false
#  disable_rate_limit              = true
#  round_robin                     = true
#  service_policies_from_namespace = true
#  no_challenge                    = false
#  js_challenge {
#    js_script_delay = var.js_script_delay
#    cookie_expiry   = var.js_cookie_expiry
#  }
#}
