
resource "kubernetes_deployment" "cowrie" {
  depends_on = [module.skg]
  metadata {
    name = "cowrie"

    labels = {
      honeypot = "cowrie"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        honeypot = "cowrie"
      }
    }

    template {
      metadata {
        labels = {
          honeypot = "cowrie"
        }
      }

      spec {
        volume {
          name      = "cowrie-tmp"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name      = "cowrie-etc"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name      = "cowrie-log"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name      = "cowrie-dl"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name      = "cowrie-tty"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name = "cowrie-config"

          config_map {
            name = "cowrie-cfg-configmap"

            items {
              key  = "cowrie.cfg"
              path = "cowrie.cfg"
            }
          }
        }

        volume {
          name      = "filebeat-data"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name      = "filebeat-logs"
          empty_dir {
            medium = ""
          }
        }

        volume {
          name = "filebeat-config"

          config_map {
            name = "filebeat-configmap-cowrie"

            items {
              key  = "filebeat.yml"
              path = "filebeat.yml"
            }
          }
        }

        container {
          name  = "cowrie"
          image = "registry.gitlab.com/f5-protea/cowrie:latest"

          port {
            container_port = 2222
          }

          port {
            container_port = 2223
          }

          volume_mount {
            name       = "cowrie-tmp"
            mount_path = "/tmp/cowrie"
          }

          volume_mount {
            name       = "cowrie-config"
            mount_path = "/home/cowrie/cowrie/etc/cowrie.cfg"
            sub_path   = "cowrie.cfg"
          }

          volume_mount {
            name       = "cowrie-etc"
            mount_path = "/home/cowrie/cowrie/etc"
          }

          volume_mount {
            name       = "cowrie-dl"
            mount_path = "/home/cowrie/cowrie/dl"
          }

          volume_mount {
            name       = "cowrie-log"
            mount_path = "/home/cowrie/cowrie/log"
          }

          volume_mount {
            name       = "cowrie-tty"
            mount_path = "/home/cowrie/cowrie/log/tty"
          }

          image_pull_policy = "Always"
        }

        container {
          name  = "filebeat-sidecar"
          image = "docker.elastic.co/beats/filebeat:8.2.3"

          volume_mount {
            name       = "cowrie-log"
            mount_path = "/var/log"
          }

          volume_mount {
            name       = "filebeat-data"
            mount_path = "/usr/share/filebeat/data"
          }

          volume_mount {
            name       = "filebeat-logs"
            mount_path = "/usr/share/filebeat/logs"
          }

          volume_mount {
            name       = "filebeat-config"
            mount_path = "/usr/share/filebeat/filebeat.yml"
            sub_path   = "filebeat.yml"
          }
        }

        restart_policy = "Always"

        security_context {
          fs_group = 2000
        }
      }
    }

    strategy {
      type = "Recreate"
    }
  }
}

resource "kubernetes_config_map" "filebeat_configmap_cowrie" {
  depends_on = [module.skg]
  metadata {
    name = "filebeat-configmap-cowrie"
  }

  data = {
    "filebeat.yml" = "name: \"cowrie\"\ntags: [\"cowrie\", \"protea\"]\nfilebeat:\n  inputs:\n    - type: filestream\n      id: cowrie-json\n      paths:\n        - \"/var/log/cowrie.json\"\n      parsers:\n        - ndjson:\n            keys_under_root: true\noutput:\n  logstash:\n    hosts: [\"logstash.stir.sr.f5-demo.com:5244\"]\n"
  }
}

resource "kubernetes_config_map" "cowrie_cfg_configmap" {
  depends_on = [module.skg]
  metadata {
    name = "cowrie-cfg-configmap"
  }

  data = {
    "cowrie.cfg" = "# ============================================================================\n# General Cowrie Options\n# ============================================================================\n[honeypot]\n\n# Sensor name is used to identify this Cowrie instance. Used by the database\n# logging modules such as mysql.\n#\n# If not specified, the logging modules will instead use the IP address of the\n# server as the sensor name.\n#\n# (default: not specified)\nsensor_name=hipster-shop\n\n# Hostname for the honeypot. Displayed by the shell prompt of the virtual\n# environment\n#\n# (default: svr04)\nhostname = hipster-shop\n\n\n# Directory where to save log files in.\n#\n# (default: log)\n# log_path = var/log/cowrie\nlog_path = log\n\n# Directory where to save downloaded artifacts in.\n#\n# (default: downloads)\ndownload_path = $${honeypot:state_path}/downloads\n\n\n# Directory for static data files\n#\n# (default: share/cowrie)\nshare_path = share/cowrie\n\n\n# Directory for variable state files\n#\n# (default: var/lib/cowrie)\nstate_path = var/lib/cowrie\n\n\n# Directory for config files\n#\n# (default: etc)\netc_path = etc\n\n\n# Directory where virtual file contents are kept in.\n#\n# This is only used by commands like 'cat' to display the contents of files.\n# Adding files here is not enough for them to appear in the honeypot - the\n# actual virtual filesystem is kept in filesystem_file (see below)\n#\n# (default: honeyfs)\ncontents_path = honeyfs\n\n\n# Directory for creating simple commands that only output text.\n#\n# The command must be placed under this directory with the proper path, such\n# as:\n#   txtcmds/usr/bin/vi\n# The contents of the file will be the output of the command when run inside\n# the honeypot.\n#\n# In addition to this, the file must exist in the virtual filesystem\n#\n# (default: txtcmds)\ntxtcmds_path = txtcmds\n\n\n# Maximum file size (in bytes) for downloaded files to be stored in 'download_path'.\n# A value of 0 means no limit. If the file size is known to be too big from the start,\n# the file will not be stored on disk at all.\n#\n# (default: 0)\n#download_limit_size = 10485760\n\n# TTY logging will log a transcript of the complete terminal interaction in UML\n# compatible format.\n# (default: true)\nttylog = true\n\n# Default directory for TTY logs.\n# (default: ttylog_path = %(state_path)s/tty)\nttylog_path = $${honeypot:state_path}/tty\n\n# Interactive timeout determines when logged in sessions are\n# terminated for being idle. In seconds.\n# (default: 180)\ninteractive_timeout = 180\n\n# Authentication Timeout\n# The server disconnects after this time if the user has not successfully logged in.  If the value is 0,\n# there is no time limit.  The default is 120 seconds.\nauthentication_timeout = 120\n\n# EXPERIMENTAL: back-end to user for Cowrie, options: proxy or shell\n# (default: shell)\nbackend = shell\n\n# Timezone Cowrie uses for logging\n# This can be any valid timezone for the TZ environment variable\n# The special value `system` will let Cowrie use the system time zone\n# `system` is not recommended because you will need to deal with daylight\n# savings time and other special cases yourself when analysing the logs.\ntimezone = UTC\n\n# Custom prompt\n# By default, Cowrie creates a shell prompt like: root@svr03:~#\n# If you want something totally custom, uncomment the option below and set your prompt\n# Beware that the path won't be included in your prompt any longer\n# prompt = hello>\n\n\n# ============================================================================\n# Network Specific Options\n# ============================================================================\n\n\n# IP address to bind to when opening outgoing connections. Used by wget and\n# curl commands.\n#\n# (default: not specified)\n#out_addr = 0.0.0.0\n\n\n# Fake address displayed as the address of the incoming connection.\n# This doesn't affect logging, and is only used by honeypot commands such as\n# 'w' and 'last'\n#\n# If not specified, the actual IP address is displayed instead (default\n# behaviour).\n#\n# (default: not specified)\n#fake_addr = 192.168.66.254\n\n\n# The IP address on which this machine is reachable on from the internet.\n# Useful if you use portforwarding or other mechanisms. If empty, Cowrie\n# will determine by itself. Used in 'netstat' output\n#\n#internet_facing_ip = 9.9.9.9\n\n\n\n# ============================================================================\n# Authentication Specific Options\n# ============================================================================\n\n\n# Class that implements the checklogin() method.\n#\n# Class must be defined in cowrie/core/auth.py\n# Default is the 'UserDB' class which uses the password database.\n#\n# Alternatively the 'AuthRandom' class can be used, which will let\n# a user login after a random number of attempts.\n# It will also cache username/password combinations that allow login.\n#\nauth_class = UserDB\n\n# When AuthRandom is used also set the\n#  auth_class_parameters: <min try>, <max try>, <maxcache>\n#  for example: 2, 5, 10 = allows access after randint(2,5) attempts\n#  and cache 10 combinations.\n#\n#auth_class = AuthRandom\n#auth_class_parameters = 2, 5, 10\n\n\n[backend_pool]\n# ============================================================================\n# Backend Pool Configurations\n# only used on the cowrie instance that runs the pool\n# ============================================================================\n\n# enable this to solely run the pool, regardless of other configurations (disables SSH and Telnet)\npool_only = false\n\n# time between full VM recycling (cleans older VMs and boots newer ones) - involves some downtime between cycles\n# -1 to disable\nrecycle_period = 1500\n\n# change interface below to allow connections from outside (e.g. remote pool)\nlisten_endpoints = tcp:6415:interface=127.0.0.1\n\n# guest snapshots\nsave_snapshots = false\nsnapshot_path = $${honeypot:state_path}/snapshots\n\n# pool xml configs\nconfig_files_path = $${honeypot:share_path}/pool_configs\n\nnetwork_config = default_network.xml\nnw_filter_config = default_filter.xml\n\n# =====================================\n# Guest details (for a generic x86-64 guest, like Ubuntu)\n#\n# Used to provide configuration details to save snapshots, identify\n# running guests, and provide other details to Cowrie.\n#   - SSH and Telnet ports: which ports are listening for these services in the guest OS;\n#     if you're not using one of them omit the config or set to 0\n#   - Guest private key: used by the pool to control the guest's state via SSH; guest must\n#     have the corresponding pubkey in root's authorized_keys (not implemented)\n# =====================================\nguest_config = default_guest.xml\nguest_privkey = $${honeypot:state_path}/ubuntu18.04-guest\nguest_tag = ubuntu18.04\nguest_ssh_port = 22\nguest_telnet_port = 23\n\n# Configs below are used on default XMLs provided.\n# If you provide your own XML in guest_config you don't need these configs.\n#\n# Guest hypervisor can be qemu or kvm, for example. Recent hardware has KVM,\n# which is more performant than the qemu software-based emulation. Guest arch\n# must match your machine's. If it's older or you're unsure, set it to 'qemu'.\n#\n# Memory size is in MB.\n#\n# Advanced: guest_qemu_machine defines which machine Qemu emulates for your VM\n# If you get a \"unsupported machine type\" exception when VMs are loading, change\n# it to a compatible machine listed by the command: 'qemu-system-x86_64 -machine help'\nguest_image_path = /home/cowrie/cowrie-imgs/ubuntu18.04-minimal.qcow2\nguest_hypervisor = kvm\nguest_memory = 512\nguest_qemu_machine = pc-q35-bionic\n\n# =====================================\n# Guest details (for OpenWRT with ARM architecture)\n#\n# Used to provide configuration details to save snapshots, identify running guests,\n# and provide other details to Cowrie.\n# =====================================\n#guest_config = wrt_arm_guest.xml\n#guest_tag = wrt\n#guest_ssh_port = 22\n#guest_telnet_port = 23\n\n# Configs below are used on default XMLs provided.\n# If you provide your own XML in guest_config you don't need these configs.\n#\n# Guest hypervisor can be qemu or kvm, for example. Recent hardware has KVM,\n# which is more performant than the qemu software-based emulation. Guest arch\n# must match your machine's.\n#\n# Memory size is in MB.\n#\n# Advanced: guest_qemu_machine defines which machine Qemu emulates for your VM\n# If you get a \"unsupported machine type\" exception when VMs are loading, change\n# it to a compatible machine listed by the command: 'qemu-system-arm -machine help'\n#guest_image_path = /home/cowrie/cowrie-imgs/root.qcow2\n#guest_hypervisor = qemu\n#guest_memory = 256\n#guest_kernel_image = /home/cowrie/cowrie-imgs/zImage\n#guest_qemu_machine = virt-2.9\n\n# =====================================\n# Other configs\n# =====================================\n# Use NAT (for remote pool)\n#\n# Guests exist in a local interface created by libvirt; NAT functionality creates a port in the host,\n# exposed to a public interface, and forwards TCP data to and from the libvirt private interface.\n# Cowrie's proxy receives the public information instead of the local IP of guests.\nuse_nat = true\nnat_public_ip = 192.168.1.40\n\n\n# ============================================================================\n# Proxy Options\n# ============================================================================\n[proxy]\n\n# type of backend:\n#   - simple: backend machine deployed by you (CAREFUL WITH SECURITY ASPECTS!!), specify hosts and ports below\n#   - pool: cowrie-managed pool of virtual machines, configure below\nbackend = pool\n\n# =====================================\n# Simple Backend Configuration\n# =====================================\nbackend_ssh_host = localhost\nbackend_ssh_port = 2022\n\nbackend_telnet_host = localhost\nbackend_telnet_port = 2023\n\n# =====================================\n# Pool Backend Configuration\n# =====================================\n\n# generic pool configurable settings\npool_max_vms = 5\npool_vm_unused_timeout = 600\n\n# allow sharing guests between different attackers if no new VMs are available\npool_share_guests = true\n\n# Where to deploy the backend pool (only if backend = pool)\n#   - \"local\": same machine as the proxy\n#   - \"remote\": set host and port of the pool below\npool = local\n\n# Remote pool configurations (used with pool=remote)\npool_host = 192.168.1.40\npool_port = 6415\n\n# =====================================\n# Proxy Configurations\n# =====================================\n\n# real credentials to log into backend\nbackend_user = root\nbackend_pass = root\n\n# Telnet prompt detection\n#\n# To detect authentication prompts (and spoof auth details to the ones the backend accepts) we need to capture\n# login and password prompts, and spoof data to the backend in order to successfully authenticate. If disabled,\n# attackers can only use the real user credentials of the backend.\ntelnet_spoof_authentication = true\n\n# These regex were made using Ubuntu 18.04; you have to adapt these for the prompts\n# from your backend. You can enable raw logging above to analyse data passing through\n# and identify the format of the prompts you need.\n# You should generally include \".*\" at the beginning and end of prompts, since Telnet messages can contain\n# more data than the prompt.\n\n# For login it is usually <hostname> login:\ntelnet_username_prompt_regex = (\\n|^)ubuntu login: .*\n\n# Password prompt is usually only the word Password\ntelnet_password_prompt_regex = .*Password: .*\n\n# This data is sent by clients at the beginning of negotiation (before the password prompt), and contains the username\n# that is trying to log in. We replace that username with the one in \"backend_user\" to allow the chance of a successful\n# login after the first password prompt. We are only able to check if credentials are allowed after the password is\n# inserted. If they are, then a correct username was already sent and authentication succeeds; if not, we send a fake\n# password to force authentication to fail.\ntelnet_username_in_negotiation_regex = (.*\\xff\\xfa.*USER\\x01)(.*?)(\\xff.*)\n\n# Other configs #\n# log raw TCP packets in SSh and Telnet\nlog_raw = false\n\n\n# ============================================================================\n# Shell Options\n# Options around Cowrie's Shell Emulation\n# ============================================================================\n\n[shell]\n\n# File in the Python pickle format containing the virtual filesystem.\n#\n# This includes the filenames, paths, permissions for the Cowrie filesystem,\n# but not the file contents. This is created by the bin/createfs utility from\n# a real template linux installation.\n#\n# (default: fs.pickle)\nfilesystem = $${honeypot:share_path}/fs.pickle\n\n\n# File that contains output for the `ps` command.\n#\n# (default: share/cowrie/cmdoutput.json)\nprocesses = share/cowrie/cmdoutput.json\n\n\n# Fake architectures/OS\n# When Cowrie receive a command like /bin/cat XXXX (where XXXX is an executable)\n# it replies with the content of a dummy executable (located in data_path/arch)\n# compiled for an architecture/OS/endian_mode\n# arch can be a comma separated list. When there are multiple elements, a random\n# is chosen at login time.\n# (default: linux-x64-lsb)\n\narch = linux-x64-lsb\n\n# Here the list of supported OS-ARCH-ENDIANESS executables\n# bsd-aarch64-lsb:\t    64-bit\tLSB\tARM aarch64 version 1 (SYSV)\n# bsd-aarch64-msb:\t    64-bit\tMSB\tARM aarch64 version 1 (SYSV)\n# bsd-bfin-msb:\t\t    32-bit\tMSB\tAnalog Devices Blackfin\tversion\t1 (SYSV)\n# bsd-mips64-lsb:\t\t64-bit\tLSB\tMIPS MIPS-III version 1\t(SYSV)\n# bsd-mips64-msb:\t\t64-bit\tMSB\tMIPS MIPS-III version 1\t(SYSV)\n# bsd-mips-lsb:\t\t    32-bit\tLSB\tMIPS MIPS-I version 1 (FreeBSD)\n# bsd-mips-msb:\t\t    32-bit\tMSB\tMIPS MIPS-I version 1 (FreeBSD)\n# bsd-powepc64-lsb:\t    64-bit\tMSB\t64-bit PowerPC or cisco\t7500 version 1 (FreeBSD)\n# bsd-powepc-msb:\t\t32-bit\tMSB\tPowerPC\tor cisco 4500 version 1\t(FreeBSD)\n# bsd-riscv64-lsb:\t    64-bit\tLSB\tUCB RISC-V version 1 (SYSV)\n# bsd-sparc64-msb:\t    64-bit\tMSB\tSPARC V9 relaxed memory\tordering version 1 (FreeBSD)\n# bsd-sparc-msb:\t\t32-bit\tMSB\tSPARC version 1\t(SYSV) statically\n# bsd-x32-lsb:\t\t    32-bit\tLSB\tIntel 80386 version 1 (FreeBSD)\n# bsd-x64-lsb:\t\t    64-bit\tLSB\tx86-64 version 1 (FreeBSD)\n# linux-aarch64-lsb:\t64-bit\tLSB\tARM aarch64 version 1 (SYSV)\n# linux-aarch64-msb:\t64-bit\tMSB\tARM aarch64 version 1 (SYSV)\n# linux-alpha-lsb:\t    64-bit\tLSB\tAlpha (unofficial) version 1 (SYSV)\n# linux-am33-lsb:\t\t32-bit\tLSB\tMatsushita MN10300 version 1 (SYSV)\n# linux-arc-lsb:\t\t32-bit\tLSB\tARC Cores Tangent-A5 version 1 (SYSV)\n# linux-arc-msb:\t\t32-bit\tMSB\tARC Cores Tangent-A5 version 1 (SYSV)\n# linux-arm-lsb:\t\t32-bit\tLSB\tARM EABI5 version 1 (SYSV)\n# linux-arm-msb:\t\t32-bit\tMSB\tARM EABI5 version 1 (SYSV)\n# linux-avr32-lsb:\t    32-bit\tLSB\tAtmel AVR 8-bit\tversion 1 (SYSV)\n# linux-bfin-lsb:\t\t32-bit\tLSB\tAnalog Devices Blackfin version\t1 (SYSV)\n# linux-c6x-lsb:\t\t32-bit\tLSB\tTI TMS320C6000 DSP family version 1\n# linux-c6x-msb:\t\t32-bit\tMSB\tTI TMS320C6000 DSP family version 1\n# linux-cris-lsb:\t\t32-bit\tLSB\tAxis cris version 1 (SYSV)\n# linux-frv-msb:\t\t32-bit\tMSB\tCygnus FRV (unofficial) version\t1 (SYSV)\n# linux-h8300-msb:\t    32-bit\tMSB\tRenesas\tH8/300 version 1 (SYSV)\n# linux-hppa64-msb:\t    64-bit\tMSB\tPA-RISC\t02.00.00 (LP64) version\t1\n# linux-hppa-msb:\t\t32-bit\tMSB\tPA-RISC\t*unknown arch 0xf* version 1 (GNU/Linux)\n# linux-ia64-lsb:\t\t64-bit\tLSB\tIA-64 version 1\t(SYSV)\n# linux-m32r-msb:\t\t32-bit\tMSB\tRenesas\tM32R version 1 (SYSV)\n# linux-m68k-msb:\t\t32-bit\tMSB\tMotorola m68k 68020 version 1 (SYSV)\n# linux-microblaze-msb:\t32-bit\tMSB\tXilinx MicroBlaze 32-bit RISC version 1\t(SYSV)\n# linux-mips64-lsb:\t    64-bit\tLSB\tMIPS MIPS-III version 1\t(SYSV)\n# linux-mips64-msb:\t    64-bit\tMSB\tMIPS MIPS-III version 1\t(SYSV)\n# linux-mips-lsb:\t\t32-bit\tLSB\tMIPS MIPS-I version 1 (SYSV)\n# linux-mips-msb:\t\t32-bit\tMSB\tMIPS MIPS-I version 1 (SYSV)\n# linux-mn10300-lsb:\t32-bit\tLSB\tMatsushita MN10300 version 1 (SYSV)\n# linux-nios-lsb:\t\t32-bit\tLSB\tAltera Nios II version 1 (SYSV)\n# linux-nios-msb:\t\t32-bit\tMSB\tAltera Nios II version 1 (SYSV)\n# linux-powerpc64-lsb:\t64-bit\tLSB\t64-bit PowerPC or cisco\t7500 version 1 (SYSV)\n# linux-powerpc64-msb:\t64-bit\tMSB\t64-bit PowerPC or cisco\t7500 version 1 (SYSV)\n# linux-powerpc-lsb:\t32-bit\tLSB\tPowerPC\tor cisco 4500 version 1 (SYSV)\n# linux-powerpc-msb:\t32-bit\tMSB\tPowerPC\tor cisco 4500 version 1 (SYSV)\n# linux-riscv64-lsb:  \t64-bit\tLSB\tUCB RISC-V version 1 (SYSV)\n# linux-s390x-msb:    \t64-bit\tMSB\tIBM S/390 version 1 (SYSV)\n# linux-sh-lsb:\t    \t32-bit\tLSB\tRenesas\tSH version 1 (SYSV)\n# linux-sh-msb:\t    \t32-bit\tMSB\tRenesas\tSH version 1 (SYSV)\n# linux-sparc64-msb:  \t64-bit\tMSB\tSPARC V9 relaxed memory\tordering version 1 (SYSV)\n# linux-sparc-msb:    \t32-bit\tMSB\tSPARC version 1\t(SYSV)\n# linux-tilegx64-lsb:\t64-bit\tLSB\tTilera TILE-Gx version 1 (SYSV)\n# linux-tilegx64-msb: \t64-bit\tMSB\tTilera TILE-Gx version 1 (SYSV)\n# linux-tilegx-lsb:   \t32-bit\tLSB\tTilera TILE-Gx version 1 (SYSV)\n# linux-tilegx-msb:   \t32-bit\tMSB\tTilera TILE-Gx version 1 (SYSV)\n# linux-x64-lsb:\t    64-bit\tLSB\tx86-64 version 1 (SYSV)\n# linux-x86-lsb:\t    32-bit\tLSB\tIntel 80386 version 1 (SYSV)\n# linux-xtensa-msb:   \t32-bit\tMSB\tTensilica Xtensa version 1 (SYSV)\n# osx-x32-lsb:\t    \t32-bit\tLSB Intel 80386\n# osx-x64-lsb:\t    \t64-bit\tLSB\tx86-64\n\n# arch = bsd-aarch64-lsb, bsd-aarch64-msb, bsd-bfin-msb, bsd-mips-lsb, bsd-mips-msb, bsd-mips64-lsb, bsd-mips64-msb, bsd-powepc-msb, bsd-powepc64-lsb, bsd-riscv64-lsb, bsd-sparc-msb, bsd-sparc64-msb, bsd-x32-lsb, bsd-x64-lsb, linux-aarch64-lsb, linux-aarch64-msb, linux-alpha-lsb, linux-am33-lsb, linux-arc-lsb, linux-arc-msb, linux-arm-lsb, linux-arm-msb, linux-avr32-lsb, linux-bfin-lsb, linux-c6x-lsb, linux-c6x-msb, linux-cris-lsb, linux-frv-msb, linux-h8300-msb, linux-hppa-msb, linux-hppa64-msb, linux-ia64-lsb, linux-m32r-msb, linux-m68k-msb, linux-microblaze-msb, linux-mips-lsb, linux-mips-msb, linux-mips64-lsb, linux-mips64-msb, linux-mn10300-lsb, linux-nios-lsb, linux-nios-msb, linux-powerpc-lsb, linux-powerpc-msb, linux-powerpc64-lsb, linux-powerpc64-msb, linux-riscv64-lsb, linux-s390x-msb, linux-sh-lsb, linux-sh-msb, linux-sparc-msb, linux-sparc64-msb, linux-tilegx-lsb, linux-tilegx-msb, linux-tilegx64-lsb, linux-tilegx64-msb, linux-x64-lsb, linux-x86-lsb, linux-xtensa-msb, osx-x32-lsb, osx-x64-lsb\n\n# Modify the response of '/bin/uname'\n# Default (uname -a): Linux <hostname> <kernel_version> <kernel_build_string> <hardware_platform> <operating system>\nkernel_version = 3.2.0-4-amd64\nkernel_build_string = #1 SMP Debian 3.2.68-1+deb7u1\nhardware_platform = x86_64\noperating_system = GNU/Linux\n\n# SSH Version as printed by \"ssh -V\" in shell emulation\nssh_version = OpenSSH_7.9p1, OpenSSL 1.1.1a  20 Nov 2018\n\n\n# ============================================================================\n# SSH Specific Options\n# ============================================================================\n[ssh]\n\n# Enable SSH support\n# (default: true)\nenabled = true\n\n\n# Public and private SSH key files. If these don't exist, they are created\n# automatically.\nrsa_public_key = $${honeypot:state_path}/ssh_host_rsa_key.pub\nrsa_private_key = $${honeypot:state_path}/ssh_host_rsa_key\ndsa_public_key = $${honeypot:state_path}/ssh_host_dsa_key.pub\ndsa_private_key = $${honeypot:state_path}/ssh_host_dsa_key\necdsa_public_key = $${honeypot:state_path}/ssh_host_ecdsa_key.pub\necdsa_private_key = $${honeypot:state_path}/ssh_host_ecdsa_key\ned25519_public_key = $${honeypot:state_path}/ssh_host_ed25519_key.pub\ned25519_private_key = $${honeypot:state_path}/ssh_host_ed25519_key\n\n# Public keys supported are: ssh-rsa, ssh-dss, ecdsa-sha2-nistp256, ssh-ed25519\npublic_key_auth = ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519\n\n# SSH version string as present to the client.\n#\n# Version string MUST start with SSH-2.0- or SSH-1.99-\n#\n# Use these to disguise your honeypot from a simple SSH version scan\n# Examples:\n# SSH-2.0-OpenSSH_5.1p1 Debian-5\n# SSH-1.99-OpenSSH_4.3\n# SSH-1.99-OpenSSH_4.7\n# SSH-1.99-Sun_SSH_1.1\n# SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3.1\n# SSH-2.0-OpenSSH_4.3\n# SSH-2.0-OpenSSH_4.6\n# SSH-2.0-OpenSSH_5.1p1 Debian-5\n# SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901\n# SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5\n# SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6\n# SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7\n# SSH-2.0-OpenSSH_5.5p1 Debian-6\n# SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze1\n# SSH-2.0-OpenSSH_5.5p1 Debian-6+squeeze2\n# SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503\n# SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1\n# SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\n# SSH-2.0-OpenSSH_5.9\n#\n# (default: \"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\")\nversion = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\n\n# Cipher encryption algorithms to be used.\n#\n# MUST be supplied as a comma-separated string without\n# any spaces or newlines.\n#\n# Use ciphers to limit to more secure algorithms only\n# any spaces.\n# Supported ciphers:\n#\n# aes128-ctr\n# aes192-ctr\n# aes256-ctr\n# aes256-cbc\n# aes192-cbc\n# aes128-cbc\n# 3des-cbc\n# blowfish-cbc\n# cast128-cbc\nciphers = aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc\n\n\n# MAC Algorithm to be used.\n#\n# MUST be supplied as a comma-separated string without\n# any spaces or newlines.\n#\n# hmac-sha1 and hmac-md5 are considered insecure now, and\n# instead MACs with higher number of bits should be used.\n#\n# Supported HMACs:\n# hmac-sha2-512\n# hmac-sha2-384\n# hmac-sha2-256\n# hmac-sha1\n# hmac-md5\nmacs = hmac-sha2-512,hmac-sha2-384,hmac-sha2-56,hmac-sha1,hmac-md5\n\n\n# Compression Method to be used.\n#\n# MUST be supplied as a comma-separated string without\n# any spaces or newlines.\n#\n# Supported Compression Methods:\n# zlib@openssh.com\n# zlib\n# none\ncompression = zlib@openssh.com,zlib,none\n\n# Endpoint to listen on for incoming SSH connections.\n# See https://twistedmatrix.com/documents/current/core/howto/endpoints.html#servers\n# (default: listen_endpoints = tcp:2222:interface=0.0.0.0)\n# (use systemd: endpoint for systemd activation)\n# listen_endpoints = systemd:domain=INET:index=0\n# For both IPv4 and IPv6: listen_endpoints = tcp6:2222:interface=\\:\\:\n# Listening on multiple endpoints is supported with a single space seperator\n# e.g listen_endpoints = \"tcp:2222:interface=0.0.0.0 tcp:1022:interface=0.0.0.0\" will result listening both on ports 2222 and 1022\n# use authbind for port numbers under 1024\n\nlisten_endpoints = tcp:2222:interface=0.0.0.0\n\n# Enable the SFTP subsystem\n# (default: true)\nsftp_enabled = true\n\n\n# Enable SSH direct-tcpip forwarding\n# (default: true)\nforwarding = true\n\n\n# This enables redirecting forwarding requests to another address\n# Useful for forwarding protocols to other honeypots\n# (default: false)\nforward_redirect = false\n\n\n# Configure where to forward the data to.\n# forward_redirect_<portnumber> = <redirect ip>:<redirect port>\n\n# Redirect http/https\n# forward_redirect_80 = 127.0.0.1:8000\n# forward_redirect_443 = 127.0.0.1:8443\n\n# To record SMTP traffic, install an SMTP honeypoint.\n# (e.g https://github.com/awhitehatter/mailoney), run\n# python mailoney.py -s yahoo.com -t schizo_open_relay -p 12525\n# forward_redirect_25 = 127.0.0.1:12525\n# forward_redirect_587 = 127.0.0.1:12525\n\n\n# This enables tunneling forwarding requests to another address\n# Useful for forwarding protocols to a proxy like Squid\n# (default: false)\nforward_tunnel = false\n\n\n# Configure where to tunnel the data to.\n# forward_tunnel_<portnumber> = <tunnel ip>:<tunnel port>\n\n# Tunnel http/https\n# forward_tunnel_80 = 127.0.0.1:3128\n# forward_tunnel_443 = 127.0.0.1:3128\n\n\n# No authentication checking at all\n# enabling 'auth_none' will enable the ssh2 'auth_none' authentication method\n# this allows the requested user in without any verification at all\n#\n# (default: false)\n#auth_none_enabled = false\n\n\n# Configure keyboard-interactive login\nauth_keyboard_interactive_enabled = false\n\n# ============================================================================\n# Telnet Specific Options\n# ============================================================================\n[telnet]\n\n# Enable Telnet support, disabled by default\nenabled = true\n\n# Endpoint to listen on for incoming Telnet connections.\n# See https://twistedmatrix.com/documents/current/core/howto/endpoints.html#servers\n# (default: listen_endpoints = tcp:2223:interface=0.0.0.0)\n# (use systemd: endpoint for systemd activation)\n# listen_endpoints = systemd:domain=INET:index=0\n# For IPv4 and IPv6: listen_endpoints = tcp6:2223:interface=\\:\\: tcp:2223:interface=0.0.0.0\n# Listening on multiple endpoints is supported with a single space seperator\n# e.g \"listen_endpoints = tcp:2223:interface=0.0.0.0 tcp:2323:interface=0.0.0.0\" will result listening both on ports 2223 and 2323\n# use authbind for port numbers under 1024\n\nlisten_endpoints = tcp:2223:interface=0.0.0.0\n\n\n# Source Port to report in logs (useful if you use iptables to forward ports to Cowrie)\nreported_port = 23\n\n\n\n# ============================================================================\n# Database logging Specific Options\n# ============================================================================\n\n# XMPP Logging\n# Log to an xmpp server.\n#\n#[database_xmpp]\n#server = sensors.carnivore.it\n#user = anonymous@sensors.carnivore.it\n#password = anonymous\n#muc = dionaea.sensors.carnivore.it\n#signal_createsession = cowrie-events\n#signal_connectionlost = cowrie-events\n#signal_loginfailed = cowrie-events\n#signal_loginsucceeded = cowrie-events\n#signal_command = cowrie-events\n#signal_clientversion = cowrie-events\n#debug=true\n\n\n\n\n# ============================================================================\n# Output Plugins\n# These provide an extensible mechanism to send audit log entries to third\n# parties. The audit entries contain information on clients connecting to\n# the honeypot.\n#\n# Output entries need to start with 'output_' and have the 'enabled' entry.\n# ============================================================================\n\n[output_xmpp]\nenabled=false\nserver = conference.cowrie.local\nuser = cowrie@cowrie.local\npassword = cowrie\nmuc = hacker_room\n\n# JSON based logging module\n#\n[output_jsonlog]\nenabled = true\nlogfile = $${honeypot:log_path}/cowrie.json\nepoch_timestamp = false\n\n# Supports logging to Elasticsearch\n# This is a simple early release\n#\n[output_elasticsearch]\nenabled = false\nhost = localhost\nport = 9200\nindex = cowrie\n# type has been deprecated since ES 6.0.0\n# use _doc which is the default type. See\n# https://stackoverflow.com/a/53688626 for\n# more information\n#type = _doc\n# set pipeline = geoip to map src_ip to\n# geo location data. You can use a custom\n# pipeline but you must ensure it exists\n# in elasticsearch.\n#pipeline = geoip\n#\n# Authentication. When x-pack.security is enabled\n# in ES, default users have been created and requests\n# must be authenticated.\n#\n# Credentials\n#username = elastic\n#password =\n#\n# TLS encryption. Communications between the client (cowrie)\n# and the ES server should naturally be protected by encryption\n# if requests are authenticated (to prevent from man-in-the-middle\n# attacks). The following options are then paramount\n# if username and password are provided.\n#\n# use ssl/tls\n#ssl = true\n# Path to trusted CA certs on disk\n#ca_certs = /cowrie/cowrie-git/etc/elastic_ca.crt\n# verify SSL certificates\n#verify_certs = true\n\n# Send login attemp information to SANS DShield\n# See https://isc.sans.edu/ssh.html\n# You must signup for an api key.\n# Once registered, find your details at: https://isc.sans.edu/myaccount.html\n#\n[output_dshield]\nenabled = false\nuserid = userid_here\nauth_key = auth_key_here\nbatch_size = 100\n#\n# Graylog logging module for GELF http input\n[output_graylog]\nenabled = false\nurl = http://graylog.example.com:122011/gelf\n#\n# Local Syslog output module\n#\n# This sends log messages to the local syslog daemon.\n# Facility can be:\n# KERN, USER, MAIL, DAEMON, AUTH, LPR, NEWS, UUCP, CRON, SYSLOG and LOCAL0 to LOCAL7.\n#\n# Format can be:\n# text, cef\n#\n[output_localsyslog]\nenabled = false\nfacility = USER\nformat = text\n\n\n# Text output\n# This writes audit log entries to a text file\n#\n# Format can be:\n# text, cef\n#\n[output_textlog]\nenabled = false\nlogfile = $${honeypot:log_path}/audit.log\nformat = text\n\n\n# MySQL logging module\n# Database structure for this module is supplied in docs/sql/mysql.sql\n#\n# MySQL logging requires extra software: sudo apt-get install libmysqlclient-dev\n# MySQL logging requires an extra Python module: pip install mysql-python\n#\n[output_mysql]\nenabled = false\nhost = localhost\ndatabase = cowrie\nusername = cowrie\npassword = secret\nport = 3306\ndebug = false\n\n# Rethinkdb output module\n# Rethinkdb output module requires extra Python module: pip install rethinkdb\n\n[output_rethinkdblog]\nenabled = false\nhost = 127.0.0.1\nport = 28015\ntable = output\npassword =\ndb = cowrie\n\n# SQLite3 logging module\n#\n# Logging to SQLite3 database. To init the database, use the script\n# docs/sql/sqlite3.sql:\n#     sqlite3 <db_file> < docs/sql/sqlite3.sql\n#\n[output_sqlite]\nenabled = false\ndb_file = cowrie.db\n\n# MongoDB logging module\n#\n# MongoDB logging requires an extra Python module: pip install pymongo\n#\n[output_mongodb]\nenabled = false\nconnection_string = mongodb://username:password@host:port/database\ndatabase = dbname\n\n\n# Splunk HTTP Event Collector (HEC) output module\n# sends JSON directly to Splunk over HTTP or HTTPS\n# Use 'https' if your HEC is encrypted, else 'http'\n# mandatory fields: url, token\n# optional fields: index, source, sourcetype, host\n#\n[output_splunk]\nenabled = false\nurl = https://localhost:8088/services/collector/event\ntoken = 6A0EA6C6-8006-4E39-FC44-C35FF6E561A8\nindex = cowrie\nsourcetype = cowrie\nsource = cowrie\n\n\n# HPFeeds3\n# Python3 implementation of HPFeeds\n[output_hpfeeds3]\nenabled = false\nserver = hpfeeds.mysite.org\nport = 10000\nidentifier = abc123\nsecret = secret\ndebug=false\n\n\n# VirusTotal output module\n# You must signup for an api key.\n#\n[output_virustotal]\nenabled = false\napi_key = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nupload = True\ndebug = False\nscan_file = True\nscan_url = False\n\n\n# Cuckoo output module\n[output_cuckoo]\nenabled = false\n# no slash at the end\nurl_base = http://127.0.0.1:8090\nuser = user\npasswd = passwd\n# force will upload duplicated files to cuckoo\nforce = 0\n\n# upload to MalShare\n# Register at https://malshare.com/register.php to get your API key\n[output_malshare]\napi_key = 130928309823098\nenabled = false\n\n# This will produce a _lot_ of messages - you have been warned....\n[output_slack]\nenabled = false\nchannel = channel_that_events_should_be_posted_in\ntoken = slack_token_for_your_bot\ndebug = false\n\n\n# https://csirtg.io\n# You must signup for an api key.\n#\n[output_csirtg]\nenabled = false\nusername = wes\nfeed = scanners\ndescription = random scanning activity\ntoken = a1b2c3d4\ndebug = false\n\n\n[output_socketlog]\nenabled = false\naddress = 127.0.0.1:9000\ntimeout = 5\n\n# Upload files that cowrie has captured to an S3 (or compatible bucket)\n# Files are stored with a name that is the SHA of their contents\n#\n[output_s3]\nenabled = false\n#\n# The AWS credentials to use.\n# Leave these blank to use botocore's credential discovery e.g .aws/config or ENV variables.\n# As per https://github.com/boto/botocore/blob/develop/botocore/credentials.py#L50-L65\naccess_key_id = AKIDEXAMPLE\nsecret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY\n#\n# The bucket to store the files in. The bucket must already exist.\nbucket = my-cowrie-bucket\n#\n# The region the bucket is in\nregion = eu-west-1\n#\n# An alternate endpoint URL. If you self host a pithos instance you can set\n# this to its URL (e.g. https://s3.mydomain.com) - can otherwise be blank\n#endpoint =\n#\n# Whether or not to validate the S3 certificate. Set this to 'no' to turn this\n# off. Do not do this for real AWS. It's only needed for self-hosted S3 clone\n# where you don't yet have real certificates.\n#verify = no\n\n[output_influx]\nenabled = false\nhost = 127.0.0.1\nport = 8086\ndatabase_name = cowrie\nretention_policy_duration = 12w\n\n[output_kafka]\nenabled = false\nhost = 127.0.0.1\nport = 9092\ntopic = cowrie\n\n\n[output_redis]\nenabled = false\nhost = 127.0.0.1\nport = 6379\n# DB of the redis server. Defaults to 0\ndb = 0\n# Password of the redis server. Defaults to None\n# password = secret\n# Name of the list to push to or the channel to publish to. Required\nkeyname = cowrie\n# Method to use when sending data to redis.\n# Can be one of [lpush, rpush, publish]. Defaults to lpush\nsend_method = lpush\n\n\n# Perform Reverse DNS lookup\n[output_reversedns]\nenabled = false\n# Timeout in seconds\ntimeout = 3\n\n[output_greynoise]\nenabled = false\ndebug = false\n# Name of the tags separated by comma, for which the IP has to be scanned for.\n# Example \"SHODAN,JBOSS_WORM,CPANEL_SCANNER_LOW\"\n# If there isn't any specific tag then just leave it \"all\"\ntags = all\n# It's optional to have API key, so if you don't want to but\n# API key then leave this option commented\n#api_key = 1234567890\n\n# Upload all files to a MISP instance of your liking.\n# The API key can be found under Event Actions -> Automation\n[output_misp]\nenabled = false\nbase_url = https://misp.somedomain.com\napi_key = secret_key\nverify_cert = true\npublish_event = true\ndebug = false\n\n# Send message using Telegram bot\n# 1. Create a bot following https://core.telegram.org/bots#6-botfather to get token.\n# 2. Send message to your bot, then use https://api.telegram.org/bot{bot_token}/getUpdates to find chat_id.\n# N.b. bot will only send messages on cowrie.login.success, cowrie.command.input/.failed, and\n# cowrie.session.file_download, to prevent spam.\n[output_telegram]\nenabled = false\nbot_token = 123456789:AbCDEfGhiJkLmnOpQRstUVWxYZ\nchat_id = 987654321\n\n# The crashreporter sends data on Python exceptions to api.cowrie.org\n# To disable set `enabled = false` in cowrie.cfg\n[output_crashreporter]\nenabled = false\ndebug = false\n\n# Reports login attempts to AbuseIPDB. A short guide is in the original\n# pull request on GitHub: https://github.com/cowrie/cowrie/pull/1346\n[output_abuseipdb]\nenabled = false\n#api_key =\n#rereport_after = 24\n#tolerance_window is in minutes\n#tolerance_window = 120\n#tolerance_attempts = 10\n# WARNING: A binary file is read from this directory on start-up. Do not\n# change unless you understand the security implications!\n#dump_path = $${honeypot:state_path}/abuseipdb\n\n# Report login and session tracking attempts via the ThreatJammer.com Report API.\n# ThreatJammer.com is a risk assessment tool <https://threatjammer.com>\n# Read the docs for more information: https://cowrie.readthedocs.io/en/latest/threatjammer/README.html\n[output_threatjammer]\nenabled = false\nbearer_token = THREATJAMMER_API_TOKEN\n#api_url=https://dublin.report.threatjammer.com/v1/ip\n#track_login = true\n#track_session = false\n#ttl = 86400\n#category = ABUSE\n#tags = COWRIE,LOGIN,SESSION\n\n# Send output to a Discord webhook\n[output_discord]\nenabled = false\nurl = https://discord.com/api/webhooks/id/token\n"
  }
}

resource "kubernetes_service" "cowrie" {
  depends_on = [module.skg]
  metadata {
    name = "cowrie"

    labels = {
      honeypot = "cowrie"
    }
  }

  spec {
    port {
      name        = "22"
      port        = 2222
      target_port = "2222"
      node_port   = 32222
    }

    port {
      name        = "23"
      port        = 2223
      target_port = "2223"
      node_port   = 32223
    }

    selector = {
      honeypot = "cowrie"
    }

    type = "NodePort"
  }
}
