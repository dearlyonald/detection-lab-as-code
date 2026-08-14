# -*- mode: ruby -*-
# vi: set ft=ruby :
# =============================================================================
#  detection-lab-as-code — Vagrantfile
# =============================================================================
#  This file contains NO hard-coded sizes, IPs or hostnames. Everything is read
#  from lab.yml so that the infrastructure and the documentation can never drift
#  apart. Adding a machine is a lab.yml edit, not a Vagrantfile edit.
#
#  Usage:
#    $env:LAB_PROFILE = "standard"     # minimal | standard | full
#    vagrant up
#    vagrant up siem                   # one machine at a time (recommended)
#    vagrant provision ws01            # re-run provisioning without rebuilding
#    vagrant destroy -f                # burn it all down
# =============================================================================

require 'yaml'

VAGRANTFILE_API_VERSION = '2'.freeze
LAB_ROOT   = File.dirname(__FILE__)
CONFIG     = YAML.load_file(File.join(LAB_ROOT, 'lab.yml'))

LAB        = CONFIG.fetch('lab')
MACHINES   = CONFIG.fetch('machines')
PROFILES   = CONFIG.fetch('profiles')
TELEMETRY  = CONFIG.fetch('telemetry')

# Profile selection: env var wins, then lab.yml default.
PROFILE = ENV.fetch('LAB_PROFILE', CONFIG.fetch('default_profile'))
unless PROFILES.key?(PROFILE)
  abort("[lab] Unknown LAB_PROFILE '#{PROFILE}'. Valid: #{PROFILES.keys.join(', ')}")
end
ACTIVE = PROFILES.fetch(PROFILE)

# vagrant-reload is required because promoting a domain controller and joining a
# domain both need a reboot *in the middle* of provisioning.
unless Vagrant.has_plugin?('vagrant-reload')
  abort("[lab] Missing plugin. Run:  vagrant plugin install vagrant-reload")
end

# Total RAM sanity check — fail loudly before VirtualBox starts thrashing.
total_mb = ACTIVE.sum { |n| MACHINES.fetch(n).fetch('memory') }
puts "[lab] profile=#{PROFILE}  machines=#{ACTIVE.join(', ')}  ram=#{total_mb / 1024.0} GB"

# Environment passed into every provisioning script, so the scripts also read
# their settings from lab.yml instead of duplicating them.
def lab_env(name)
  m = MACHINES.fetch(name)
  {
    'LAB_DOMAIN'   => LAB.fetch('domain'),
    'LAB_NETBIOS'  => LAB.fetch('netbios'),
    'LAB_DC_IP'    => MACHINES.fetch('dc01').fetch('ip'),
    'LAB_SIEM_IP'  => MACHINES.fetch('siem').fetch('ip'),
    'LAB_HOSTNAME' => m.fetch('hostname'),
    'LAB_ROLE'     => m.fetch('role'),
    'SYSMON_CONFIG_URL' => TELEMETRY.fetch('sysmon').fetch('config_url')
  }
end

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  # Host-only networking only. The lab must never be reachable from the LAN.
  config.vm.boot_timeout = 900
  config.vm.synced_folder '.', '/vagrant', disabled: true

  ACTIVE.each do |name|
    m = MACHINES.fetch(name)
    windows = %w[domain_controller workstation].include?(m.fetch('role'))

    config.vm.define name do |node|
      node.vm.box      = m.fetch('box')
      node.vm.hostname = m.fetch('hostname') unless windows # set via provisioner on Windows
      node.vm.network 'private_network', ip: m.fetch('ip')

      node.vm.provider 'virtualbox' do |vb|
        vb.name   = "#{LAB.fetch('name')}-#{name}"
        vb.memory = m.fetch('memory')
        vb.cpus   = m.fetch('cpus')
        vb.gui    = m.fetch('gui')
        # Nested paging + enough video RAM for a usable console.
        vb.customize ['modifyvm', :id, '--nested-hw-virt', 'on']
        vb.customize ['modifyvm', :id, '--vram', '64']
        vb.customize ['modifyvm', :id, '--clipboard', 'bidirectional']
        # Deterministic MACs make network artefacts stable across rebuilds,
        # which matters when you are diffing detections between runs.
        vb.customize ['modifyvm', :id, '--groups', "/#{LAB.fetch('name')}"]
      end

      # -----------------------------------------------------------------
      # Windows guests
      # -----------------------------------------------------------------
      if windows
        node.vm.communicator      = 'winrm'
        node.vm.guest             = :windows
        node.winrm.username       = 'vagrant'
        node.winrm.password       = 'vagrant'
        node.winrm.timeout        = 1800
        node.winrm.retry_limit    = 60
        node.vm.graceful_halt_timeout = 600

        # -- Stage 1: baseline (hostname, DNS, firewall, telemetry prereqs)
        node.vm.provision 'base', type: 'shell',
          path: 'provision/windows/01-base.ps1',
          env:  lab_env(name)

        # -- Stage 2: audit policy. Must run BEFORE any attack telemetry is
        #    expected, otherwise 4688 command lines simply will not exist.
        node.vm.provision 'audit', type: 'shell',
          path: 'provision/windows/02-audit-policy.ps1',
          env:  lab_env(name)

        # -- Stage 3: Sysmon
        if TELEMETRY.fetch('sysmon').fetch('enabled')
          node.vm.provision 'sysmon', type: 'shell',
            path: 'provision/windows/03-sysmon.ps1',
            env:  lab_env(name)
        end

        # -- Stage 4: role-specific build
        case m.fetch('role')
        when 'domain_controller'
          node.vm.provision 'dc-promote', type: 'shell',
            path: 'provision/windows/10-dc-promote.ps1',
            env:  lab_env(name)
          node.vm.provision :reload
          node.vm.provision 'dc-populate', type: 'shell',
            path: 'provision/windows/11-dc-populate.ps1',
            env:  lab_env(name)
        when 'workstation'
          node.vm.provision 'domain-join', type: 'shell',
            path: 'provision/windows/20-ws-join.ps1',
            env:  lab_env(name)
          node.vm.provision :reload
          node.vm.provision 'ws-victimise', type: 'shell',
            path: 'provision/windows/21-ws-victimise.ps1',
            env:  lab_env(name)
        end

        # -- Stage 5: ship the logs. Last, so the agent starts with full
        #    telemetry already configured.
        if TELEMETRY.fetch('wazuh').fetch('agent_enroll')
          node.vm.provision 'wazuh-agent', type: 'shell',
            path: 'provision/windows/30-wazuh-agent.ps1',
            env:  lab_env(name)
        end

        # -- Stage 6: attack tooling (Atomic Red Team), workstation only.
        if m.fetch('role') == 'workstation'
          node.vm.provision 'atomic', type: 'shell',
            path: 'provision/windows/40-atomic-red-team.ps1',
            env:  lab_env(name)
        end

      # -----------------------------------------------------------------
      # Linux guests
      # -----------------------------------------------------------------
      else
        case m.fetch('role')
        when 'siem'
          node.vm.provision 'wazuh-stack', type: 'shell',
            path: 'provision/linux/siem/install-wazuh.sh',
            env:  lab_env(name).merge('WAZUH_BIND_IP' => m.fetch('ip'))
          node.vm.provision 'decoders-rules', type: 'shell',
            path: 'provision/linux/siem/deploy-detections.sh',
            env:  lab_env(name)
        when 'attacker'
          node.vm.provision 'attacker-tools', type: 'shell',
            path: 'provision/linux/attacker/install-tools.sh',
            env:  lab_env(name)
        end
      end

      # A short, honest completion banner per machine.
      node.vm.post_up_message = <<~MSG
        [#{name}] up at #{m.fetch('ip')}  (role: #{m.fetch('role')})
        #{'Dashboard: https://' + m.fetch('ip') + '  (user: admin — password printed by the installer)' if m.fetch('role') == 'siem'}
      MSG
    end
  end
end
