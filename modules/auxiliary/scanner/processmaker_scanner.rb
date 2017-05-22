##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'ProcessMaker Scanner',
      'Description' => %q{
This module attempts to find ProcessMaker instances on the network.

ProcessMaker is a popular open source and enterprise solution for
managing defined business processes and workflows. Privileged access
to a ProcessMaker instance may yield significant insight into
how a business works, key stakeholders, and high value targets.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/2drpjphgq6p07xwofqpka53ea

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'], '/sysworkflow/en/neoclassic/login/login'),
    })

    if res && res.body =~ /Powered by ProcessMaker/i
      print_good("#{peer} - Found ProcessMaker")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'ProcessMaker',
        info: 'ProcessMaker Business Process Management suite'
      })
    end
  end
end
