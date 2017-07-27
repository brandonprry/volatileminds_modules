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
      'Name'        => 'SugarCRM Scanner',
      'Description' => %q{
This module scans for SugarCRM instances.

SugarCRM is a popular open-source enterprise-grade CRM. This module attempts to find SugarCRM instances
on the network. Tested against 6.5.25.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/2eiw3g090zzb6w8mtrod16fuq

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The URI to test for SugarCRM after.", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'], 'index.php?action=Login&module=Users')
    })

    if res and res.body =~ /SugarCRM, Inc. Copyright \(C\)/
      print_good("#{peer} - Found SugarCRM")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'SugarCRM',
        info: 'SugarCRM instance'
      })
    end
  end
end
