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
      'Name'        => 'Foreman Scanner',
      'Description' => %q{
This module scans for instances of Foreman, an open-source provisioning application.

        Foreman is a popular open-source enterprise solution for managing and provisioning assets on a network.
        Privileged access to a Foreman instance could yield significant insight and power over a network or
        access to vulnerabilities deeper in Foreman available only to authenticated users.


Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/MkVVLA0tVDLJRSWJYMn7nwRPC

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds',
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true
      }
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The test path to find Foreman", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'users', 'login')
    })

    if res && res.body =~ /<strong>Welcome to Foreman<\/strong>/
      version = $1 if res.body =~ /<p id="version">(.*?)<\/p>/

      print_good("#{peer} - Found Foreman " + (version ? version : ''))
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Foreman',
        info: 'Foreman ' + (version ? version : '')
      })
    end
  end
end
