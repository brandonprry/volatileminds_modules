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
      'Name'        => 'SuiteCRM Scanner',
      'Description' => %q{
This module scans for instances of SuiteCRM on the network.

SuiteCRM is a popular fork of the last open source version
of SugarCRM. Authenticated access to a SuiteCRM instance
may yield signifcant insight into business processes and
potential high value targets.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/Ln4GIyVsoCu4kZyjrQR2yiA5q

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find SuiteCRM", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + '/index.php?action=Login&module=Users'
    })

    if res && res.body =~ /Supercharged by SuiteCRM/
      print_good("#{peer} - Found SuiteCRM")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'SuiteCRM',
        info: 'SuiteCRM'
      })
    end

  end
end
