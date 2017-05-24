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
      'Name'        => 'SonicWall Universal Management Application Scanner',
      'Description' => %q{
This module scans for SonicWall Universal Management Application instances.

SonicWall Universal Management Application (UMA) is a popular enterprise
solution for managing SonicWall appliances on the network. Access to a
UMA instance may yield significant insight into the network perimeter
and high value targets on the network.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/4zqlpvhl6jzbkte7zylsrufnl

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find the application", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + '/appliance/applianceMainPage',
    })

    if res && res.code == 200 && res.body =~ /SonicWALL UMA Version(.*?)<\/td>/m
      print_good("#{peer} - Found SonicWALL UMA Version #{$1.strip}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'SonicWALL UMA',
        info: 'SonicWALL UMA Version ' + $1
      })
    end
  end
end
