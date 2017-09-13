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
      'Name'        => 'osTicket Scanner',
      'Description' => %q{
This module scans for instances of osTicket on a network.

osTicket is a popular open-source ticket management system
written in PHP. Privileged access to an osTicket instance
could yield great insight into high values targets in
the company or other sensitive information.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/jYsZMgmWvBdP9YxcDlKW2a6Hv

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find osTicket", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + '/index.php',
    })

    if res and res.body =~ /osTicket, Customer support system/
      print_good("#{peer} - Found osTicket")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'osTicket',
        info: 'osTicket instance'
      })
    end

  end
end
