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
      'Name'        => 'ManageEngine Exchange Reporter Plus Scanner',
      'Description' => %q{
This module scans for instances of ManageEngine Exchange Reporter Plus on the network.

ManageEngine Exchange Reporter Plus is a popular enterprise solution for managing and
auditing environments using Exchange for email. Privileged
access to an Exchange Reporter Plus instance could yield significant insight into credentials
on the network and other sensitive information. This module exploits an unauthenticated remote code execution
vulnerability in order to gain a remote shell on the host.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/yKj1NyDhbpgM9Xbwr0QWTjapz

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [ Opt::RPORT(8181),
        OptString.new('TARGETURI', [ true,  "The test path to find Exchange Reporter Plus", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['TARGETURI']  + '/exchange/Home.do',
    })

    if res && res.body =~ /<title>ManageEngine - Exchange Reporter Plus<\/title>/
      print_good("#{peer} - Found ManageEngine Exchange Reporter Plus")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'ManageEngine Exchange Reporter Plus',
        info: 'ManageEngine Exchange Reporter Plus',
      })
    end
  end


end
