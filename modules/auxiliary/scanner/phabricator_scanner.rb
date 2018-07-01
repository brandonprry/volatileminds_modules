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
      'Name'        => 'Phabricator Scanner',
      'Description' => %q{
This module scans for instances of Phabricator on the network.

Phabricator enables software development collaboration with features
such as code review or change control. It is a popular solution for
open source or enterprise users. Privileged access to Phabricator
could yield significant insight into high-value targets, source code
access, or business processes.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/9GeXcjHhA50mr9CqsTULN59eZ

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The URI to test", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['TARGETURI'],
    })

    if res and res.body =~ /<div class="phabricator-main-menu phabricator-main-menu-background"/
      print_good("#{peer} - Found Phabricator")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Phabricator',
        info: 'Phabricator'
      })
    end
  end
end
