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
      'Name'        => 'ManageEngine Applications Manager Scanner',
      'Description' => %q{
This module scans for instances of ManageEngine Applications Manager on the network.

ManageEngine Applications Manager is an enterprise solution for managing and monitoring a diverse
set of other enterprise solutions ranging from databases to web servers. Privileged access
could yield significant insight into high value targets on the network.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/FESImeHr8eWKD7TrXoVNUQWRE

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(9090),
        OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'MyPage.do?method=viewDashBoard&toredirect=true')
    })

    if res && res.body =~ /<title>Applications Manager Login Screen<\/title>/
      ver = $1 if res.body =~ /;color:#666">(.*?) &/
      print_good("#{peer} - Found ManageEngine #{ver}")

      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'ManageEngine ' + ver,
        info: 'ManageEngine ' + ver
      })
    end
  end
end
