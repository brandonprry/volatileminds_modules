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
      'Name'        => 'OpenText iHub Scanner',
      'Description' => %q{
This module scans for instances of OpenText iHub on the network.

OpenText iHub is an enterprise-grade document management system.
Authenticated or privileged access to an iHub instance could
yield great insight into high-value targets or other
sensitive information such as network credentials.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/f8V0nY0k7rNfsrThStVypFZNQ

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(8700),
        OptString.new('PATH', [ true,  "The test path to find OpenText iHub", '/iportal/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + 'login.do',
    })

    if res and res.body =~ /iHub&nbsp;-&nbsp;\[Login&nbsp;screen\]/
      print_good("#{peer} - Found OpenText iHub")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'OpenText iHub',
        info: 'OpenText iHub'
      })
    end
  end
end
