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
      'Name'        => 'CanvasLMS Scanner',
      'Description' => %q{
This module scans for instances of CanvasLMS.

CanvasLMS is a popular open-source learning management system (LMS)
used by schools around the world. Privileged access may yield
greater insight into an organization or other sensitive information.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/Z8dkAIi02xW8qUxqCLcahYEz5

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find CanvasLMS", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + '/login/canvas'
    })

    if res && res.body =~ /<title>Log In to Canvas<\/title>/
      print_good("#{peer} - Found CanvasLMS")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'CanvasLMS',
        info: 'An instance of CanvasLMS'
      })
    end
  end
end
