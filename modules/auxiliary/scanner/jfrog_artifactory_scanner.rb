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
      'Name'        => 'JFrog Artifactory Scanner',
      'Description' => %q{
This module attempts to bruteforce weak credentials on JFrog Artifactory instances.

The JFrog Artifactory repository manager allows developers to manage dependencies and
other binary data for easy distribution. Privileged access to a JFrog Artifactory instance
could allow remote code execution on any machine relying on dependencies through the system.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/OmkwTvHBEkNYx0bQ7JEh7XahM

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The URI to test", '/artifactory/'])
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + 'ui/auth/current',
    })

    if res.code == 200 and res.headers['Server'] =~ /Artifactory\/(.*)/
      print_good("#{peer} - Found JFrog Artifactory " + $1)
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'JFrog Artifactory',
        info: 'JFrog Artifactory ' + $1
      })
    end
  end
end
