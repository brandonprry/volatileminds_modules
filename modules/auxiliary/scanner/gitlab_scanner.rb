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
      'Name'        => 'GitLab Scanner',
      'Description' => %q{
This module scans a network range for GitLab instances.

GitLab is a popular open-source version management system,
with similar features to GitHub. Access to a version control
system often leads to sensitive information or credentials.
This was tested against 9.0.5.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/1i106t8uj054ht84rwnd4uegd

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds',
      'DefaultOptions' => {
        'RPORT'           => 443,
        'SSL' => true,
       }

    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The URI to look for GitLab at", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'], '/users/sign_in')
    })

    if res and res.body =~ /<title>Sign in \xC2\xB7 GitLab<\/title>/
      print_good("#{peer} - GitLab found")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'GitLab',
        info: 'GitLab version management system'
      })
    end
  end
end
