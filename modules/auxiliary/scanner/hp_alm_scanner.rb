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
      'Name'        => 'HP Application Lifecycle Management Scanner',
      'Description' => %q{
This module scans for instances of HP Application Lifecycle Management.

The HP Application Lifecycle Management software suite is a popular enterprise
solution for managing application and software development lifecycles. Credentialed
access may give an attacker access to sensitive information such as network
credentials.

Categories: Enterprise

Price: 0

Video: none

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds',
      'DefaultOptions' => {
        'RPORT'           => 8080,
      }
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/']),
      ], self.class)
  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'qcbin', 'SiteAdmin.jsp')
    })

    if res and res.body =~ /<title>HP Application Lifecycle Management (.*?) - Site Administration<\/title>/
      print_good("#{peer} - Found HP Application Lifecycle Management #{$1}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'HP Application Lifecycle Management',
        info: 'HP Application Lifecycle Management ' + $1
      })
    end
  end
end
