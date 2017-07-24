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
      'Name'        => 'X2Engine CRM Scanner',
      'Description' => %q{
This module scans for instances of X2Engine CRM.
X2Engine is a powerful open-source CRM for small- or
medium-sized businesses. Gaining credentialed access
to X2Engine instances can yield great insight into
how a business operates, information on potential high
value targets, and even remote code execution.
Categories: Open Source
Price: 0
Video: none
OS: Multi
Arch: Multi
Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find the X2Engine CRM instance", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') +'index.php/site/login',
    })

    if res && res.body =~ /<span>X2CRM Version (.*?), <a href="https:\/\/www.x2crm.com">/
      print_good("#{peer} - Found X2Engine CRM Version #{$1}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'X2Engine CRM',
        info: 'X2ENgine CRM Version ' + $1
      })
    end
  end
end
