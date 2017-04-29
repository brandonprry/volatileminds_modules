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
      'Name'        => 'b2evolution Scanner Module',
      'Description' => %q{
This module attempts to find instances of b2evolution on a network.

b2evolution is a popular open-source forums and content management
system. Gaining credentialed access may lead to vulnerabilities in older
versions, private forums, or other sensitive data. This was tested against 6.8.2.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/ct4irbrty8aoegiqr33ye2hu7

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find b2evolution", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + 'index.php'
    })

    if res && res.body =~ /<meta name="generator" content="b2evolution (.*?)" \/>/
      print_good("#{peer} - Found b2evolution #{$1}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'b2evolution',
        info: 'b2evolution ' + $1
      })
    end
  end
end
