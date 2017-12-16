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
      'Name'        => 'ManageEngine OpManager Scanner',
      'Description' => %q{
This module scans for ManageEngine OpManager instances on the network.

ManageEngine OpManager is a popular enterprise solution for managing
IT and office infrastructure such as servers, phones, and other
sensitive devices. Privileged access to a ManageEngine OpManager
instance could yield significant insight or access to high value targets
or other sensitive information.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/cBEFMzAGByvviWNwmdjv9U2p0

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find ManageEngine OpManager", '/']),
      ], self.class)
  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/apiclient/ember/Login.jsp'),
    })

    if res && res.body =~ /<h2>OpManager<span>v (.*?)<\/span><\/h2>/
      print_good("#{peer} - Found ManageEngine OpManager " + $1)
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'ManageEngine OpManager',
        info: 'ManageEngine OpManager ' + $1
      })
    end
  end
end
