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
      'Name'        => 'Discourse Forums Scanner',
      'Description' => %q{
      This module scans for instances of Discourse forums.

      Discourse is a popular open source forums software written in Ruby.
      Internal forum instances often have protected areas with sensitive
      internal network information.
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
      'uri' => datastore['TARGETURI']
    })

    if res and res.body =~ /<meta name="generator" content="Discourse (.*?)">/
      print_good("#{peer}  - Found Discourse "+$1)
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Discourse',
        info: 'Discourse forums installation'
      })
    end
  end
end
