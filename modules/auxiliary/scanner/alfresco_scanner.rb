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
      'Name'        => 'Alfresco ECM/BPM Scanner',
      'Description' => %q{
This module scans for instances of the Alfresco enterprise suite.

The Alfresco enterprise software suite allows businesses to easily
manage documents and business processes, while providing support
for internal social networks and other features. Gaining access
to Alfresco instances may yield sensitive documents and information,
as well as significant insights into busines processes and high value
targets.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/04c7xdlhmarfwgjvr4nacn5g9

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        #OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => '/share/page'
    })

    if res && res.body =~ /<title>Alfresco &raquo; Login<\/title>/
      print_good("#{peer} - Found Alfresco")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Alfresco',
        info: 'Alfresco Content Manager'
      })
    end
  end
end
