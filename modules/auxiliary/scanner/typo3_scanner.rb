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
      'Name'        => 'TYPO3 Scanner',
      'Description' => %q{
This module scans for TYPO3 instances on the network.

TYPO3 is a popular open-source content management system written
in PHP. Privileged access to a TYPO3 instance could result in a
better foothold into the web server's internal network or provide
for phishing opportunities.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/29JA7XTe9AiXLGvisUixN5TA0

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find TYPO3", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + 'typo3/index.php',
    })

    if res && res.body =~ /TYPO3 CMS/
      print_good("#{peer} - Found TYPO3")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'TYPO3',
        info: 'TYPO3 content management system'
      })
    end
  end
end
