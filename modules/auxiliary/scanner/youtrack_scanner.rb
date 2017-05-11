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
      'Name'        => 'YouTrack Scanner',
      'Description' => %q{
This module scans for instances of Jetbrains YouTrack.

The JetBrains YouTrack software suite enable development teams to manage
and track development of software using agile-centered development strategies
and bug tracking. Privileged access to a YouTrack instance may lead to
sensitive information disclosure such as network credentials or high-value
targets on the network.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/adv9fwuwqt17hzgmikbbxgbf6

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds',
      'DefaultOptions' => {
        'RPORT' => 443,
        'SSL' => true
      }
    )

    register_options(
      [
        #OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => '/dashboard'
    })

    if res && res.body =~ /no-title="YouTrack"/
      print_good("#{peer} - Found YouTrack")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'YouTrack',
        info: 'YouTrack'
      })
    end
  end
end
