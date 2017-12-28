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
      'Name'        => 'Re:dash Scanner',
      'Description' => %q{
This module scans for instances of Re:dash on the network.

Re:dash is a popular open-source solution for data visualization
and log management. Privileged access to Re:dash instances
could yield significant insight into high-value targets
or other sensitive organizational information.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/4PxExAtiPVwhDiuLjVvLRwsxo

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find Re:dash", '/']),
      ], self.class)

  end

  def run_host(target_host)
    ['/', datastore['PATH']].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path + (path[-1] == '/' ? '' : '/') + 'login',
        'headers' => {
          'X-Forwarded-For' => Rex::Text.rand_text_alpha(10)
        }
      })

      if res and res.body =~ /<title>Login . Redash<\/title>/
        print_good("#{peer} - Found Re:dash on path " + path)
        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'Re:dash',
          info: 'Re:dash SIEM on path ' + path
        })
      end
    end
  end
end
