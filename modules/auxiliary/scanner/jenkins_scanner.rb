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
      'Name'        => 'Jenkins CI Scanner',
      'Description' => %q{
This module scans for Jenkins CI instances on the network.

Jenkins CI is a popular open-source and enterprise solution for managing
        software development lifecycles. Privileged access to Jenkins instances
        could give an attacker significant leverage in a network with access
        to high value targets or sensitive network credentials.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/PWTByiaAYyxkBQw7176zBvPWG

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The base URI", '/jenkins/']),
      ], self.class)

  end

  def run_host(target_host)
    ['/', datastore['PATH']].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path + (path[-1] == '/' ? '' : '/') + 'login'
      })

      if res && res.headers['X-Jenkins']
        print_good("#{peer} - Found Jenkins v" + res.headers['X-Jenkins'])
        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'Jenkins',
          info: 'Jenkins CI v'+res.headers['X-Jenkins']
        })
      end
    end
  end
end
