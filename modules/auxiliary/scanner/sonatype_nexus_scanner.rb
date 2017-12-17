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
      'Name'        => 'Sonatype Nexus Scanner',
      'Description' => %q{
This module scans for Sonatype Nexus instances on a network.

Sonatype Nexus is a popular open-source enterprise development
solution, used to manage repositories of dependencies for application
development. Privileged access to a Sonatype Nexus instance could
yield significantly more access through the network via backdoored
dependency packages.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/osaVXTM7oe35U2afs4EA1bUam

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
        'Author'       => [],
        'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(8081),
        OptString.new('TARGETURI', [ true,  "The test path to find Sonatype Nexus", '/nexus']),
      ], self.class)

  end

  def run_host(target_host)

    [datastore['TARGETURI'], '/', '/nexus'].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path + (path[-1] == '/' ? '' : '/')
      })

      if res && res.body =~ /<title>Nexus Repository Manager<\/title>/
        res = send_request_cgi({
          'uri' =>  path + (path[-1] == '/' ? '' : '/') + 'service/local/status',
          'headers' => {
            'Accept' => 'application/json'
          }
        })

        version = ''
        if res.code != 404
          json = JSON.parse(res.body)
          version = json['data']['version']
        else
          version = res.headers['Server']
        end

        print_good("#{peer} - Found Sonatype Nexus " + version + ' on path ' + path)

        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'Sonatype Nexus',
          info: 'Sonatype Nexus ' + version
        })
        break
      end
    end
  end
end
