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
      'Name'        => 'SonarQube Scanner',
      'Description' => %q{
This module scans for SonarQube instances.

The SonarQube system enables easy and fast code review for a large
variety of languages. As such, SonarQube instances often give
significant insight into internal codebases and business
processes.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/Uqb18Gi9z6oRpNWKj67DGKIuE

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find SonarQube", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + '/sessions/new',
    })

    if res && res.body =~ /<title>SonarQube<\/title>/
      res = send_request_cgi({
        'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + '/api/system/status'
      })

      json = JSON.parse(res.body)

      print_good("#{peer} - Found SonarQube #{json['version']}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'SonarQube',
        info: "SonarQube #{json['version']}"
      })

    end
  end
end
