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
      'Name'        => 'ManageEngine AD360 Scanner',
      'Description' => %q{
This module scans for instances of ManageEngine AD360 on the network.

ManageEngine AD360 is a popular enterprise solution for managing and
auditing environments using ActiveDirectory for authentication. Privileged
access to an AD360 instance could yield signficant insight into credentials
on the network.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/34cR03do7I4tceW1IYwdMZEAO

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(8082),
        OptString.new('PATH', [ true,  "The base URI", '/']),
      ], self.class)

  end

  def run_host(target_host)

    ['/',datastore['PATH']].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path + (path[-1] == '/' ? '' : '/') + 'AppsHome.do'
      })

      if res && res.body =~ /ad360-login-container/
        build = $1 if res.body =~ /buildno=(.*?)"\/>/
        print_good("#{peer} - Found ManageEngine AD360 " +(build ? 'build '+build : ''))
        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'ManageEngine AD360',
          info: 'ManageEngine AD360 ' + (build ? 'build ' + build : '')
        })
      end
    end
  end
end
