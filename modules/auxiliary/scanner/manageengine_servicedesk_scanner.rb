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
      'Name'        => 'ManageEngine ServiceDesk Plus Scanner',
      'Description' => %q{
This module scans for instances of ManageEngine ServiceDesk Plus on the network.

ManageEngine ServiceDesk Plus is a popular enterprise system for managing
service-oriented workflows and requests within an organization. Privileged
access to ServiceDesk instances can provide a wealth of information such
as network credentials and high-value targets.

Categories: Enterprise

Price: 0

Video: none

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('PATH', [ true,  "The path to find ServiceDesk Plus on.", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path),
    })

    if res and res.body =~ /<title>ManageEngine ServiceDesk Plus<\/title>/
      version = $1 if res.body =~ /index.html','(.*?)'\); \/\/NO OUTPUTENCODING/

      print_good("#{peer} - Found ManageEngine Service Desk Plus #{version}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'ManageEngine ServiceDesk Plus',
        info: "ManageEngine ServiceDesk Plus #{version}"
      })
    end
  end
end
