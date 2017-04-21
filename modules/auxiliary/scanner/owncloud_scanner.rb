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
      'Name'        => 'ownCloud Scanner',
      'Description' => %q{
This module scans for ownCloud instances.

The ownCloud software suite allows a user to easily spin up
a free Dropbox alternative. They can be used for file sharing
or general backup purposes. As such, they can be a gold mine of 
information.

Categories: Open Source

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
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [ true,  "The URI to test for ownCloud", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/index.php/login')
    })


    if res and res.body =~ /ownCloud/
      print_good("#{peer} - Found ownCloud instance")
      report_service(
        :host => target_host,
        :port => datastore['RPORT'],
        :name => 'ownCloud',
        :info => 'ownCloud instance'
      )
    end
  end
end
