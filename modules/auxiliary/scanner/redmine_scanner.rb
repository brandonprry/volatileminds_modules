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
      'Name'        => 'Redmine Scanner',
      'Description' => %q{
      This module scans for Redmine instances.

      Redmine is a popular open source bug tracking that allows
      anyone to easily track feature development and bugs. Bug
      tracking software can often be a gold mine of sensitive
      internal network information such as credentials or 
      high value targets.

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
        OptString.new('PATH', [ true,  "The test path to find robots.txt file", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/themes/README')
    })

    if res and res.code == 200 and res.body =~ /Redmine/
      print_good("#{peer} - Found Redmine instance")
    end
  end
end
