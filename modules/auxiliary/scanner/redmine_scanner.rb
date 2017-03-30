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
      'Name'        => '',
      'Description' => '',
      'Author'       => [],
      'License'     => MSF_LICENSE
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
