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
      'Name'        => 'Wordpress Support Plus Responsive Ticket System Scanner',
      'Description' => 'This module scans for instances of the Support Plus Responsive Ticket Scanner plugin for Wordpress.',
      'Author'       => [
        'ExploitHub'
       ],
      'License'     => 'ExploitHub'
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The target URI of the Wordpress installation.", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'wp-support-plus-responsive-ticket-system', 'readme.txt')
    })

   if res and res.body =~ /WP Support Plus Responsive Ticket System/
     print_good("#{peer} - Wordpress Support Plus Responsive Ticket System plugin found.")
   end
  end
end
