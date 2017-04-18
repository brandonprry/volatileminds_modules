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
      'Name'        => 'TeamPass Password Manager Scanner',
      'Description' => %q{
This module scans for TeamPass Password Manager instances.

TeamPass Password Manager is a popular open source password manager
meant for password sharing between teams of people, often used in an
enterprise environment. Gaining access to the password manager can
yield the keys to the kingdom so to speak.
      },
      'Author'       => ['VolatileMinds'],
      'License'     => 'VolatileMinds'
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'The target URI to test for TeamPass', '/'])
      ], self.class
    )
  end

  def run_host(target_host)
    peer = "#{target_host}:#{rport}"
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'index.php'),
    })

    if res && res.body =~ /TeamPass/
      version = $1 if res.body =~ /TeamPass&nbsp;(.*?)&nbsp;/

      print_good("#{peer}: Found a TeamPass Password Manager version #{version}")

      if Gem::Version.new(version) < Gem::Version.new('2.1.26.9')
         res = send_request_cgi({
           'method' => 'GET',
           'uri' => normalize_uri(target_uri.path, 'api', 'index.php'),
           'vars_get' => {
             'apikey' => 'fdsa'
           }
         })

         if res && res.body =~ /api_key fdsa doesn't exist/
           print_good("#{peer}: API access available to TeamPass Password Manager")

           res = send_request_cgi({
             'method' => 'GET',
             'uri' => normalize_uri(target_uri.path, 'api', 'index.php'),
             'vars_get' => {
               'apikey' => 'fdsa',
               'pre' => "'"
             }
           })

           if res && res.body =~ /error in your SQL syntax/
             print_good("#{peer}: Instance likely vulnerable to unauthenticated SQL injection")
           end
         else
           vprint_bad("#{peer}: No API access on host")
         end
      end
    else
      vprint_bad("No response or didn't return expected response")
    end
  end
end
