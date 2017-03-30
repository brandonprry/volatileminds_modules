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
      'Name'        => 'MantisBT Scanner',
      'Description' => 'This module scans for instances of MantisBT open source bug tracking software.',
      'Author'       => [],
      'License'     => 'ExploitHub'
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true,  "The URI to look for when searching for MantisBT instances", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'login_page.php')
    })

    if res && res.body =~ /<title>MantisBT<\/title>/
      print_good("#{target_host}:#{datastore['RPORT']} - MantisBT instance found")
      report_service(
        :host => target_host,
        :port => datastore['RPORT'],
        :name => 'MantisBT',
        :info => 'An instance of the MantisBT open source bug tracking software.'
      )
    end
  end
end
