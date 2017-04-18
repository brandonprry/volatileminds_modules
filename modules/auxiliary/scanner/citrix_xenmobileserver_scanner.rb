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
      'Name'        => 'Citrix XenMobile Server Scanner',
      'Description' => %q{
      This module scans for instances of Citrix XenMobile Server.

      Citrix XenMobile servers allow an enterprise to granularly
      manage what mobile devices are allowed on the enterprise network.
},
      'Author'       => [
        'VolatileMinds'
       ],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(8443),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptString.new('TARGETURI', [ true,  "The target URI of the XenMobile Server installation.", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/controlpoint/rest/xdmServices/general/version'),
      'headers' => {
        'Accept' => 'application/javascript',
        'Referer' => "https://#{target_host}:8443/zdm/login_xdm_uc.jsp"
      }
    })

    if res and res.code == 200 and res.body
      begin
        version = JSON.parse(res.body)
        print_good("#{peer} - Found XenMobile Server version #{version['message']}")
      rescue
        print_error('Parsing server response failed')
      end
    end
  end
end
