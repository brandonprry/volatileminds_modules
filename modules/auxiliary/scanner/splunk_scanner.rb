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
      'Name'        => 'Splunk Scanner',
      'Description' => 'This module scans for Splunk instances.',
      'Author'       => ['VolatileMinds'],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        Opt::RPORT(8000)
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => '/'
    })

    if res and res.headers["Server"] =~ /splunkd/i
      print_good("#{peer} - Found Splunk instance")

      res = send_request_cgi({
        'uri' => '/en-US/account/login'
      })

      partials = $1 if res.body =~ /<script type="text\/json" id="splunkd-partials">(.*?)<\/script>/m

      if partials
        partials = JSON.parse(partials)

      end

    end
  end
end
