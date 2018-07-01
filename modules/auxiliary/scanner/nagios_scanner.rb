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
      'Name'        => 'Nagios Scanner',
      'Description' => %q{
This module scans for instances of Nagios on the network.

Nagios is a popular open-source enterprise solution for
asset management and monitoring. Privileged access to
a Nagios instance could yield significant insight into
a given network, and potential control over networked
assets.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/gYahWk5JpKiujyCnFqdnSJhWO

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find Nagios", '/']),
      ], self.class)

  end

  def run_host(target_host)

    [datastore['PATH'], '/nagiosxi'].each do |path|
      res = send_request_cgi({
        'uri' => normalize_uri(path, 'login.php')
      })

      if res && res.body =~ /<input type="hidden" name="product" value="nagiosxi">/
        version = $1 if res.body =~ /<input type="hidden" name="version" value="(.*?)">/

        print_good("#{peer} - Found Nagios XI #{version} on path #{path}")
        report_services({
          host: target_host,
          port: datastore['RPORT'],
          name: 'Nagios XI',
          info: 'Nagios XI ' + version
        })
      end
    end
  end
end
