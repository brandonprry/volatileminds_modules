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
      'Name'        => 'Odoo Scanner',
      'Description' => %q{
This module scans for instances of Odoo (formerly OpenERP) on the network.

This module scans for instances of Odoo (formerly OpenERP) on the network.
Odoo is a popular open-source suite of applications for managing many aspects
of businesses and enterprises. Privileged access to an Odoo instance could
yield significant insight into an organization's high-value targets, as well
as sensitive or privileged information.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/Of9jpkenoVABbe42DOk5G7OJZ

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true,  "The base uri for Odoo", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'web', 'login')
    })

    if res and res.body =~ /var odoo={csrf_token:/
      print_good("#{peer} - Found Odoo")
      report_service(
        host: target_host,
        port: datastore['RPORT'],
        name: 'Odoo (OpenERP)',
        info: 'Odoo (formerly OpenERP)'
      )
    end
  end
end
