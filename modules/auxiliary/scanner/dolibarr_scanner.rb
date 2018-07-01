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
      'Name'        => 'Dolibarr ERP & CRM Scanner',
      'Description' => %q{
This module scans for Dolibarr ERP/CRM instances on the network.

Dolibarr ERP & CRM is a popular open-source solution for enterprises or
        organizations to manage invoicing, customer relations, lead generation,
        and a slew of other features. Privileged access to a Dolibarr instance
        could yield significant insight into business processes or high value
        targets.

Categories: Open Source, Enterprise, SQL Injection

Price: 0

Video: https://asciinema.org/a/rTOvGBcy9NNpDh17xrMKSoOIq

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find Dolibarr", '/']),
      ], self.class)

  end

  def run_host(target_host)
    [datastore['PATH'], '/'].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path
      })

      if res and res.body =~ /<div class="login_table_title center" title="Dolibarr (.*?)">/
        print_good("#{peer} - Found Dolibarr " + $1)
        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'Dolibarr',
          info: "Dolibarr ERP " + $1
        })
      end
    end
  end
end
