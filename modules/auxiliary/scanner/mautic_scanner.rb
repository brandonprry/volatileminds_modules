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
      'Name'        => 'Mautic Scanner',
      'Description' => %q{
This module scans for Mautic instances on the network.

Mautic is a popular open-source enterprise solution for
managing marketing campaigns. Privileged access to
Mautic instances could yield significant insight into
sensitive information such as email addresses or customer names.

Categories: Open Source, Enterprise

Price: 0

Video: https://asciinema.org/a/v3Oc9EiTs5qKXb3FONCmI2yhp

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find Mautic", '/']),
      ], self.class)

  end

  def run_host(target_host)

    ['/', datastore['PATH']].uniq.each do |path|
      res = send_request_cgi({
        'uri' => normalize_uri(path, '/s/login'),
      })

      if res && res.body =~ /<title>Mautic<\/title>/
       print_good("#{peer} - Found Mautic")
       report_service({
         host: target_host,
         port: datastore['RPORT'],
         name: 'Mautic',
         info: 'Mautic marketing campaign manager'
       })
      end
    end
  end
end
