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
      'Name'        => 'WebMail Pro PHP Scanner',
      'Description' => %q{
This module scans for WebMail Pro PHP instances on the network.

WebMail Pro is a popular enterprise solution for mail, calendar,
and file management. Privileged access to a WebMail Pro instance
could yield significant insight into high value targets in the
organization or other sensitive information.

Categories: Enterprise

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
        OptString.new('PATH', [ true,  "The test path to find WebMail Pro", '/']),
      ], self.class)

  end

  def run_host(target_host)

    ['/', datastore['PATH']].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path
      })

      if res.body =~ /"ImportingContacts":"https:\\\/\\\/afterlogic.com\\\/docs\\\/webmail/
        res = send_request_cgi({
          'uri' => normalize_uri(path, 'VERSION')
        })

        if res.code == 200
          version = res.body
        end

        print_good("#{peer} - Found WebMail Pro PHP " + version)
        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'WebMail Pro',
          info: 'WebMail Pro PHP v' + version
        })
      end
    end
  end
end
