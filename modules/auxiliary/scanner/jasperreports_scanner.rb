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
      'Name'        => 'JasperReports Scanner',
      'Description' => %q{
This module scans for instances of JasperReports.

JasperReports is a popular enterprise solution for creating
and managing dynamic reports from any kind of dataset. Gaining
access to a JasperReports instance may yield significant insight
into a company's data, and even remote access to the server via
the operating system shell.

Categories: Enterprise

Price: 0

Video: https://asciinema.org/a/2kmkklaaqml3t41dc8tmc5ynu

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find JasperReports", '/jasperserver/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + '/login.html;jsessionid=',
    })

    if res && res.body =~ /<title>TIBCO Jaspersoft: Login<\/title>/
      str = ' - Found JasperReports'

      res.body =~ /<p class="message">Product Version: <span class="emphasis">(.*?)<\/span><\/p>/
      v = $1

      res.body =~ /<p class="message">Build: <span class="emphasis">(.*?)<\/span><\/p>/
      b = $1

      if v && b
        str << " Version #{v} Build #{b}"
      end

      print_good("#{peer}" + str)
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'JasperReports',
        info: "JasperReports #{v} #{b}"
      })
    end
  end
end
