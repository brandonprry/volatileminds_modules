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
      'Name'        => 'MediaWiki Scanner',
      'Description' => %q{
This module scans for MediaWiki instances on the network.

MediaWiki is a popular open-source content manager and wiki,
internal wikis can be a gold mine of sensitive business information,
used by businesses and hobbyists alike. Often times,
such as high value targets or network credentials. This was tested
against 1.28.1.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/63whqo38brvmnkodnqkqib3yp

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find MediaWiki", '/']),
      ], self.class)

  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['PATH'] + 'index.php?title=Main_Page'
    })

    if res && res.body =~ /<meta name="generator" content="MediaWiki (.*?)"/
      print_good("#{peer} - Found MediaWiki #{$1}")
      report_service({
        host: target_host,
        port: datastore['RPORT'],
        name: 'MediaWiki',
        info: "MediaWiki #{$1}"
      })
    end
  end
end
