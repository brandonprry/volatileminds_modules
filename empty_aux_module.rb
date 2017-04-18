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
      'Name'           => 'Empty Auxiliar Module',
      'Description'    => %q{
    This is a short descrption for an auxiliary module. Also lists
    the version tested.

    A longer description after the short description goes into more
    detail about the module, the vulnerbaility, or whatever information
    is useful to provide for documentation purposes.
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
        #OptString.new("TARGETURI", [true, 'The relative URI', '/']),
      ], self.class)
  end

  def check
    Msf::Exploit::CheckCode::Safe
  end

  def run
  end
end

