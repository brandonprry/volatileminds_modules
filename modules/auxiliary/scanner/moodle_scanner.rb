##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Moodle Scanner',
      'Description' => %q{
This module scans for instances of Moodle on the network.

Moodle is a popular open-source learning management system (LMS)
that enables trainers, educators, and students to manage and use
industry-standard educational content. Privileged access to
Moodle instances may yield signficant insight into sensitive
information such as student names or other material.

Categories: Open Source

Price: 0

Video: https://asciinema.org/a/W4pNj84hEHvHvIhyXoArQqh41

OS: Multi

Arch: Multi

Requirements: Metasploit Framework
      },
      'Author'       => [],
      'License'     => 'VolatileMinds'
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find Moodle", '/']),
      ], self.class)

  end

  def run_host(target_host)

    ['/', datastore['PATH']].uniq.each do |path|
      res = send_request_cgi({
        'uri' => path
      })

      if res && (res.get_cookies =~ /MoodleSession/ || res.body =~ /moodle-has-zindex/)
        print_good("#{peer} - Found Moodle")
        report_service({
          host: target_host,
          port: datastore['RPORT'],
          name: 'Moodle',
          info: 'Moodle LMS'
        })
      end
    end
  end
end
