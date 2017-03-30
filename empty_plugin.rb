require 'digest'

module Msf
class Plugin::ExploitHub < Msf::Plugin
  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      'ExploitHub'
    end

    def commands
      {
        'eh_login' => 'Login with your ExploitHub credentials',
      }
    end

    def cmd_eh_login(*args)
    end

  end

  def initialize(framework, opts)
    super
    print_status("ExploitHub plugin loaded. Log in with your ExploitHub credentials.")
  end

  def cleanup
    remove_console_dispatcher('ExploitHub')
  end

  def name
    'ExploitHub'
  end

  def desc
    'Integrate Metasploit with your ExploitHub account'
  end
end
end
