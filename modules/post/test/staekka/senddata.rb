# Advanced Post Exploitation
# require 'test/lib/module_test'
require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

require 'msf/core/post/common'
require 'msf/core/post/file'

require 'core/post/staekka'
require 'core/post/staekka/send_data'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  # include Msf::Post::Staekka::File
  include Msf::Post::Staekka::SendData

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Msf::Sessions::Senddata-test',
                      'Description'   => ' This module will test Msf::Sessions::Senddata ',
                      'Author'        => ['jot'],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_senddata
    # send_ctrl_c
    # return

    ##################################################
    #
    # TODO:
    # usually it works; sometimes it causes errors
    #
    #
    #        it "execute top and send not execute a command" do
    #        	session.shell_write("\n")
    #        	session.shell_write("top")
    #        	session.shell_write("\n")
    #        	!cmd_success?("pwd")
    #        end
    #        it "execute top and send q to quit" do
    #        	send_q
    #        	send_newline
    #        	send_newline
    #        	session.shell_write("top")
    #        	session.shell_write("\n")
    #        	send_q
    #        	send_newline
    #        	sleep 1
    #        	cmd_success?("pwd")
    #        end
    ###################################################
    it 'execute top and send [crtl-c] to quit' do
      send_q
      session.shell_write("\n")
      session.shell_write('top')
      session.shell_write("\n")
      send_ctrl_c
      sleep 1
      cmd_success?('pwd')
    end
    it 'execute top and send [crtl-z] to pause' do
      send_q
      session.shell_write("\n")
      session.shell_write('top')
      session.shell_write("\n")
      send_ctrl_z
      sleep 1
      cmd_success?('pwd')
    end
    #        it "edit and send [crtl-d] for EOF" do
    #            send_q
    #            session.shell_write("\n")
    #            session.shell_write("cat >/dev/null")
    #            session.shell_write("\n")
    #            send_ctrl_d
    #            sleep 1
    #            cmd_success?("pwd")
    #        end
    it 'execute vi and send execute a shell' do
      session.shell_write("\n")
      session.shell_write('vi')
      session.shell_write("\n")
      send_vi_shell
      session.shell_write("\n")
      sleep 1
      cmd_success?('pwd')
    end
  end
end
