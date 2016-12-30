# Advanced Post Exploitation
# require 'test/lib/module_test'

require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

require 'msf/core/post/common'
require 'core/post/staekka'
# require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'

# load 'test/lib/module_test.rb'
# load 'lib/rex/text.rb'
# load 'lib/msf/core/post/linux/system.rb'
# load 'lib/msf/core/post/unix/enum_user_dirs.rb'

require 'base/sessions/shell_extensions'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::Common
  include Msf::Post::Staekka

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Msf::Sessions::ShellExtensions-test',
                      'Description'   => ' This module will test Msf::Sessions::ShellExtensions ',
                      'Author'        => ['jot'],
                      #				'Platform'      => [ 'linux', 'java' ],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_cmd
    it 'should execute a command' do
      out = session.shell_command_token_unix('echo XXXX1').to_s.chomp
      out == 'XXXX1'
    end
    it 'should timeout 1' do
      out = session.shell_command_token_unix('sleep 10; echo XXXX2', 2).to_s.chomp
      sleep 5
      vprint_status "OUT=#{out.dump}"
      out != 'XXXX2'
    end
    it 'should timeout 2' do
      out = session.shell_command_token_unix('sleep 1;echo XXXX3;sleep 1;echo XXXX3;sleep 1; echo XXXX3;sleep 1; echo XXXX3', 2, 4).to_s.chomp
      sleep 5
      out != 'XXXX3'
    end
    it 'should not timeout 1' do
      out = session.shell_command_token_unix('sleep 5; echo XXXX4', 7).to_s.chomp
      sleep 5
      out == 'XXXX4'
    end
  end

  def test_cmd_success
    it 'should fail: cat /non/existing/file' do
      !cmd_success?('cat /non/existing/file')
    end
    it 'should be true: echo ' do
      cmd_success?('pwd')
    end
  end

  def test_echo?
    it 'should have echo' do
      session.echo?
    end
  end

  def test_tty?
    it 'should have tty' do
      session.tty?
    end
  end

  def test_environ
    it 'should get $PATH' do
      out = session.enviroment_get('PATH')
      out.match('/bin')
    end
    it 'should be empty: get $NOTHING' do
      out = session.enviroment_get('NOTHING')
      out.empty?
    end
    it 'should set a FOO env' do
      session.enviroment_set('FOO', 'BAR')
      out = session.enviroment_get('FOO')
      out == 'BAR'
    end
  end

  def test_session
    it 'should be the same session' do
      session.new_session_start
      !session.new_session?
    end
  end

  def test_commands
    it 'should echo a short string' do
      tmp = 'X'
      out = cmd_exec("echo #{tmp}")
      tmp == out
    end
    it 'should echo a long string' do
      tmp = ''
      2000.times do
        tmp << 'A'
      end
      out = cmd_exec("echo #{tmp}")
      tmp == out
    end
  end

  def _no_test_mutible_commands
    number_of_tests = 10
    it 'should execute multible commands using' do
      tokens = []
      cmd = ''
      number_of_tests.times do
        tokens << ::Rex::Text.rand_text_alpha(16)
      end
      tokens.each do |t|
        cmd << "echo #{t};"
      end
      result = true
      out = cmd_exec(cmd)
      tokens.each do |t|
        next if out.match(t)
        vprint_status "CMD=|#{cmd}|"
        vprint_status "OUT=|#{out}| token=|#{t}|"
        result = false
      end
      result
    end
  end

  def test_length
    number_of_tests = 10
    it 'should echo a token with various length' do
      [1, 8, 32, 64, 128, 250, 500, 1000, 2000, 5000].each do |string_len|
        print_status("token with length of #{string_len} characters")
        number_of_tests.times do
          token = ::Rex::Text.rand_text_alpha(string_len)
          out = cmd_exec("echo #{token}")
          next if token == out
          if out.to_s.empty?
            vprint_status "String-length=#{string_len}\t: EMPTY"
          else
            vprint_status "String-length=#{string_len}\t:exec error: |#{token}| != |#{out.dump}|"
          end
          # vprint_status "exec error: |#{token}| != |#{out}|"
          break
        end
      end
    end
  end
end
