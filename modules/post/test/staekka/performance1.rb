# Advanced Post Exploitation
# require 'test/lib/module_test'
require 'msf/core'
lib = File.join(Msf::Config.install_root, 'test', 'lib')
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

require 'msf/core/post/common'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'staekka_path'

require 'benchmark'

# require 'staekka/base/sessions/shell_extensions.rb'
# load 'test/lib/module_test.rb'
# load 'lib/rex/text.rb'
# load 'lib/msf/core/post/linux/system.rb'
# load 'lib/msf/core/post/unix/enum_user_dirs.rb'

# load 'lib/staekka/base/sessions/shell_extensions.rb'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  # include Msf::Post::Staekka::File
  # include Msf::StaekkaTest

  def initialize(info = {})
    #        @workdir = File.realpath (File.dirname(__FILE__) + '/../../../../' + 'test/data/files')
    #        @localdir = File.realpath (File.dirname(__FILE__) + '/../../../../' + 'test/data/files')
    #        @workdir = staekka_path + '/test/data/files'
    #        @localdir = staekka_path + '/test/data/files'

    super(update_info(info,
                      'Name'          => 'Performance1',
                      'Description'   => ' This module will do some performance tests ',
                      'Author'        => ['jot'],
                      #				'Platform'      => [ 'linux', 'java' ],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_exec
    #        return
    vprint_status cmd_exec('echo START')
    number_of_tests = 1000
    number_of_tests = 20
    #       [ 8, 32, 128, 1200, 5000, 10000, 12000, 32000, 60000].each do |string_len|
    #        [1, 8, 32, 1200, 4000, 8192, 9000, 10000, 12000, 12288, 16000].each do |string_len|
    #        [1, 8, 32, 1200, 4000, 8192, 9000, 10000, 12000, 12288].each do |string_len|
    #        [1, 8, 32, 1200, 4000, 8192].each do |string_len|
    [8, 32, 500, 1200, 4000, 5000].each do |string_len|
      #         [8, 32, 128, 500, 1200, 5000].each do |string_len|
      #       [8, 32, 128].each do |string_len|
      vprint_status "LEN: #{string_len}"

      performance_print = Benchmark.measure do
        number_of_tests.times do
          token_len = 6
          token = 'X' * (string_len - token_len)
          token << ::Rex::Text.rand_text_alpha(token_len)
          out = cmd_exec("echo #{token}")
          print '.    '
          next if token == out
          if out.to_s.empty?
            vprint_status 'EMPTY    '
          else
            vprint_status "exec error: |#{token}| != |#{out.dump}|"
          end
          # vprint_status "exec error: |#{token}| != |#{out}|"
          break
        end
      end
      vprint_status ':'
      print_status "Performance: echo #{string_len}\n#{performance_print}"
      print_status "Performance: echo #{string_len}"
      printf "%f\n", (performance_print.real / number_of_tests)
    end
  end

  #
  #
  def test_stress_random
    # return
    vprint_status cmd_exec('echo RANDOM_LEN')
    number_of_tests = 100
    max_len = 5000
    number_of_tests.times do
      string_len = rand(max_len)
      token = ::Rex::Text.rand_text_alpha(string_len)
      out = cmd_exec("echo #{token}")
      print '.'
      next if token == out
      if out.to_s.empty?
        vprint_status "EMPTY: (token length = #{token.length})"
      else
        vprint_status "exec error: (length = #{token.length}) |#{token}| != |#{out.dump}|"
      end
    end
  end
end
