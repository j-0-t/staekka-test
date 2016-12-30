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
    # test_path  = "/home/msftest/staekka/"
    staekka_test_path =  ENV['STAEKKA_TEST']
    if staekka_test_path.nil?
      raise "Need a test directory containing a file for this testing option (export STAEKKA_TEST=...)"
    end
    #test_path = File.dirname(__FILE__) + '/../../../../../'
    test_path = staekka_test_path
    @workdir = ::File.expand_path(test_path + '/data/files')
    @localdir = ::File.expand_path(test_path + '/data/files')
    super(update_info(info,
                      'Name'          => 'Performance2',
                      'Description'   => ' This module will do some performance tests ',
                      'Author'        => ['jot'],
                      #				'Platform'      => [ 'linux', 'java' ],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_cmd
    it 'should execute a command' do
      out = session.shell_command_token_unix('echo XXXX').to_s.chomp
      out == 'XXXX'
    end
  end

  def test_read2
    # return
    max_len = 4096
    # max_len = 60000
    # max_len = 2000
    # set_unix_max_line_length(max_len)
    [
      'cat __READ_FILE__ |base64',
      'cat __READ_FILE__ |openssl enc -a -e',
      "perl -MMIME::Base64 -0777 -ne 'print encode_base64($_)' <__READ_FILE__",
      %q^php  -r 'print  base64_encode(file_get_contents("__READ_FILE__"));'^,
      %q^python -c 'import base64;encoded=base64.b64encode(open("__READ_FILE__", "r").read());print encoded'^,
      %q^ruby -e 'require "base64";puts Base64.encode64(File.read("__READ_FILE__"))'^,
      # %q^cat __READ_FILE__ |uuencode -m - ^, # [BUG] not working
      'uuenview -b __READ_FILE__'
    ].each do |foo|
      number_of_tests = 10
      performance_print = Benchmark.measure do
        number_of_tests.times do
          it "base64 encoding with \'#{foo}\' : max line lenght: #{max_len}" do
            session.cache.delete('base64_command')
            session.cache.add('base64_command', foo)
            file_local_digestmd5("#{@localdir}/file_binary_1mb") == file_remote_digestmd5("#{@workdir}/file_binary_1mb")
          end
        end
        vprint_status "Performance: #{foo}\n#{max_len}\n#{performance_print}"

        raise 'No Shell' unless cmd_success?('echo AAAA')
      end
      printf "%f\n", (performance_print.real / number_of_tests)
      vprint_status '============================================================================'
    end
    session.cache.delete('base64_command')
  end
  #

  def test_write2
    # return
    raise 'No Shell' unless cmd_success?('echo AAAA')
    session.cache.delete('base64_command')
    # max_len = 60000
    max_len = 4096
    i = 0
    # set_unix_max_line_length(max_len)
    [
      #            { :cmd => %q^echo 'CONTENTS'|xxd -p -r^ , :enc => :bare_hex, :name => "xxd" },
      # Both of these work for sure on Linux and FreeBSD
      { cmd: "/usr/bin/printf 'CONTENTS'", enc: :octal, name: 'printf' },
      { cmd: "printf 'CONTENTS'", enc: :octal, name: 'printf' },
      # Works on Solaris
      { cmd: "/usr/bin/printf %b 'CONTENTS'", enc: :octal, name: 'printf' },
      { cmd: "printf %b 'CONTENTS'", enc: :octal, name: 'printf' },
      # Perl supports both octal and hex escapes, but octal is usually
      # shorter (e.g. 0 becomes \0 instead of \x00)
      { cmd: %q^perl -e 'print("CONTENTS")'^, enc: :octal, name: 'perl' },
      # POSIX awk doesn't have \xNN escapes, use gawk to ensure we're
      # getting the GNU version.
      { cmd: %q(gawk 'BEGIN {ORS="";print "CONTENTS"}' </dev/null), enc: :hex, name: 'awk' },
      # Use echo as a last resort since it frequently doesn't support -e
      # or -n.  bash and zsh's echo builtins are apparently the only ones
      # that support both.  Most others treat all options as just more
      # arguments to print. In particular, the standalone /bin/echo or
      # /usr/bin/echo appear never to have -e so don't bother trying
      # them.
      { cmd: "echo -ne 'CONTENTS'", enc: :hex },
      #######################
      #
      { cmd: %q^php -r 'print("CONTENTS");'^, enc: :octal, name: 'php' },
      # TODO: python remove last new line from output
      # Python supports both octal and hex escapes, but octal is usually
      # shorter (e.g. 0 becomes \0 instead of \x00)
      # { :cmd => %q^python -c 'print("CONTENTS")'^ , :enc => :octal, :name => "python" },
      # Ruby supports both octal and hex escapes, but octal is usually
      # shorter (e.g. 0 becomes \0 instead of \x00)
      { cmd: %q^ruby -e 'print("CONTENTS")'^, enc: :octal, name: 'ruby' }
    ].each do |foo|
      number_of_tests = 10
      number_of_tests.times do
        performance_print = Benchmark.measure do
          #            puts "External: #{session.rstream.stdout.external_encoding}"
          #            puts "Internal: #{session.rstream.stdout.internal_encoding}"
          #            session.rstream.stdout.set_encoding("ascii-8bit:iso-8859-1")

          i = + 1
          session.cache.delete('echo_cmd')
          session.cache.delete('echo_enc')
          session.cache.delete('echo_name')

          command = foo[:cmd]
          encoding = foo[:enc]
          cmd_name = foo[:name]
          session.cache.add('echo_cmd', command)
          session.cache.add('echo_enc', encoding)
          session.cache.add('echo_name', cmd_name)

          file_rm("#{@workdir}/tmp_file_2_#{i}")

          performance_print = Benchmark.measure do
            it "should write a big file using #{command}" do
              write_file("#{@workdir}/tmp_file_2_#{i}", ::File.read("#{@workdir}/file_binary_performance"))
              data = read_file("#{@workdir}/file_binary_performance", true, false)
              tmp1 = ::File.new('/tmp/__debug_file', 'w')
              tmp1.print data
              tmp1.close
              file_local_digestmd5("#{@workdir}/file_binary_performance") == file_remote_digestmd5("#{@workdir}/tmp_file_2_#{i}")
            end
            #                it "should delete tmp file" do
            #                    file_rm("#{@workdir}/tmp_file_2_#{i}")
            #                    not file_exist?("#{@workdir}/tmp_file_2_#{i}")
            #                end
          end
          print_status("#{@workdir}/file_binary_performance ->  #{@workdir}/tmp_file_2_#{i}")
          print_status "Performance: #{command}\n#{max_len}\n#{performance_print}"
          unless cmd_success?('echo AAAA')
            # wait a moment and try again
            Rex::ThreadSafe.sleep 0.5
            unless cmd_success?('echo BBBBBBBB')
              raise 'No Shell'
            end
          end
        end
        printf "%f\n", (performance_print.real / number_of_tests)
      end

      vprint_status '============================================================================'
    end
  end
end
