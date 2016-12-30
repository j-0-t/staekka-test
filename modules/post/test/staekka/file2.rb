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
    #@staekka_path =  ENV['STAEKKA_PATH']
    @staekka_path =  Msf::Config.staekka_path
    if @staekka_path.nil?
      raise "Need a staekka directory containing a file for this testing option (export STAEKKA_PATH=...)"
    end

    @staekka_test_path =  ENV['STAEKKA_TEST']
    if @staekka_test_path.nil?
      raise "Need a test directory containing a file for this testing option (export STAEKKA_TEST=...)"
    end

    # test_path  = "/home/msftest/staekka/"
    #test_path = File.dirname(__FILE__) + '/../../../../../'
    test_path = @staekka_test_path
    @workdir = test_path + '/data/files'
    @localdir = test_path + '/data/files'
    super(update_info(info,
                      'Name'          => 'Msf::Sessions::File-test',
                      'Description'   => ' This module will test Msf::Sessions::File ',
                      'Author'        => ['jot'],
                      #				'Platform'      => [ 'linux', 'java' ],
                      'SessionTypes'  => %w(meterpreter shell)))
  end

  def test_testfiles
    it 'should change to the default directory' do
      cmd_exec("cd #{@staekka_path}")
    end
    it 'should be in the default directory' do
      cmd_exec('pwd').match(@staekka_path)
    end
    # dir?
    it 'should fail: directory? not a directory' do
      !directory?("#{@workdir}/no_such_dir")
    end
    it 'should be true: directory? a directory' do
      directory?("#{@workdir}/dir_read")
    end
    it 'should fail: directory? a file' do
      !directory?("#{@workdir}/file_exists")
    end

    # exists?
    it 'should be true: exist?  a directory' do
      exist?("#{@workdir}/dir_read")
    end
    it 'should be true: exist? a file' do
      exist?("#{@workdir}/file_exists")
    end
    it 'should be fail:exist?  no extsisting' do
      !exist?("#{@workdir}/file_does_not_exist")
    end

    # readable
    it 'should fail:readable? non extsisting' do
      !readable?("#{@workdir}/file_does_not_exist")
    end
    it 'should be true:readable? a directory' do
      readable?("#{@workdir}/dir_read")
    end
    it 'should be true:readable? a file' do
      readable?("#{@workdir}/file_oneline")
    end
    it 'should fail:readable? non readable' do
      !readable?("#{@workdir}/file_nonreadable")
    end

    # writeable
    it 'should fail: writeable?  not writeable' do
      !writeable?("#{@workdir}/file_nonreadable")
    end
    it 'should be true: writeable?  a writeable file' do
      writeable?("#{@workdir}/file_write")
    end
    it 'should be fail:file_writeable?  no extsisting' do
      !writeable?("#{@workdir}/file_does_not_exist")
    end
    # suid
    it 'should fail: suid?  not suid' do
      !suid?("#{@workdir}/file_nonreadable")
    end
    it 'should be true: suid?  a suid file' do
      suid?("#{@workdir}/file_suid")
    end
    it 'should be fail: suid?  no extsisting' do
      !suid?("#{@workdir}/file_does_not_exist")
    end
    # empty?
    it 'should be true: empty?  an empty file' do
      empty?("#{@workdir}/empty_file")
    end

    it 'should fail: empty?  a non-empty file' do
      !empty?("#{@workdir}/file_ascii_1")
    end
  end

  def test_filecache
    it 'start tests with an emty cache' do
      cache_path = '~/.msf4/loot/default/filesystem'
      command = "rm -rf #{cache_path}"
      system command
    end
    it 'file should not be in cache' do
      !file_in_cache?('/no/such/file')
    end
    it 'adding file into filecache' do
      file_to_cache('/etc/test/file/cache/testfile', 'testing OK')
      file_in_cache?('/etc/test/file/cache/testfile')
    end
  end

  def test_read
    # plain text
    it 'should read a plaintext file' do
      out = read_file_plaintext("#{@workdir}/file_oneline")
      out.match('one LinE')
    end
    it 'should read a multi line plaintext file' do
      out = read_file_plaintext("#{@workdir}/file_multiline")
      out.match('Mulit lin3s')
    end
    # binary
    it 'should read a binray file' do
      out = read_file_binary("#{@workdir}/file_oneline")
      out.match('one LinE')
    end
    it 'should read a multi line binary file' do
      out = read_file_binary("#{@workdir}/file_multiline")
      out.match('Mulit lin3s')
    end
    # read_file
    it 'should read a file' do
      out = read_file("#{@workdir}/file_oneline", false, false)
      out.match('one LinE')
    end
    it 'should read a multi line file' do
      out = read_file("#{@workdir}/file_multiline", false, false)
      out.match('Mulit lin3s')
    end
    it 'should read a file' do
      out = read_file("#{@workdir}/file_oneline", true, false)
      out.match('one LinE')
    end
    it 'should read a multi line file' do
      out = read_file("#{@workdir}/file_multiline", true, false)
      out.match('Mulit lin3s')
    end
    it 'should read a file (cached)' do
      out = read_file("#{@workdir}/file_oneline", false, true)
      out.match('one LinE')
    end
    it 'should read a multi line file (cached)' do
      out = read_file("#{@workdir}/file_multiline", false, true)
      out.match('Mulit lin3s')
    end
    it 'should read a file (cached)' do
      out = read_file("#{@workdir}/file_oneline", true, true)
      out.match('one LinE')
    end
    it 'should read a multi line file (cached)' do
      out = read_file("#{@workdir}/file_multiline", true, true)
      out.match('Mulit lin3s')
    end
    it "should have the same md5 sum (plaintext file) [#{@localdir}/file_multiline|#{@workdir}/file_multiline]" do
      file_local_digestmd5("#{@localdir}/file_multiline") == file_remote_digestmd5("#{@workdir}/file_multiline")
    end
    it "should have the same md5 sum (binary file) [#{@localdir}/file_binary|#{@workdir}/file_binary]" do
      file_local_digestmd5("#{@localdir}/file_binary") == file_remote_digestmd5("#{@workdir}/file_binary")
    end
    it "should have the same md5 sum (big binary file) [#{@localdir}/file_binary_1mb|#{@workdir}/file_binary_1mb]" do
      file_local_digestmd5("#{@localdir}/file_binary_1mb") == file_remote_digestmd5("#{@workdir}/file_binary_1mb")
    end
    it 'should help debugging' do
      out = read_file("#{@workdir}/file_binary_1mb", true, false)
      tmp = ::File.new('/tmp/staekka_read_tmp_1', 'w')
      tmp.print out
      tmp.close
      true
    end
  end

  def test_read2
    return
    max_len = 4096
    set_unix_max_line_length(max_len)
    [
      'cat __READ_FILE__ |base64',
      'cat __READ_FILE__ |openssl enc -a -e',
      "perl -MMIME::Base64 -0777 -ne 'print encode_base64($_)' <__READ_FILE__",
      %q^php  -r 'print  base64_encode(file_get_contents("__READ_FILE__"));'^,
      %q^python -c 'import base64;encoded=base64.b64encode(open("__READ_FILE__", "r").read());print encoded'^,
      %q^ruby -e 'require "base64";puts Base64.encode64(File.read("__READ_FILE__"))'^,
      'cat __READ_FILE__ |uuencode -m - ',
      'uuenview -b __READ_FILE__'
    ].each do |foo|
      performance_print = Benchmark.measure do
        it "base64 encoding with \'#{foo}\' : max line lenght: #{max_len}" do
          session.cache.delete('base64_command')
          session.cache.add('base64_command', foo)
          file_local_digestmd5("#{@localdir}/file_binary_1mb") == file_remote_digestmd5("#{@workdir}/file_binary_1mb")
        end
      end
      vprint_status "Performance: #{foo}\n#{max_len}\n#{performance_print}"
      raise 'No Shell' unless cmd_success?('echo AAAA')
    end
    session.cache.delete('base64_command')
  end

  def test_write
    file_rm("#{@workdir}/tmp_file_1")
    it 'should write a file (plaintext)' do
      write_file("#{@workdir}/tmp_file_1", "write\ninto\nfile\ntest__1\nTest__")
      out = read_file("#{@workdir}/tmp_file_1", false, false)
      # $stdout.puts "out=[#{out}]"
      out.match('test__1')
    end
    it 'should append a file (plaintext)' do
      append_file("#{@workdir}/tmp_file_1", "2__test2\nappend\ninto\nfile")
      out = read_file("#{@workdir}/tmp_file_1", false, false)
      out.match('Test__2__test2')
    end
    it 'should delete tmp file' do
      file_rm("#{@workdir}/tmp_file_1")
      !file_exist?("#{@workdir}/tmp_file_1")
    end
    file_rm("#{@workdir}/tmp_file_2")
    it 'should write a file (binray)' do
      write_file("#{@workdir}/tmp_file_2", ::File.read("#{@workdir}/file_binary"))
      file_remote_digestmd5("#{@workdir}/file_binary") == file_remote_digestmd5("#{@workdir}/tmp_file_2")
    end
    it 'should write a big file ' do
      write_file("#{@workdir}/tmp_file_2", ::File.read("#{@workdir}/file_binary"))
      file_remote_digestmd5("#{@workdir}/file_binary_1mb") == file_remote_digestmd5("#{@workdir}/tmp_file_2")
    end
    it 'should delete tmp file' do
      file_rm("#{@workdir}/tmp_file_2")
      !file_exist?("#{@workdir}/tmp_file_2")
    end
  end

  def test_write2
    session.cache.delete('base64_command')
    # max_len = 60000
    max_len = 4096
    i = 0
    set_unix_max_line_length(max_len)
    [
      { cmd: "echo 'CONTENTS'|xxd -p -r", enc: :bare_hex, name: 'xxd' },
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
      { cmd: %q^python -c 'print("CONTENTS")'^, enc: :octal, name: 'python' },
      # Ruby supports both octal and hex escapes, but octal is usually
      # shorter (e.g. 0 becomes \0 instead of \x00)
      { cmd: %q^ruby -e 'print("CONTENTS")'^, enc: :octal, name: 'ruby' }
    ].each do |foo|
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
          file_remote_digestmd5("#{@workdir}/file_binary_performance") == file_remote_digestmd5("#{@workdir}/tmp_file_2_#{i}")
        end
        it 'should delete tmp file' do
          file_rm("#{@workdir}/tmp_file_2_#{i}")
          !file_exist?("#{@workdir}/tmp_file_2_#{i}")
        end
      end
      vprint_status "Performance: #{command}\n#{max_len}\n#{performance_print}"
      raise 'No Shell' unless cmd_success?('echo AAAA')
    end
  end

  def test_download
    it 'should download a text file' do
      download("#{@workdir}/file_multiline", false, false, 5)
      file_from_cache("#{@workdir}/file_multiline").match('Mulit lin3s')
    end
    it 'should download a file' do
      delete_from_cache("#{@workdir}/file_multiline")
      download("#{@workdir}/file_multiline", true, true, 5).match('Mulit lin3s')
    end
    it 'should download a cached file' do
      file_from_cache("#{@workdir}/file_multiline").to_s.match('Mulit lin3s')
    end
    #		it "should download a file using a tcp connection" do
    #			delete_from_cache("#{@workdir}/file_multiline")
    #			download_tcp_reverse("#{@workdir}/file_multiline", "127.0.0.1", 4422)
    #			file_from_cache("#{@workdir}/file_multiline").match("Mulit lin3s")
    #		end
  end
end
