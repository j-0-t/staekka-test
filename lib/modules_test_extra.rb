#
class DebugUiBuffer
  attr_accessor :buffer
  attr_accessor :status
  def initialize
    @buffer = ''
    @status = ''
  end

  def reset
    @buffer = ''
    @status = ''
  end

  def print_good(string)
    @buffer << string
    @status = 'good'
  end

  def print_status(string)
    @buffer << string
    @status = 'status'
  end

  def print_error(string)
    @buffer << string
    @status = 'error'
  end

  def prompting?
    false
  end
end

module Msf::ModuleTestExtra
  def load_test_module(mod_name)
    begin
     if (mod = framework.modules.create(mod_name)).nil?
       print_error("Failed to load module: #{mod_name}")
       return false
     end
   rescue Rex::AmbiguousArgumentError => info
     print_error(info.to_s)
   rescue NameError => info
     log_error("The supplied module name is ambiguous: #{$ERROR_INFO}.")
   end

    return false if mod.nil?

    @output = DebugUiBuffer.new
    mod.init_ui(@output, @output)
    print_status "loaded module #{mod_name}"
    @mod = mod
  end
end
