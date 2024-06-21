require_relative 'ext/kalkancrypt/kalkancrypt'

module KalkanRuby
  class Client
    def initialize
      @mutex = Mutex.new
    end

    def self.new_client
      client = new
    end

    def client_init
      @mutex.synchronize do
        kc_init
      end
    end

    private

    def kc_init
      kc = KalkanCrypt::KalkanCrypt.new
      kc.init
    end
  end
end

cli = KalkanRuby::Client.new_client
client = cli.client_init
puts "Initialization client: #{client}"
