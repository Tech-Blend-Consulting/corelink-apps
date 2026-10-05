# frozen_string_literal: true

require 'monitor'

module TransitClient
  # Polls the transit API and fires callbacks when values change.
  #
  # Register callbacks with #watch_secret / #watch_config before calling #start.
  # Name '*' watches everything. Named and wildcard callbacks are independent:
  # both fire when a named value changes and a wildcard watch is registered.
  #
  # Transient fetch errors are skipped; polling resumes on the next tick.
  class Watcher
    def initialize(client, interval: 15.0)
      @client = client
      @interval = interval
      @monitor = Monitor.new
      @secret_vals = {}
      @config_vals = {}
      @secret_seen = {}
      @config_seen = {}
      @secret_fns = Hash.new { |h, k| h[k] = [] }
      @config_fns = Hash.new { |h, k| h[k] = [] }
      @thread = nil
      @stopped = false
    end

    # Register a block called with the secret's value. Use '*' for all secrets.
    def watch_secret(name, &block)
      @monitor.synchronize { @secret_fns[name] << block }
    end

    # Register a block called with the config's content. Use '*' for all configs.
    def watch_config(name, &block)
      @monitor.synchronize { @config_fns[name] << block }
    end

    # Begin polling in a background thread. The first poll runs immediately.
    def start
      @stopped = false
      @thread = Thread.new do
        poll
        until @stopped
          sleep @interval
          break if @stopped

          poll
        end
      end
      @thread.abort_on_exception = false
      nil
    end

    # Stop polling.
    def stop
      @stopped = true
      @thread&.join(@interval + 1)
      @thread = nil
      nil
    end

    private

    def poll
      poll_secrets
      poll_configs
    end

    def poll_secrets
      has_wild, names = @monitor.synchronize do
        [@secret_fns.key?('*'), @secret_fns.keys.reject { |n| n == '*' }]
      end
      processed = {}

      if has_wild
        begin
          secrets = @client.list_secrets
        rescue StandardError
          return # whole listing failed; try again next tick
        end
        secrets.each do |s|
          name = s['name']
          value = s['value'].to_s
          if update(@secret_vals, @secret_seen, name, value)
            dispatch(@secret_fns, '*', value)
            dispatch(@secret_fns, name, value)
          end
          processed[name] = true
        end
      end

      names.each do |name|
        next if processed[name]

        begin
          value = @client.get_secret(name)
        rescue StandardError
          next
        end
        dispatch(@secret_fns, name, value) if update(@secret_vals, @secret_seen, name, value)
      end
    end

    def poll_configs
      has_wild, names = @monitor.synchronize do
        [@config_fns.key?('*'), @config_fns.keys.reject { |n| n == '*' }]
      end
      processed = {}

      if has_wild
        begin
          configs = @client.list_configs
        rescue StandardError
          return
        end
        configs.each do |c|
          name = c['name']
          content = c['content'].to_s
          if update(@config_vals, @config_seen, name, content)
            dispatch(@config_fns, '*', content)
            dispatch(@config_fns, name, content)
          end
          processed[name] = true
        end
      end

      names.each do |name|
        next if processed[name]

        begin
          content = @client.get_config(name)
        rescue StandardError
          next
        end
        dispatch(@config_fns, name, content) if update(@config_vals, @config_seen, name, content)
      end
    end

    # Store and report whether this is the first sighting or a change.
    def update(vals, seen, name, value)
      @monitor.synchronize do
        if !seen[name] || vals[name] != value
          vals[name] = value
          seen[name] = true
          true
        else
          false
        end
      end
    end

    # Invoke callbacks outside the lock; a throwing callback must not stop the
    # others or kill the poll loop.
    def dispatch(fns_map, key, value)
      fns = @monitor.synchronize { fns_map[key].dup }
      fns.each do |fn|
        fn.call(value)
      rescue StandardError
        # callback errors are the caller's problem, not the watcher's
      end
    end
  end
end
