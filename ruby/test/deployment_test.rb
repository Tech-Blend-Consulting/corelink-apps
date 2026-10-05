# frozen_string_literal: true

# The deployment file reader, against the cases every SDK shares.
#
# Six hand-written readers drift unless one thing pins them.
# sdk/testdata/deployment_cases.json is that thing: the accepted files with
# their expected result, and the rejected files that must be refused rather than
# read as something their author did not write.
#
# Run: ruby -Isdk/ruby/lib sdk/ruby/test/deployment_test.rb

require 'json'
require 'minitest/autorun'
require 'tmpdir'
require 'transit_client'

class SharedDeploymentCasesTest < Minitest::Test
  CASES = File.expand_path('../../testdata/deployment_cases.json', __dir__)

  def setup
    @cases = JSON.parse(File.read(CASES))
    refute_empty @cases['accepted']
    refute_empty @cases['rejected']
  end

  # Run the whole load, so the shared cases exercise what an application calls.
  def parse_text(text)
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'secrets.yaml')
      File.write(path, text)
      return TransitClient::Deployment.load(path)
    end
  end

  def test_accepted
    @cases['accepted'].each do |c|
      d = parse_text(c['text'])
      assert_equal c['nhiId'], d.nhi_id, "#{c['name']}: nhiId"
      assert_equal c['serviceAccount'], d.service_account, "#{c['name']}: serviceAccount"
      assert_equal c['secrets'], d.secrets, "#{c['name']}: secrets"
    end
  end

  def test_rejected
    @cases['rejected'].each do |c|
      assert_raises(TransitClient::Deployment::Error,
                    "#{c['name']} was accepted; it should be refused rather than read " \
                    'as something its author did not write') do
        parse_text(c['text'])
      end
    end
  end
end

class DeploymentLoadingTest < Minitest::Test
  def test_a_missing_file_is_not_an_error_for_the_optional_loader
    Dir.mktmpdir do |dir|
      assert_nil TransitClient::Deployment.load_if_present(File.join(dir, 'absent.yaml'))
    end
  end

  def test_but_a_file_that_does_not_parse_still_is
    # "No file" and "a file I could not read" are different, and running the
    # application on a configuration nobody wrote is the wrong recovery.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'broken.yaml')
      File.write(path, "nhiId: a\nsecrets: [one]\n")
      assert_raises(TransitClient::Deployment::Error) do
        TransitClient::Deployment.load_if_present(path)
      end
    end
  end

  def test_the_environment_overrides_the_path
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'elsewhere.yaml')
      File.write(path, "nhiId: abc\nsecrets: production/one\n")
      ENV[TransitClient::Deployment::PATH_ENV] = path
      begin
        assert_equal path, TransitClient::Deployment.load.path
      ensure
        ENV.delete(TransitClient::Deployment::PATH_ENV)
      end
    end
  end
end

class DeploymentServiceAccountTest < Minitest::Test
  def test_no_name_means_no_opinion
    TransitClient::Deployment::File.new(nhi_id: 'a', secrets: ['one']).verify_service_account
  end

  def test_no_token_means_no_opinion
    # Not running under Kubernetes, which is the ordinary case for a host.
    TransitClient::Deployment::File.new(
      nhi_id: 'a', service_account: 'orders', secrets: ['one']
    ).verify_service_account
  end

  def test_it_reads_the_name_out_of_a_projected_token
    payload = Base64.urlsafe_encode64(
      JSON.generate('kubernetes.io' => { 'serviceaccount' => { 'name' => 'orders' } },
                    'sub' => 'system:serviceaccount:prod:orders')
    ).delete('=')
    assert_equal 'orders', TransitClient::Deployment.service_account_from_token("x.#{payload}.y")
  end

  def test_it_falls_back_to_the_subject
    payload = Base64.urlsafe_encode64(
      JSON.generate('sub' => 'system:serviceaccount:prod:billing')
    ).delete('=')
    assert_equal 'billing', TransitClient::Deployment.service_account_from_token("x.#{payload}.y")
  end

  def test_junk_is_no_opinion
    assert_nil TransitClient::Deployment.service_account_from_token('not-a-token')
  end
end
