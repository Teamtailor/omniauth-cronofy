module OmniAuth
  module Strategies
    class CronofyServiceAccount < CronofyBase
      WHITELISTED_AUTHORIZE_PARAMS = %w{
        avoid_linking
        link_token
        provider_name
      }

      option :name, "cronofy_service_account"

      option :client_options, {
        :authorize_url => "/enterprise_connect/oauth/authorize",
      }

      def request_phase
        session_params = session['omniauth.params']
        params = {}

        WHITELISTED_AUTHORIZE_PARAMS.each do |param|
          next unless session_params[param]
          params[param] = session_params[param]
        end

        if options[:authorize_params]
          options[:authorize_params].merge!(params)
        else
          options[:authorize_params] = params
        end

        options[:authorize_params][:delegated_scope] = options[:delegated_scope] if options[:delegated_scope]
        super
      end

      uid { raw_info['sub'] }

      info do
        data = {
          :common_name => raw_info['cronofy.service_account.domain'] || raw_info['cronofy.service_account.email']
        }
        data[:domain] = raw_info['cronofy.service_account.domain'] if raw_info['cronofy.service_account.domain']
        data[:email] = raw_info['cronofy.service_account.email'] if raw_info['cronofy.service_account.email']
        data
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      extra do
        {
          'raw_info' => raw_info,
        }
      end

      def raw_info
        @raw_info ||= access_token.get("#{client_options[:api_url]}/v1/userinfo").parsed
      end
    end
  end
end
