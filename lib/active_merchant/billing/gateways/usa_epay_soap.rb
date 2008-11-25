module ActiveMerchant #:nodoc:
  module Billing #:nodoc:

    #this is for using the SOAP API with USAePay

    class UsaEpaySoapGateway < Gateway
      URL = 'https://www.usaepay.com/soap/gate/FA7D8A12'

      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :diners_club, :jcb]
      self.supported_countries = ['US']
      self.homepage_url = 'http://www.usaepay.com/'
      self.display_name = 'USA ePay'

      def initialize(options = {})
        #login = source_key, password = pin
        requires!(options, :login)
        requires!(options, :password)
        @options = options
        super
      end

      def authorize(money, creditcard_or_customer_id, options = {})
        #authorizes the credit card for the passed amount, it does not capture the funds
        action = "runAuthOnly"
        if creditcard_or_customer_id.is_a?(String)
          commit("runCustomerTransaction", build_customer_request(action, money, creditcard_or_customer_id, options), options)
        else
          commit(action, build_auth_request(money, creditcard_or_customer_id, options), options)
        end
      end
      
      def capture(money, authorization, options = {})
        #capture the funds from an authorized transaction passing it the authorization number
        commit("captureTransaction", build_capture_request(money, authorization, options), options)
      end
      
      def credit(money, identification, options = {}) 
        #credit a transaction that has already been done, identification is the RefNum of the transaction
        commit("refundTransaction", build_credit_request(money, identification, options), options)
      end
      
      def store(credit_card, options = {})
        #this method creates a new customer and payment_method and saves it for use later
        if options[:firstname].blank? or options[:lastname].blank?
          options[:firstname] = credit_card.first_name
          options[:lastname] = credit_card.last_name
        end
        commit("addCustomer", build_store_request(credit_card, options), options)
      end
      
      def unstore(identification, options = {})
        #this method removes a customer option and all of the payment_methods associated
        commit('deleteCustomer', build_unstore_request(identification, options), options)
      end

      private

      def add_amount(post, money)
        post[:amount] = amount(money)
      end

      def expdate(credit_card)
        year  = format(credit_card.year, :two_digits)
        month = format(credit_card.month, :two_digits)

        "#{month}#{year}"
      end

      def address_key(prefix, key)
        "#{prefix}#{key}".to_sym
      end

      def add_invoice(post, options)
        post[:invoice] = options[:order_id]
      end
      
      def build_unstore_request(indentification, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'ns1:deleteCustomer' do
          xml << add_security_token
          xml.tag! 'CustNum', indentification, {'xsi:type' => "xsd:integer"}
        end
      end
      
      def build_store_request(credit_card, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'ns1:addCustomer' do
          xml << add_security_token
          xml.tag! 'CustomerData', {"xsi:type"=>"ns1:CustomerObject"} do
            xml.tag! "Enabled", "false", {'xsi:type' => 'xsd:boolean'}
            xml.tag! "Next", (Date.today + 1).to_s, {'xsi:type' => 'xsd:string'}
            xml.tag! "Schedule", "Weekly", {'xsi:type' => 'xsd:string'}
            xml << add_address(options)
            xml.tag! "PaymentMethods", {"SOAP-ENC:arrayType"=>"ns1:PaymentMethod[0]", "xsi:type"=>"ns1:PaymentMethodArray"} do
              xml.tag! 'item', {"xsi:type"=>"ns1:PaymentMethod"} do
                xml << add_credit_card(credit_card, options)
              end
            end
          end
        end
      end
      
      def build_credit_request(money, identification, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'ns1:refundTransaction' do
          xml << add_security_token
          xml.tag! 'RefNum', identification, {'xsi:type' => "xsd:integer"}
          xml.tag! 'Amount', amount(money), {'xsi:type' => "xsd:double"}
        end
      end

      def build_auth_request(money, credit_card, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'ns1:runAuthOnly' do
          xml << add_security_token
          xml.tag! 'Params', {'xsi:type' => "ns1:TransactionRequestObject"} do
            xml.tag! 'AccountHolder', credit_card.name, {'xsi:type' =>"xsd:string"} unless credit_card.name.blank?
            xml << add_credit_card(credit_card, options)
            xml.tag! 'Details', {'xsi:type' => "ns1:TransactionDetail"} do
              xml.tag! 'Amount', amount(money), {'xsi:type' => "xsd:double"}
            end
          end
        end
      end
      
      def build_customer_request(action, money, customer_num, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'ns1:runCustomerTransaction' do
          xml << add_security_token
          xml.tag! "Command", action, {'xsi:type' =>"xsd:string"}
          xml.tag! "PaymentMethodID", 0, {'xsi:type' =>"xsd:integer"}
          xml.tag! "CustNum", customer_num, {'xsi:type' =>"xsd:integer"}   
          xml.tag! 'Details', {'xsi:type' => "ns1:TransactionDetail"} do
            xml.tag! 'Amount', amount(money), {'xsi:type' => "xsd:double"}
          end 
        end
      end
      
      def build_capture_request(money, authorization, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'ns1:captureTransaction' do
          xml << add_security_token
          xml.tag! 'RefNum', authorization, {'xsi:type' => "xsd:integer"}
          xml.tag! 'Amount', amount(money), {'xsi:type' => "xsd:double"}
        end
      end

      def add_credit_card(credit_card, options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'CreditCardData', {'xsi:type' => "ns1:CreditCardData"} do
          xml.tag! 'CardExpiration', expdate(credit_card), {'xsi:type' =>"xsd:string"}
          xml.tag! 'CardNumber', credit_card.number, {'xsi:type' =>"xsd:string"}
          xml.tag! 'CardCode', credit_card.verification_value, {'xsi:type' =>"xsd:string"} unless credit_card.verification_value.blank?
          unless options[:address].blank?
            xml.tag! 'AvsStreet', options[:address][:address1], {'xsi:type' =>"xsd:string"} unless options[:address][:address1].blank?
            xml.tag! 'AvsZip', options[:address][:zip], {'xsi:type' =>"xsd:string"} unless options[:address][:zip].blank? 
          end
        end
        xml.target!
      end
      
      def add_address(options)
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! "BillingAddress", {'xsi:type' => "ns1:Address"} do 
          xml.tag! "City", options[:address][:city], {"xsi:type" => "xsd:string"}
          xml.tag! "State", options[:address][:state], {"xsi:type" => "xsd:string"}
          xml.tag! "Street", options[:address][:address1], {"xsi:type" => "xsd:string"}
          xml.tag! "Street2", options[:address][:address2], {"xsi:type" => "xsd:string"} unless options[:address][:address2].blank?
          xml.tag! "Zip", options[:address][:zip], {"xsi:type" => "xsd:string"}
          xml.tag! "FirstName", options[:firstname], {"xsi:type" => "xsd:string"}
          xml.tag! "LastName", options[:lastname], {"xsi:type" => "xsd:string"}
        end
        xml.target!
      end

      def expdate(credit_card)
        year  = format(credit_card.year, :two_digits)
        month = format(credit_card.month, :two_digits)
        "#{month}#{year}"
      end

      def add_security_token
        generated_hash = generate_hash
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! "Token", {'xsi:type' =>"ns1:ueSecurityToken"} do
          xml.tag! "PinHash", {'xsi:type' =>"ns1:ueHash"} do
            xml.tag! "HashValue", generated_hash[:hash], {'xsi:type' => "xsd:string"}
            xml.tag! "Seed", generated_hash[:seed], {'xsi:type' => "xsd:string"}
            xml.tag! "Type", "sha1", {'xsi:type' => "xsd:string"}
          end
          xml.tag! 'SourceKey', @options[:login], {'xsi:type' =>"xsd:string"}
        end
        xml.target!
      end
      

      def build_request(body, options)
        #where the SOAP request is formed
        xml = Builder::XmlMarkup.new :indent => 2
        xml.instruct!
        xml.tag! 'SOAP-ENV:Envelope', {'xmlns:SOAP-ENV' => 'http://schemas.xmlsoap.org/soap/envelope/', 'xmlns:ns1' => "urn:usaepay", 'xmlns:xsd' =>"http://www.w3.org/2001/XMLSchema",
          'xmlns:xsi' => "http://www.w3.org/2001/XMLSchema-instance", 'xmlns:SOAP-ENC' => "http://schemas.xmlsoap.org/soap/encoding/", 'SOAP-ENV:encodingStyle' => "http://schemas.xmlsoap.org/soap/encoding/" } do
            xml.tag! 'SOAP-ENV:Body' do            
              xml << body
            end
          end
        return xml.target!
      end

      def commit(action, request, options)
        response = parse(action, ssl_post(URL, build_request(request, options)))
        Response.new(response[:Result] == "Approved", message_from(response), response,
        :test => @options[:test] || test?,
        :authorization => response[:RefNum],
        :cvv_result => response[:CardCodeResult],
        :avs_result => { 
          :street_match => response[:AvsResultCode].to_s[0,1],
          :postal_match => response[:AvsResultCode].to_s[1,1],
          :code => response[:AvsResultCode].to_s[2,1]
          })
      end

      def generate_hash
        source_key = @options[:login]
        pin = @options[:password]
        seed = Time.now.to_i.to_s + rand(10000).to_s
        clear = source_key + seed + pin
        hash = Digest::SHA1.hexdigest(clear)
        return {:clear => clear, :seed => seed, :hash => hash}
      end
      
      def message_from(response)
        if response[:Result] == "Approved"
          return 'Success'
        else
          return 'Unspecified error' if response[:Error].blank?
          return response[:Error]
        end
      end
      
      def parse(action, xml)
        response = {}
        xml = REXML::Document.new(xml)
        if root = REXML::XPath.first(xml, "//SOAP-ENV:Fault")
          parse_element(response, root)
          response[:message] = "#{response[:faultcode]}: #{response[:faultstring]}"
        elsif root = REXML::XPath.first(xml, "//#{action}Return")
          if root.elements.size == 0
            case action
            when "addCustomer" 
              response[:CustNum] = root.text
              response[:Result] = "Approved"
            when "deleteCustomer"
              response[:Result] = "Approved"
            end
          else
            root.elements.to_a.each do |node|
              parse_element(response, node)
            end
          end
        end
        response
      end
      
      def parse_element(reply, node)
        if node.has_elements?
          node.elements.each{|e| parse_element(reply, e) }
        else
          if node.parent.name =~ /item/
            parent = node.parent.name + (node.parent.attributes["id"] ? "_" + node.parent.attributes["id"] : '')
            reply[(parent + '_' + node.name).to_sym] = node.text
          else  
            reply[node.name.to_sym] = node.text
          end
        end
        return reply
      end

    end
  end
end