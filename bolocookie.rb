require 'packetfu'

class BoloCookie
  
  #CREATE OBJECT
  def initialize(service_name)
    @cookie_info = {:presence => false, :service_name => service_name}
  end

  #RETURN SERVICE SEARCHED FOR
  def service
    @cookie_info[:service_name]
  end

  #ADD FIELD TO OBJECT
  def add_cookie(cookie_name)
    @cookie_info[cookie_name] = nil
  end

  #RECORD IF THE OBJECT IS FOUND
  def found (bool)
    @cookie_info[:presence] = bool
  end

  #RETURN IF THE OBJECT IS FOUND
  def found?
    @cookie_info[:presence]
  end

  #ADD VALUE TO FIELD
  def add_value(cookie_name,cookie_value)
    @cookie_info[cookie_name] = cookie_value
  end

  #RETURN ENTIRE HASH TABLE
  def get_hash
    @cookie_info
  end

  #RETURN ONLY FIELDS 
  def get_cookies
    cookies = Array.new
    @cookie_info.keys.each { |key|
      if key.is_a?String then
        cookies << key
      end
    }
    cookies
  end

  #RETURN FIELDS AND VALUES
  def get_pairs
    cookies = Hash.new
    @cookie_info.keys.each { |key|
      if key.is_a?String then
        cookies[key] = @cookie_info[key]
      end
    }
    cookies
  end

end