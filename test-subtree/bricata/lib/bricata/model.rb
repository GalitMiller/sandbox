require 'bricata/model/types'
require 'dm-core'

module Bricata
  module Model

    def self.included(base)
      base.send :include, DataMapper::Resource, 
                DataMapper::Migrations, Model::Types
    end

  end
end
