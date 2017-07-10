#!/usr/bin/env ruby

require 'fog'
require 'logger'

# Fog::Compute.new :provider => 'AWS', :aws_access_key_id => KEY, :aws_secret_access_key => SECRET, :region => REGION
module Fog::AWS
  def self.regions
    @regions ||= ['ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'eu-central-1', 'eu-west-1', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'sa-east-1', 'cn-north-1', 'us-gov-west-1', 'ap-south-1']
  end
end

class Tagger

  attr_accessor :credentials

  Credentials = Struct.new(:provider, :aws_access_key_id, :aws_secret_access_key, :region)

  VERSION = '0.2.0'

  def initialize_log
    return @logger if defined? @logger
    @logger = Logger.new(STDOUT)
    @logger.formatter = proc do |severity, datetime, progname, msg|
      date_format = datetime.strftime("%Y-%m-%d %H:%M:%S")
      "#{date_format}: #{severity.ljust(5)}: #{msg}\n"
    end
    @logger.level = Logger::DEBUG
  end

  def initialize(opts = {})
    initialize_log

    @credentials = Credentials.new('AWS', opts[:aws_access_key_id], opts[:aws_secret_access_key], opts[:region]).to_h
    @compute = Fog::Compute.new @credentials
    @vpc = @compute.vpcs.all('vpc-id' => opts[:vpc], 'state' => 'available').first
    @vpc_name = @vpc.tags['Name'] || 'Default'
    @rds = Fog::AWS::RDS.new @credentials.delete_if {|key| key == :provider}
    @elb = Fog::AWS::ELB.new @credentials.delete_if {|key| key == :provider}

    @config_tags = key_to_sym opts[:tags][@vpc_name]

    raise ArgumentError, "Cannot find VPC named \"#{@vpc.id}\". Aborting." unless @vpc
    raise ArgumentError, "Cannot find Tags for \"#{@vpc_name}\". Aborting." unless @config_tags
  end

  def self.get_hash_diff(existing, compliance)
    compliance.delete_if{ |key, value| (existing.has_key? key or existing.has_key? key.to_sym) }
  end

  def get_tags(existing)
    compliance = {
      script_info: "Tagger v#{VERSION}",
      provisioned_by: 'devops'
    }.merge(@config_tags)

    Tagger.get_hash_diff(key_to_sym(existing), compliance)
  end

  def tag_vpc
    tags = get_tags(@vpc.tags)
    unless tags.empty?
      @compute.create_tags @vpc.id, tags
      @logger.info "Tagged VPC #{@vpc.tags['Name']} (#{@vpc.id})"
    end
  end

  def tag_vpc_subnets
    subnets = @compute.subnets.all('vpc-id' => @vpc.id)

    subnets.each do |subnet|
      tags = get_tags(subnet.tag_set)
      unless tags.empty?
        @compute.create_tags subnet.subnet_id, tags
        @logger.info "Tagged Subnet #{subnet.tag_set['Name']} (#{subnet.subnet_id})"
      end
    end
  end

  def tag_vpc_security_groups
    security_groups = @compute.security_groups.all('vpc-id' => @vpc.id)

    security_groups.each do |security_group|
      tags = get_tags(security_group.tags)
      unless tags.empty?
        @compute.create_tags security_group.group_id, tags
        @logger.info "Tagged Security Group #{security_group.tags['Name']} (#{security_group.group_id})"
      end
    end
  end

  def get_autoscaling_tag(resourceId, key, value)
    {
      'Key' => key, #Key<~String> - The key of the tag.
      'PropagateAtLaunch' => true, #PropagateAtLaunch<~Boolean> - Specifies whether the new tag will be applied to instances launched after the tag is created. The same behavior applies to updates: If you change a tag, the changed tag will be applied to all instances launched after you made the change.
      'ResourceId' => resourceId, #ResourceId<~String> - The name of the Auto Scaling group.
      'ResourceType' => 'auto-scaling-group',#ResourceType<~String> - The kind of resource to which the tag is applied. Currently, Auto Scaling supports the auto-scaling-group resource type.
      'Value' => value  #duh
    }
  end

  def get_autoscaling_tags(resourceId, tags)
    tags.map { |key, value|  get_autoscaling_tag(resourceId, key, value) }
  end

  def tag_autoscaling_groups
    as = Fog::AWS[:auto_scaling]

    allGroups = as.groups.all('vpc-id' => @vpc.id)
    allGroups.each do |group|
      newTags = get_autoscaling_tags(group.id, get_tags({}))
      unless newTags.empty?
        as.create_or_update_tags(newTags)
        @logger.info "Tagged Autoscaling Group (#{group.id})"
      end
    end
  end

  # tagger = Tagger.new ({
  #   aws_access_key_id: credentials.credentials.access_key_id,
  #   aws_secret_access_key: credentials.credentials.secret_access_key,
  #   region: region,
  #   vpc: vpv_id,
  #   tags: configuration[:tags]
  # })
  # tagger.tag_ec2_by_id id

  def tag_ec2_by_id id
    tag_ec2 @compute.servers.select {|instance| instance.id == id}
  end

  def tag_ec2_by_vpc
    puts "   EC2 instances in #{@vpc.id} #{@vpc_name}"
    tag_ec2 @compute.servers.all('vpc-id' => @vpc.id)
  end

  def tag_ec2 instances
    instances.each do |instance|
      tags = get_tags(instance.tags)
      unless tags.empty?
        @compute.create_tags instance.id, tags
        @logger.info "Tagged EC2 instance #{instance.tags['Name']} (#{instance.id})"
      end
    end
  end

  # tagger = Tagger.new ({
  #   aws_access_key_id: credentials.credentials.access_key_id,
  #   aws_secret_access_key: credentials.credentials.secret_access_key,
  #   region: region,
  #   vpc: vpc_id,
  #   tags: configuration[:tags]
  # })
  # tagger.tag_rds_by_id id

  def tag_rds_by_id id
    tag_rds @rds.servers.select {|instance| instance.id == id}
  end

  def tag_rds_by_vpc
    rds_vpc = @rds.subnet_groups.select {|group| group.vpc_id == @vpc.id}.reduce([]) {|rds_vpc, group| rds_vpc << group.id}
    puts "   RDS instances in #{@vpc.id} [#{rds_vpc.join(', ')}]"
    return if rds_vpc.empty?

    tag_rds @rds.servers.select {|instance| rds_vpc.include? instance.db_subnet_group_name}
  end

  def tag_rds instances
    instances.each do |instance|
      tags = get_tags(instance.tags)
      tags.merge!({Name: instance.id}) if not tags.has_key? 'Name'
      unless tags.empty?
        @rds.add_tags_to_resource instance.id, sym_to_key(tags)
        @logger.info "Tagged RDS instance #{instance.db_name} (#{instance.id})"
      end
    end
  end

  def tag_elb_by_name name
    tag_elb @elb.load_balancers.select {|lb| lb.vpc_id == @vpc.id && lb.id == name }
  end

  def tag_elb instances
    instances.each do |instance|
      tags = get_tags(instance.tags)
      tags.merge!({Name: instance.id}) if not tags.has_key? 'Name'
      unless tags.empty?
        begin
          instance.add_tags tags
          @logger.info "Tagged ELB instance #{instance.tags['Name']} (#{instance.id})"
        rescue Fog::AWS::ELB::ValidationError => msg
          @logger.error "Error tagging ELB instance #{instance.tags['Name']} (#{instance.id})"
          @logger.error msg
        end
      end
    end
  end

  private
  def key_to_sym(value)
    return value if not value.is_a?(Hash)
    hash = value.inject({}){|memo,(k,v)| memo[k.to_sym] = key_to_sym(v); memo}
    return hash
  end

  def sym_to_key(value)
    return value if not value.is_a?(Hash)
    hash = value.inject({}){|memo,(k,v)| memo["#{k}"] = sym_to_key(v); memo}
    return hash
  end
end
