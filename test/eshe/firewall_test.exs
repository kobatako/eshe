defmodule Eshe.FirewallTest do
  use ExUnit.Case
  doctest Eshe.Firewall

  # source ip   : 192.168.20.10
  # dest ip     : 192.168.10.10
  # source port : 2048
  # dest port   : 80
  @test_packet <<4 :: size(4), 5 :: size(4), 0 :: size(88),
              192, 168, 20, 10, 192, 168, 10, 10, 8, 00, 00, 80>>

  test "Multiple combination dest ip and dest port" do
    # dest ip is true and dest port is true
    assert Eshe.Firewall.match(%{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: 80,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil
    }, @test_packet)

    # dest ip is false and dest port is true
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 20, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: 80,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil
    }, @test_packet)

    # dest ip is true and dest port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: 8080,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil
    }, @test_packet)

    # dest ip is false and dest port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 20, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: 8080,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil
    }, @test_packet)
  end

  test "Multiple combination dest ip and source ip" do
    # dest ip is true and source ip is true
    assert Eshe.Firewall.match(%{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255 ,0},
      source_port: nil
    }, @test_packet)

    # dest ip is false and source ip is true
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 20, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255 ,0},
      source_port: nil
    }, @test_packet)

    # dest ip is true and source ip is false
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 30, 0},
      source_netmask: {255, 255, 255 ,0},
      source_port: nil
    }, @test_packet)

    # dest ip is false and source ip is false
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 20, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 30, 0},
      source_netmask: {255, 255, 255 ,0},
      source_port: nil
    }, @test_packet)
  end

  test "Multiple combination dest ip and source port" do
    # dest ip is true and source port is true
    assert Eshe.Firewall.match(%{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 2048
    }, @test_packet)

    # dest ip is false and source port is true
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 20, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 2048
    }, @test_packet)

    # dest ip is true and source port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 80
    }, @test_packet)

    # dest ip is false and source port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: {192, 168, 20, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 80
    }, @test_packet)
  end

  test "Multiple combination dest port and source ip" do
    # dest port is true and source ip is true
    assert Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 80,
      protocol: nil,
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: nil
    }, @test_packet)

    # dest port is false and source ip is true
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 81,
      protocol: nil,
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: nil
    }, @test_packet)

    # dest port is true and source ip is false
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 80,
      protocol: nil,
      source_ip: {192, 168, 30, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: nil
    }, @test_packet)

    # dest port is false and source ip is false
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 81,
      protocol: nil,
      source_ip: {192, 168, 30, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: nil
    }, @test_packet)
  end

  test "Multiple combination dest port and source port" do
    # dest port is true and source port is true
    assert Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 80,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 2048
    }, @test_packet)

    # dest port is false and source port is true
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 81,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 2048
    }, @test_packet)

    # dest port is true and source port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 80,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 2000
    }, @test_packet)

    # dest port is false and source port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: 81,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: 2000
    }, @test_packet)
  end

  test "Multiple combination source ip and source port" do
    # dest port is true and source port is true
    assert Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: 2048
    }, @test_packet)

    # dest port is false and source port is true
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 30, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: 2048
    }, @test_packet)

    # dest port is true and source port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: 2000
    }, @test_packet)

    # dest port is false and source port is false
    assert !Eshe.Firewall.match(%{
      dest_ip: nil,
      dest_netmask: nil,
      dest_port: nil,
      protocol: nil,
      source_ip: {192, 168, 30, 0},
      source_netmask: {255, 255, 255, 0},
      source_port: 2000
    }, @test_packet)
  end
end
