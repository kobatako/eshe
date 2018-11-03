defmodule Eshe.ChaosTest do
  use ExUnit.Case
  doctest Eshe.Chaos

  # source ip   : 192.168.20.10
  # dest ip     : 192.168.10.10
  # source port : 2048
  # dest port   : 80
  @test_packet <<4::size(4), 5::size(4), 0::size(88), 192, 168, 20, 10, 192, 168, 10, 10, 8, 00,
                 00, 80>>

  test "chaos type loss" do
    true_loss = %{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil,
      rate: 100
    }
    assert Eshe.Chaos.chaos_type_pipeline({:loss, true_loss}, @test_packet, %{})
                == {:error, {{:message, :chaos_type_loss}, {:record, true_loss}, {:data, @test_packet}}}

    false_loss = %{
      dest_ip: {192, 168, 0, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil,
      rate: 100
    }
    assert Eshe.Chaos.chaos_type_pipeline({:loss, false_loss}, @test_packet, %{}) == {:ok, @test_packet, %{}}

  end

  test "chaos type duplicate" do
    assert Eshe.Chaos.chaos_type_pipeline({:duplicate, %{
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil,
      rate: 100
    }}, @test_packet, %{}) == {:ok, @test_packet, %{duplicate: true}}

    assert Eshe.Chaos.chaos_type_pipeline({:loss, %{
      dest_ip: {192, 168, 0, 0},
      dest_netmask: {255, 255, 255, 0},
      dest_port: nil,
      protocol: nil,
      source_ip: nil,
      source_netmask: nil,
      source_port: nil,
      rate: 100
    }}, @test_packet, %{}) == {:ok, @test_packet, %{}}
  end
end
