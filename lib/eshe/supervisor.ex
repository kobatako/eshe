defmodule Eshe.Supervisor do
  import Supervisor.Spec
  use GenServer
  import Eshe.Router
  import Eshe.Firewall
  import Eshe.Pipeline
  import Eshe.Chaos

  route do
    add(
      dest_route: {192, 168, 20, 0},
      subnetmask: {255, 255, 255, 0},
      nexthop: {},
      out_interface: :eth1
    )

    add(
      dest_route: {192, 168, 30, 0},
      subnetmask: {255, 255, 255, 0},
      nexthop: {},
      out_interface: :eth0
    )
  end

  firewall :default do
    allow(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :ip
    )
    allow(
      source_ip: {192, 168, 40, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp
    )

    deny()
  end

  chaos :default do
    loss(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp,
      rate: 0
    )
    delay(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp,
      milisec: 100,
      rate: 0
    )
    duplicate(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp,
      rate: 0
    )
    tcp_ack(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp,
      rate: 0
    )
  end

  def start_link() do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init([]) do
    # test
    # route_through(:global)
    firewall_through(:default)
    chaos_through(:default)
    {:ok, []}
  end
end
