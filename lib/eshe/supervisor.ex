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
      protocol: :tcp
    )

    allow(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :ip
    )

    allow(
      source_ip: {192, 168, 10, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp
    )

    allow(
      source_ip: {192, 168, 10, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :ip
    )

    deny(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      dest_ip: {192, 168, 10, 0},
      dest_netmask: {255, 255, 255, 0}
    )

    deny()
  end

  chaos :default do
    delay(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 255, 255, 0},
      protocol: :tcp,
      milisec: 1000,
      rate: 50
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
