defmodule Eshe.Supervisor do
  import Supervisor.Spec
  use GenServer
  import Eshe.Router
  import Eshe.Firewall

  firewall :default do
    allow(
      source_ip: {0, 0, 0, 0},
      source_netmask: {255, 2555, 255, 0},
      dest_ip: nil,
      dest_netmask: {255, 255, 255, 0},
      dest_port: 80
    )

    deny(
      source_ip: {192, 168, 20, 0},
      source_netmask: {255, 2555, 255, 0},
      dest_ip: {0, 0, 0, 0},
      dest_netmask: {255, 255, 255, 0}
    )

    allow(source_ip: {192, 168, 0, 0}, source_netmask: {255, 2555, 255, 0})
    deny()
  end

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

  def start_link() do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init([]) do
    route_through(:global)
    firewall_through(:default)
    {:ok, []}
  end
end
