defmodule Eshe.Supervisor do
  import Supervisor.Spec
  use GenServer

  import Eshe.Router

  static do
    add dest_route: [192, 168, 20, 0], subnetmask: [255, 255, 255, 0], nexthop: [],  out_interface: :eth1
  end

  def start_link() do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl true
  def init([]) do
    IO.inspect "gen server init"
    {:ok, []}
  end
end
