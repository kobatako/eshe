defmodule Eshe.Supervisor do
  import Supervisor.Spec
  use GenServer

  def start_link() do

  end

  @impl true
  def init([]) do
    {:ok, []}
  end
end
