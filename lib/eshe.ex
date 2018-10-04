defmodule Eshe do
  @moduledoc """
  Documentation for Eshe.
  """

  @doc """
  Hello world.

  ## Examples

  """
  use Supervisor

  def start(_type, _args) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init([]) do
    children = [
      %{
        id: Eshe.Supervisor,
        start: {Eshe.Supervisor, :start_link, []},
        type: :supervisor
      }
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
