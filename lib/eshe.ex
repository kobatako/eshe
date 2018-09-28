defmodule Eshe do
  @moduledoc """
  Documentation for Eshe.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Eshe.hello()
      :world

  """
  use Supervisor

  def start(_type, _args) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init([]) do
    children = [
      %{
        id: ExAviso.Supervisor,
        start: {ExAviso.Supervisor, :start_link, []},
        type: :supervisor
      }
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
