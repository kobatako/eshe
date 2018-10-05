defmodule Eshe.Router do
  defmacro route(identifier \\ :global, attrs \\ [], do: context) do
    do_route(identifier, attrs, context)
  end

  defp do_route(identifier, attrs, block) when is_atom(identifier) do
    quote do
      Module.register_attribute(__MODULE__, :change_route, accumulate: true)
      Module.register_attribute(__MODULE__, :static_route, accumulate: true)
      identifier = unquote(identifier)
      attrs = unquote(attrs)
      Module.put_attribute(__MODULE__, :change_route, {:identifier, identifier})

      try do
        unquote(block)
      after
        :ok
      end

      Eshe.Router.merge_route(__MODULE__, @change_route)
      loaded = Eshe.Router.__load__(__MODULE__, @change_route)
      Module.put_attribute(__MODULE__, :static_route, loaded)
    end
  end

  def merge_route(module, strcut) do
    field = Module.get_attribute(module, :change_route)
    route = for {:route_record, [r]} <- field, do: r
    Module.put_attribute(module, :change_route, {:route, route})
  end

  def __load__(module, struct) do
    change_route = Map.new(struct)
    Map.delete(change_route, :route_record)
  end

  defmacro add(c) when is_list(c) do
    quote do
      Eshe.Router.__add__(__MODULE__, unquote(c))
    end
  end

  def __add__(module, c) do
    Module.put_attribute(module, :change_route, {:route_record, [Map.new(c)]})
  end

  defmacro route_through(identifier) do
    quote do
      identifier = unquote(identifier)
      route = for %{identifier: id, route: route} <- @static_route, identifier == id, do: route

      route
      |> List.flatten()
      |> Enum.map(fn r -> :brook_ip.route(:add, :static, r) end)
    end
  end
end
